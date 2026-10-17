import type { SslResultDto } from '../services/api';
import { computeGradeCaps, computeScoreBreakdown, getVulnStatus, gradeRank } from './sslScore';

/**
 * Regression on real scans of badssl.com (results saved from the Medianet pipeline, October 2026): each site is
 * broken on purpose in one known way. The test pins what the detection must find and the cap it must apply, so a
 * parser or scoring change that stops seeing an expired or untrusted certificate fails here.
 * The full score is not pinned: it also counts HTTP headers, which badssl.com does not send.
 */
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '__fixtures__', 'badssl');
const fixtures: Record<string, SslResultDto> = {};
for (const f of fs.readdirSync(dir) as string[]) {
  if (f.endsWith('.json')) fixtures[f.replace('.json', '')] = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
}

function capsOf(r: SslResultDto) {
  return computeGradeCaps(r, getVulnStatus([r.heartbleed ?? undefined, r.sslyzeHeartbleed ?? undefined]));
}
const hasCap = (r: SslResultDto, grade: string, re: RegExp) => capsOf(r).some((c) => c.grade === grade && re.test(c.reason));

describe('badssl.com regression', () => {
  it('has the real scan results', () => {
    expect(Object.keys(fixtures).sort()).toEqual([
      '3des_badssl_com', 'expired_badssl_com', 'hsts_badssl_com', 'rc4_badssl_com', 'self-signed_badssl_com',
      'tls-v1-2_badssl_com_1012', 'untrusted-root_badssl_com', 'wrong_host_badssl_com',
    ]);
  });

  it('certificates a browser refuses give F, for the right reason', () => {
    expect(hasCap(fixtures.expired_badssl_com, 'F', /expiré/)).toBe(true);
    expect(hasCap(fixtures['self-signed_badssl_com'], 'F', /non reconnu/)).toBe(true);
    expect(hasCap(fixtures['untrusted-root_badssl_com'], 'F', /non reconnu/)).toBe(true);
    expect(hasCap(fixtures.wrong_host_badssl_com, 'F', /ne correspond pas au nom/)).toBe(true);
    for (const k of ['expired_badssl_com', 'self-signed_badssl_com', 'untrusted-root_badssl_com', 'wrong_host_badssl_com']) {
      expect(computeScoreBreakdown(fixtures[k]).grade).toBe('F');
      expect(computeScoreBreakdown(fixtures[k]).riskLevel).toBe('Critique');
    }
  });

  it('weak ciphers are found and capped', () => {
    expect(hasCap(fixtures['3des_badssl_com'], 'B', /3DES/)).toBe(true);
    expect(hasCap(fixtures.rc4_badssl_com, 'C', /RC4/)).toBe(true);
  });

  it('a TLS 1.2-only server is not accused of obsolete protocols or a bad certificate', () => {
    const r = fixtures['tls-v1-2_badssl_com_1012'];
    const reasons = capsOf(r).map((c) => c.reason).join(' ');
    expect(reasons).not.toMatch(/TLS 1\.0|SSL 3\.0|SSL 2\.0|expiré|non reconnu|ne correspond pas/);
    expect(r.targetPort).toBe(1012);
    expect(r.ssllabsStatus).toBe('DISABLED'); // SSL Labs only tests port 443, and now says so
  });

  it('the verdict is never better than any cap', () => {
    for (const r of Object.values(fixtures)) {
      const bd = computeScoreBreakdown(r);
      for (const c of capsOf(r)) expect(gradeRank(bd.grade)).toBeGreaterThanOrEqual(gradeRank(c.grade));
    }
  });
});

describe('what to fix first', () => {
  it('names the flaw each badssl site was built with', () => {
    const { topRisks } = require('./sslScore');
    const first = (k: string) => topRisks(computeScoreBreakdown(fixtures[k])).map((r: { label: string }) => r.label).join(' / ');
    expect(first('3des_badssl_com')).toMatch(/3DES/);
    expect(first('rc4_badssl_com')).toMatch(/RC4/);
    expect(first('expired_badssl_com')).toMatch(/expiré/);
    expect(first('self-signed_badssl_com')).toMatch(/non reconnu/);
    expect(first('wrong_host_badssl_com')).toMatch(/ne correspond pas au nom/);
  });
});
