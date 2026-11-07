import type { ScanResultDto, SslResultDto } from '../services/api';
import { compareWithLabs, labsOnVerdictScale, sourceGrades } from './sslGrades';
import { goodSslResult } from './sslTestFixtures';
import { comparisonTsv, latestPerDomain } from '../components/SslLabsComparison';

const fs = require('fs');
const path = require('path');
const load = (name: string): SslResultDto =>
  JSON.parse(fs.readFileSync(path.join(__dirname, '__fixtures__', 'badssl', `${name}.json`), 'utf8'));

describe('sourceGrades', () => {
  it('only shows the tools that did their job', () => {
    const r = goodSslResult({
      scanStatus: 'COMPLETED', grade: 'A+',
      ssllabsStatus: 'READY', ssllabsGrade: 'A+',
      sslyzeStatus: 'READY', sslyzeGrade: 'A',
      censysStatus: 'NO_DATA', censysGrade: '?',
    } as Partial<SslResultDto>);
    expect(sourceGrades(r).map((s) => `${s.name} ${s.grade}`)).toEqual(['Kali A+', 'SSL Labs A+', 'SSLyze A']);
  });

  it('a failed or timed-out tool is left out', () => {
    const r = goodSslResult({
      scanStatus: 'COMPLETED', grade: 'B', ssllabsStatus: 'TIMEOUT', ssllabsGrade: '?',
      sslyzeStatus: 'ERROR', sslyzeGrade: 'F', censysStatus: 'READY', censysGrade: 'A',
    } as Partial<SslResultDto>);
    expect(sourceGrades(r).map((s) => s.id)).toEqual(['kali', 'censys']);
  });
});

describe('compareWithLabs', () => {
  it('puts SSL Labs grades on the verdict scale', () => {
    expect(labsOnVerdictScale('A-')).toBe('A');
    expect(labsOnVerdictScale('T')).toBe('F');
  });

  it('missing browser headers no longer make the SSL grade differ from SSL Labs (rh.antigoneinterne.agency case)', () => {
    const r = goodSslResult({ ssllabsStatus: 'READY', ssllabsGrade: 'A+', contentSecurityPolicy: false, cspValue: null,
      xFrameOptions: false, xFrameOptionsValue: null, headersLiveChecked: true } as Partial<SslResultDto>);
    const c = compareWithLabs(r);
    expect(c.vulnix).toBe('A+');
    expect(c.verdict).toBe('same');
  });

  it('HSTS shorter than 6 months is A, like SSL Labs (courtlinker.com case)', () => {
    const r = goodSslResult({ ssllabsStatus: 'READY', ssllabsGrade: 'A', hsts: true, hstsValue: 'max-age=300' } as Partial<SslResultDto>);
    const c = compareWithLabs(r);
    expect(c.vulnix).toBe('A');
    expect(c.verdict).toBe('same');
    expect(compareWithLabs(goodSslResult({ hsts: true, hstsValue: 'max-age=31536000' } as Partial<SslResultDto>)).vulnix).toBe('A+');
  });

  it('real broken sites: Vulnix is never more lenient than SSL Labs', () => {
    for (const name of ['expired_badssl_com', 'self-signed_badssl_com', 'untrusted-root_badssl_com', 'wrong_host_badssl_com', 'rc4_badssl_com', '3des_badssl_com']) {
      const c = compareWithLabs(load(name));
      expect([name, c.verdict === 'lenient']).toEqual([name, false]);
    }
  });

  it('no SSL Labs grade is said so', () => {
    const c = compareWithLabs(goodSslResult({ ssllabsStatus: 'ERROR', ssllabsGrade: '?' } as Partial<SslResultDto>));
    expect(c.verdict).toBe('no_labs');
  });
});

describe('validation table', () => {
  const scan = (id: number, domain: string, status = 'COMPLETED') =>
    ({ id, repoUrl: `ssl://${domain}`, targetDomain: domain, status } as unknown as ScanResultDto);

  it('keeps the latest finished scan of each domain', () => {
    const list = [scan(9, 'a.com'), scan(8, 'b.com', 'FAILED'), scan(7, 'a.com'), scan(6, 'b.com')];
    expect(latestPerDomain(list).map((s) => s.id)).toEqual([9, 6]);
  });

  it('copies as a table for Word or Excel', () => {
    const tsv = comparisonTsv([{ domain: 'a.com', vulnix: 'B', score: 85, labs: 'A+', gap: 2, verdict: 'stricter', reason: 'CSP absente.' }]);
    expect(tsv.split('\n')).toEqual([
      'Domaine\tNote Vulnix\tScore\tNote SSL Labs\tÉcart\tExplication',
      'a.com\tB\t85\tA+\tVulnix plus sévère\tCSP absente.',
    ]);
  });
});
