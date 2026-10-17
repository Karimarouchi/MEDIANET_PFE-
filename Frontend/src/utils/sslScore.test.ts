import { computeScoreBreakdown, topRisks } from './sslScore';
import { goodSslResult } from './sslTestFixtures';

describe('SSL verdict', () => {
  it('a well configured site gets A+ with nothing to fix', () => {
    const bd = computeScoreBreakdown(goodSslResult());
    expect(bd.grade).toBe('A+');
    expect(bd.caps).toEqual([]);
    expect(bd.riskLevel).toBe('Faible');
    expect(topRisks(bd)).toEqual([]);
  });

  // Before the caps an expired certificate only cost 8 points: the page could show A for a site every browser blocks.
  it('an expired certificate gives F whatever the points', () => {
    const bd = computeScoreBreakdown(goodSslResult({ certExpired: true, sslyzeDaysLeft: -5, certDaysLeft: -5 }));
    expect(bd.total).toBeGreaterThanOrEqual(80);
    expect(bd.grade).toBe('F');
    expect(bd.riskLevel).toBe('Critique');
    expect(topRisks(bd)[0].label).toMatch(/expiré/);
  });

  it('a self-signed or unknown-authority certificate gives F', () => {
    expect(computeScoreBreakdown(goodSslResult({ sslyzeChainTrusted: false })).grade).toBe('F');
    expect(computeScoreBreakdown(goodSslResult({ ssllabsGrade: 'T' })).grade).toBe('F');
  });

  it('a certificate for another name gives F', () => {
    const r = goodSslResult({ certificateDetail: { hostnameMatch: 'MISMATCH', keyType: 'RSA', keySize: 2048 } });
    expect(computeScoreBreakdown(r).grade).toBe('F');
  });

  it('TLS 1.0 or 1.1 caps at B', () => {
    const bd = computeScoreBreakdown(goodSslResult({ tls10: true, sslyzeSupportsTLS10: true }));
    expect(bd.grade).toBe('B');
    expect(bd.scoreGrade).toBe('A+'); // TLS 1.0 only costs 4 points: without the cap it would stay A+
    expect(bd.caps[0].reason).toMatch(/TLS 1\.0/);
  });

  it('3DES caps at B, RC4 and SSL 3.0 at C, SSL 2.0 at F', () => {
    expect(computeScoreBreakdown(goodSslResult({ ssllabsHas3des: true })).grade).toBe('B');
    expect(computeScoreBreakdown(goodSslResult({ rc4: true })).grade).toBe('C');
    expect(computeScoreBreakdown(goodSslResult({ sslyzeSupportsSSL30: true })).grade).toBe('C');
    expect(computeScoreBreakdown(goodSslResult({ sslyzeSupportsSSL20: true })).grade).toBe('F');
  });

  it('no HSTS takes away A+ only', () => {
    const bd = computeScoreBreakdown(goodSslResult({ hsts: false, hstsValue: null as unknown as string }));
    expect(['A', 'B']).toContain(bd.grade);
    expect(bd.grade).not.toBe('A+');
  });

  it('a 1024-bit RSA key caps at B, an ECDSA 256 key does not', () => {
    expect(computeScoreBreakdown(goodSslResult({ sslyzeKeySize: 1024 })).grade).toBe('B');
    const ec = goodSslResult({ sslyzeKeySize: 256, certificateDetail: { hostnameMatch: 'MATCH', keyType: 'EC', keySize: 256 } });
    expect(computeScoreBreakdown(ec).grade).toBe('A+');
  });

  it('Heartbleed seen by one tool only is "to confirm", not F', () => {
    const one = computeScoreBreakdown(goodSslResult({ heartbleed: true }));
    expect(one.grade).not.toBe('F');
    expect(one.riskLevel).toBe('Élevé');
    const two = computeScoreBreakdown(goodSslResult({ heartbleed: true, sslyzeHeartbleed: true }));
    expect(two.grade).toBe('F');
  });

  it('top risks do not repeat a cap as a lost-points line', () => {
    const bd = computeScoreBreakdown(goodSslResult({ certExpired: true, sslyzeDaysLeft: -1, tls10: true }));
    const labels = topRisks(bd, 5).map((r) => r.label);
    expect(labels.filter((l) => /expiré/i.test(l))).toHaveLength(1);
    expect(labels.filter((l) => /TLS 1\.0/.test(l))).toHaveLength(1);
  });
});
