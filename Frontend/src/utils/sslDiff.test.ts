import { compareSslResults } from './sslDiff';
import { goodSslResult } from './sslTestFixtures';

describe('compareSslResults', () => {
  it('identical scans: no change', () => {
    expect(compareSslResults(goodSslResult(), goodSslResult()).changes).toEqual([]);
  });

  it('reports a fix and the grade going up', () => {
    const before = goodSslResult({ tls10: true, sslyzeSupportsTLS10: true });
    const diff = compareSslResults(before, goodSslResult());
    expect(diff.fixedCount).toBe(2);
    expect(diff.changes.map((c) => c.label)).toEqual(expect.arrayContaining(['Note en hausse', 'TLS 1.0 désactivé']));
    expect(diff.newCount).toBe(0);
  });

  it('reports a regression', () => {
    const diff = compareSslResults(goodSslResult(), goodSslResult({ hsts: false }));
    expect(diff.changes).toEqual(expect.arrayContaining([expect.objectContaining({ kind: 'new', label: 'HSTS disparu' })]));
  });

  it('flags a change of certificate authority, not a routine renewal', () => {
    const renewed = goodSslResult({
      sslyzeCertIssuer: "CN=R10,O=Let's Encrypt,C=US",
      certSerialNumber: '02',
      certificateDetail: { hostnameMatch: 'MATCH', keyType: 'RSA', keySize: 2048, serialNumber: '02' },
    });
    const renewal = compareSslResults(goodSslResult(), renewed);
    expect(renewal.changes.map((c) => c.label)).toEqual(['Nouveau certificat (renouvellement)']);
    expect(renewal.changes[0].alert).toBeUndefined();

    const otherCa = goodSslResult({ sslyzeCertIssuer: 'CN=Evil CA,O=Evil Corp,C=XX' });
    const drift = compareSslResults(goodSslResult(), otherCa);
    expect(drift.changes).toEqual(expect.arrayContaining([
      expect.objectContaining({ label: 'Autorité de certification différente', alert: true }),
    ]));
  });

  it('does not invent SSL 2/3 changes when SSLyze was missing on one side', () => {
    const noSslyze = goodSslResult({ sslyzeStatus: 'ERROR', sslyzeSupportsSSL30: false });
    const withSsl3 = goodSslResult({ sslyzeSupportsSSL30: true });
    expect(compareSslResults(noSslyze, withSsl3).changes.some((c) => c.label.startsWith('SSL 3.0'))).toBe(false);
  });
});
