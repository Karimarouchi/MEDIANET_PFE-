import type { SslResultDto } from '../services/api';
import { fixTargets, sslFindings } from './sslFindings';
import { computeGradeCaps, getVulnStatus } from './sslScore';
import { goodSslResult } from './sslTestFixtures';

const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '__fixtures__', 'badssl');
const real: Record<string, SslResultDto> = {};
for (const f of fs.readdirSync(dir) as string[]) {
  if (f.endsWith('.json')) real[f.replace('.json', '')] = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
}

const ids = (r: SslResultDto) => sslFindings(r).findings.map((f) => f.id);
const finding = (r: SslResultDto, id: string) => sslFindings(r).findings.find((f) => f.id === id);

describe('sslFindings on real badssl.com scans', () => {
  it('each broken site shows its flaw, with the flaw if not fixed and a fix', () => {
    expect(ids(real.expired_badssl_com)).toContain('cert_expired');
    expect(ids(real['self-signed_badssl_com'])).toContain('cert_untrusted');
    expect(ids(real['untrusted-root_badssl_com'])).toContain('cert_untrusted');
    expect(ids(real.wrong_host_badssl_com)).toContain('cert_name');
    expect(ids(real.rc4_badssl_com)).toContain('rc4');
    expect(ids(real['3des_badssl_com'])).toContain('3des');
    for (const r of Object.values(real)) {
      for (const f of sslFindings(r).findings) {
        expect(f.risk.length).toBeGreaterThan(40);
        expect(f.fix.length).toBeGreaterThan(10);
        expect(f.seenBy).toBeTruthy();
      }
    }
  });

  it('every flaw that caps the grade is in the list (nothing that lowers the grade is hidden)', () => {
    const capToFinding: Array<[RegExp, string]> = [
      [/expiré/, 'cert_expired'], [/non reconnu/, 'cert_untrusted'], [/ne correspond pas au nom/, 'cert_name'],
      [/RC4/, 'rc4'], [/3DES/, '3des'], [/TLS 1\.0 ou TLS 1\.1/, 'old_tls'], [/HSTS/, 'header_hsts'],
      [/SSL 3\.0/, 'ssl3'], [/Forward Secrecy/, 'forward_secrecy'], [/Chaîne/, 'cert_chain'],
    ];
    for (const [name, r] of Object.entries(real)) {
      const caps = computeGradeCaps(r, getVulnStatus([r.heartbleed ?? undefined, r.sslyzeHeartbleed ?? undefined]));
      for (const cap of caps) {
        const match = capToFinding.find(([re]) => re.test(cap.reason));
        if (match) expect([name, ids(r)]).toEqual([name, expect.arrayContaining([match[1]])]);
      }
    }
  });

  it('most severe first', () => {
    const order = ['critique', 'élevée', 'moyenne', 'faible'];
    for (const r of Object.values(real)) {
      const sev = sslFindings(r).findings.map((f) => order.indexOf(f.severity));
      expect(sev).toEqual([...sev].sort((a, b) => a - b));
    }
  });
});

describe('sslFindings on a good configuration', () => {
  it('a clean site has no TLS problem and lists what passed', () => {
    const r = goodSslResult();
    const { findings, passed } = sslFindings(r);
    expect(findings.filter((f) => !f.id.startsWith('header_') && f.id !== 'ocsp')).toEqual([]);
    expect(passed.map((p) => p.id)).toEqual(expect.arrayContaining(['old_tls', 'ciphers', 'heartbleed']));
  });

  it('a vulnerability seen by one tool while the other says no is marked to confirm', () => {
    const r = goodSslResult({ heartbleed: true, sslyzeHeartbleed: false } as Partial<SslResultDto>);
    const hb = finding(r, 'heartbleed')!;
    expect(hb.severity).toBe('critique');
    expect(hb.toConfirm).toBe(true);
    expect(hb.cve).toBe('CVE-2014-0160');
    expect(hb.fix).toMatch(/OpenSSL/);
  });

  it('old TLS versions give the protocol line for nginx and Apache', () => {
    const f = finding(goodSslResult({ tls10: true } as Partial<SslResultDto>), 'old_tls')!;
    expect(f.title).toBe('TLS 1.0 encore accepté');
    expect(f.nginx).toBe('ssl_protocols TLSv1.2 TLSv1.3;');
    expect(f.apache).toBe('SSLProtocol -all +TLSv1.2 +TLSv1.3');
  });

  it('a certificate close to expiry is a problem, a valid one passes', () => {
    expect(finding(goodSslResult({ certDaysLeft: 5, sslyzeDaysLeft: 5 } as Partial<SslResultDto>), 'cert_expiring')!.severity).toBe('élevée');
    expect(finding(goodSslResult({ certDaysLeft: 20, sslyzeDaysLeft: 20 } as Partial<SslResultDto>), 'cert_expiring')!.severity).toBe('moyenne');
    expect(sslFindings(goodSslResult({ certDaysLeft: 80, sslyzeDaysLeft: 80 } as Partial<SslResultDto>)).passed.map((p) => p.id)).toContain('cert_valid');
  });
});

describe('fixTargets', () => {
  it('shows the detected server only, both otherwise', () => {
    expect(fixTargets('nginx')).toEqual(['nginx']);
    expect(fixTargets('apache')).toEqual(['apache']);
    expect(fixTargets('cloudflare')).toEqual(['nginx', 'apache']);
    expect(fixTargets(null)).toEqual(['nginx', 'apache']);
  });
});
