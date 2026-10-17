import { normalizeSslTarget } from './sslTarget';

describe('normalizeSslTarget', () => {
  it('turns a pasted URL into host or host:port', () => {
    expect(normalizeSslTarget('https://Site.COM/page?x=1')).toMatchObject({ ok: true, target: 'site.com', changed: true });
    expect(normalizeSslTarget('http://site.com:8443/a')).toMatchObject({ ok: true, target: 'site.com:8443', port: 8443 });
    expect(normalizeSslTarget('site.com:443')).toMatchObject({ ok: true, target: 'site.com' });
    expect(normalizeSslTarget('site.com')).toMatchObject({ ok: true, target: 'site.com', changed: false });
    expect(normalizeSslTarget('expired.badssl.com.')).toMatchObject({ ok: true, target: 'expired.badssl.com' });
  });

  it('converts international names like the backend', () => {
    expect(normalizeSslTarget('café.fr')).toMatchObject({ ok: true, host: 'xn--caf-dma.fr' });
  });

  it('refuses what cannot be scanned, with a reason', () => {
    for (const bad of ['', 'localhost', 'site.com:0', 'site.com:99999', 'user:pw@site.com', '[::1]', 'a..com',
      '999.1.1.1', 'si te.com', 'site.com;id', '-x-.com']) {
      const r = normalizeSslTarget(bad);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.length).toBeGreaterThan(5);
    }
  });
});
