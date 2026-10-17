import { linkKind } from '../utils/safeLinks';

describe('assistant links', () => {
  it('keeps app paths and http(s) links', () => {
    expect(linkKind('/vulnerabilities?scanId=3')).toBe('internal');
    expect(linkKind('https://nvd.nist.gov/vuln/detail/CVE-2024-1')).toBe('external');
    expect(linkKind('http://example.com/a')).toBe('external');
  });

  it('never makes script, data or protocol-relative links clickable', () => {
    for (const bad of ['javascript:alert(1)', ' JaVaScRiPt:alert(1)', 'data:text/html,<b>x</b>', '//evil.example/x',
      '/\\evil.example', 'vbscript:x', 'https://x y']) {
      expect(linkKind(bad)).toBe('unsafe');
    }
  });
});
