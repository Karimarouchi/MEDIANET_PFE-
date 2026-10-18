import { change, formatChange, summarize, HistoryRow } from './evolution';

const row = (scanId: number, vulns: number, crit: number, high: number, code: number, toHandle: number): HistoryRow => ({
  scanId,
  startedAt: '2026-10-17T15:00:00',
  vulnerabilities: vulns,
  bySeverity: { CRITICAL: crit, HIGH: high, MEDIUM: vulns - crit - high, LOW: 0, UNKNOWN: 0 },
  codeAlerts: code,
  rawRows: vulns + code,
  secrets: { total: toHandle + 5, toHandle, confirmed: 0, toCheck: 2, testAndDocs: 1, falsePositives: 2 },
});

describe('evolution', () => {
  it('compares first and last scan on unique vulnerabilities, severe ones and secrets', () => {
    const s = summarize([row(115, 120, 17, 60, 69, 85), row(118, 120, 17, 60, 69, 85), row(123, 23, 2, 9, 26, 0)])!;
    expect(s.scans).toBe(3);
    expect(s.vulnerabilities).toMatchObject({ first: 120, last: 23, delta: -97, trend: 'better', pct: 81 });
    expect(s.severe).toMatchObject({ first: 77, last: 11, trend: 'better' });
    expect(s.secretsToHandle).toMatchObject({ first: 85, last: 0, trend: 'better' });
    expect(s.repeats).toBe(1); // #118 identical to #115: same code scanned again
  });

  it('formats changes honestly', () => {
    expect(formatChange(change(412, 72))).toBe('−340 (−83 %)');
    expect(formatChange(change(5, 7))).toBe('+2 (+40 %)');
    expect(formatChange(change(0, 3))).toBe('+3');
    expect(formatChange(change(4, 4))).toBe('±0');
  });

  it('no scan, no summary', () => {
    expect(summarize([])).toBeNull();
  });
});

describe('uniqueVulnerabilityCount', () => {
  it('counts one CVE on one package once, whatever the tool', () => {
    const { uniqueVulnerabilityCount } = require('./evolution');
    expect(uniqueVulnerabilityCount([
      { cveId: 'CVE-2026-45623', packageName: 'postcss' },          // Grype
      { cveId: 'CVE-2026-45623', packageName: 'postcss:7.0' },      // Dependency-Check
      { cveId: 'CVE-2026-47884', canonicalId: 'CVE-2026-47884', packageName: 'org.springframework:spring-webmvc' },
    ])).toBe(2);
  });
});
