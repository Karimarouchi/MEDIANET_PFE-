/**
 * Figures of the "Évolution" tab, from GET /api/repositories/{id}/history (one row per finished scan, oldest first).
 * A vulnerability is one CVE on one package whatever the number of tools that reported it; Semgrep code alerts
 * and secrets are counted apart. No synthetic "security score": the counts by severity say it plainly.
 */
export interface HistoryRow {
  scanId: number;
  startedAt: string | null;
  commitSha?: string | null;
  vulnerabilities: number;
  bySeverity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; UNKNOWN: number };
  codeAlerts: number;
  rawRows: number;
  secrets: { total: number; toHandle: number; confirmed: number; toCheck: number; testAndDocs: number; falsePositives: number };
}

export type Trend = 'better' | 'worse' | 'same';

export interface Change {
  first: number;
  last: number;
  delta: number;
  /** % of the first value, rounded; 0 when the first value is 0. */
  pct: number;
  trend: Trend;
}

export function change(first: number, last: number): Change {
  const delta = last - first;
  return {
    first,
    last,
    delta,
    pct: first > 0 ? Math.round((Math.abs(delta) / first) * 100) : 0,
    trend: delta < 0 ? 'better' : delta > 0 ? 'worse' : 'same',
  };
}

export const severe = (r: HistoryRow) => r.bySeverity.CRITICAL + r.bySeverity.HIGH;

export interface EvolutionSummary {
  scans: number;
  vulnerabilities: Change;
  severe: Change;
  codeAlerts: Change;
  secretsToHandle: Change;
  /** Consecutive scans whose figures are identical: usually the same commit scanned again. */
  repeats: number;
}

export function summarize(rows: HistoryRow[]): EvolutionSummary | null {
  if (rows.length === 0) return null;
  const a = rows[0];
  const b = rows[rows.length - 1];
  let repeats = 0;
  for (let i = 1; i < rows.length; i++) {
    const p = rows[i - 1];
    const c = rows[i];
    if (p.vulnerabilities === c.vulnerabilities && severe(p) === severe(c) && p.codeAlerts === c.codeAlerts
      && p.secrets.toHandle === c.secrets.toHandle) repeats++;
  }
  return {
    scans: rows.length,
    vulnerabilities: change(a.vulnerabilities, b.vulnerabilities),
    severe: change(severe(a), severe(b)),
    codeAlerts: change(a.codeAlerts, b.codeAlerts),
    secretsToHandle: change(a.secrets.toHandle, b.secrets.toHandle),
    repeats,
  };
}

/** "−340 (−83 %)", "+2 (+40 %)", "±0". */
export function formatChange(c: Change): string {
  if (c.delta === 0) return '±0';
  const sign = c.delta > 0 ? '+' : '−';
  return `${sign}${Math.abs(c.delta)}${c.first > 0 ? ` (${sign}${c.pct} %)` : ''}`;
}

/**
 * Same rule as the backend history (RepositoryHistoryService.dependencyKey): one CVE on one package counts once,
 * whatever the tool, and Dependency-Check's "postcss:7.0" is the package "postcss".
 */
export function uniqueVulnerabilityCount(rows: Array<{ cveId?: string | null; canonicalId?: string | null; packageName?: string | null }>): number {
  const keys = new Set<string>();
  for (const r of rows) {
    const id = (r.canonicalId || r.cveId || '').trim().toUpperCase();
    const pkg = (r.packageName || '').trim().toLowerCase().replace(/:\d[\w.-]*$/, '');
    keys.add(`${id}|${pkg}`);
  }
  return keys.size;
}
