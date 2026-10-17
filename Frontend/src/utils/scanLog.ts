/**
 * Pure logic behind the live scan log: colour of each source ([SBOM], [NVD]...), the pipeline stage the scan is in,
 * live counters and the 0-100 % progress. Everything is derived from the log lines, so the scanner does not change.
 */

export type Source =
  | "sbom" | "nvd" | "risk" | "ml" | "secrets" | "sast" | "cve" | "system" | "success" | "warn" | "error" | "other";

export interface LogEntry {
  /** local time of reception, HH:MM:SS (one clock only: the scanner's UTC stamps are dropped) */
  time: string;
  /** receiving time in ms, to detect a silent scan */
  at: number;
  /** [TAG] shown in the left column, "" when the line has none */
  tag: string;
  source: Source;
  text: string;
}

export const SOURCE_STYLE: Record<Source, { label: string; text: string; badge: string; dot: string }> = {
  sbom: { label: "SBOM", text: "text-sky-300", badge: "bg-sky-500/15 text-sky-300 border-sky-400/30", dot: "bg-sky-400" },
  nvd: { label: "NVD", text: "text-violet-300", badge: "bg-violet-500/15 text-violet-300 border-violet-400/30", dot: "bg-violet-400" },
  risk: { label: "RISQUE", text: "text-orange-300", badge: "bg-orange-500/15 text-orange-300 border-orange-400/30", dot: "bg-orange-400" },
  ml: { label: "ML", text: "text-pink-300", badge: "bg-pink-500/15 text-pink-300 border-pink-400/30", dot: "bg-pink-400" },
  secrets: { label: "SECRETS", text: "text-rose-300", badge: "bg-rose-500/15 text-rose-300 border-rose-400/30", dot: "bg-rose-400" },
  sast: { label: "SAST", text: "text-yellow-300", badge: "bg-yellow-500/15 text-yellow-300 border-yellow-400/30", dot: "bg-yellow-400" },
  cve: { label: "CVE", text: "text-cyan-300", badge: "bg-cyan-500/15 text-cyan-300 border-cyan-400/30", dot: "bg-cyan-400" },
  system: { label: "SYSTÈME", text: "text-outline", badge: "bg-surface-container-high text-outline border-outline-variant/30", dot: "bg-outline" },
  success: { label: "OK", text: "text-emerald-300", badge: "bg-emerald-500/15 text-emerald-300 border-emerald-400/30", dot: "bg-emerald-400" },
  warn: { label: "ALERTE", text: "text-amber-300", badge: "bg-amber-500/15 text-amber-300 border-amber-400/30", dot: "bg-amber-400" },
  error: { label: "ERREUR", text: "text-red-400", badge: "bg-red-500/20 text-red-300 border-red-400/40", dot: "bg-red-500" },
  other: { label: "SCAN", text: "text-on-surface-variant", badge: "bg-surface-container-high text-on-surface-variant border-outline-variant/30", dot: "bg-outline" },
};

const TAG_SOURCE: Record<string, Source> = {
  SBOM: "sbom",
  NVD: "nvd", OSV: "nvd", GHSA: "nvd", ENRICH: "nvd",
  EPSS: "risk", KEV: "risk", EXPLOITDB: "risk",
  "SUPPLY-CHAIN": "ml", SECRETS: "ml", ML: "ml",
  SUCCESS: "success", WARN: "warn", ERROR: "error", SYSTEM: "system", INFO: "system", SCAN: "other",
};

/**
 * A tool name as a word of its own: "credsweeper — second secret detector", not "Dockerfile.credsweeper" or
 * "scripts/run_credsweeper.sh" (file names in the hadolint/trivy file lists).
 */
function tool(names: string): RegExp {
  return new RegExp(`(?<![\\w./-])(?:${names})(?![\\w.-])`, "i");
}

/** scanner output has no [TAG]: the tool name tells what a line is about */
const TOOL_SOURCE: [RegExp, Source][] = [
  [tool("gitleaks|credsweeper|trufflehog"), "secrets"],
  [tool("semgrep"), "sast"],
  [tool("syft|maven-cyclonedx|cyclonedx|sbom"), "sbom"],
  [tool("trivy|grype|osv-scanner|npm audit|dependency-check|pip-audit"), "cve"],
];

const ISO_STAMP = /^\[\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}Z?\]\s*/;
const ISO_PARTS = /^\[(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})Z?\]/;

/** The UTC moment the scanner wrote on the line, or null when the line has no stamp. */
export function scannerTime(raw: string): Date | null {
  const m = ISO_PARTS.exec(raw);
  if (!m) return null;
  const d = new Date(`${m[1]}T${m[2]}Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function parseLogLine(raw: string, now: Date = new Date()): LogEntry {
  // The scanner stamps its lines in UTC. Show that moment in local time: on reopening the page the whole log is
  // replayed at once, and the reception time made every line look as if it happened at the same second.
  const when = scannerTime(raw) ?? now;
  const time = when.toTimeString().slice(0, 8);
  const base = { time, at: when.getTime() };
  let text = raw.replace(ISO_STAMP, "").trim();
  const m = /^\[([A-Z][A-Z-]{1,14})\]\s*/.exec(text);
  if (m) {
    const tag = m[1];
    const source = TAG_SOURCE[tag];
    if (source) return { ...base, tag: `[${tag}]`, source, text: text.slice(m[0].length) };
  }
  // tag in the middle of the line, e.g. "[2026-..] [INFO] ..." already stripped above; keep older "[WARN]" anywhere
  const inner = /\[(SUCCESS|WARN|ERROR|INFO|SYSTEM)\]/.exec(text);
  if (inner) {
    return { ...base, tag: inner[0], source: TAG_SOURCE[inner[1]], text: text.replace(inner[0], "").trim() };
  }
  for (const [re, source] of TOOL_SOURCE) {
    if (re.test(text)) return { ...base, tag: "", source, text };
  }
  return { ...base, tag: "", source: "other", text };
}

// ───────────────────────── pipeline ─────────────────────────

export interface StageDef {
  id: string;
  label: string;
  icon: string;
  match: RegExp;
}

export const STAGES: StageDef[] = [
  { id: "clone", label: "Clonage", icon: "download", match: /clon(ing|age)|git clone|repo_dir|checkout/i },
  { id: "secrets", label: "Secrets", icon: "key", match: tool("gitleaks|credsweeper|trufflehog") },
  { id: "sast", label: "Code (SAST)", icon: "code", match: tool("semgrep") },
  { id: "sbom", label: "SBOM", icon: "inventory_2", match: /\bsyft\b|cyclonedx|\[SBOM\]|\bSBOM\b/i },
  { id: "cve", label: "Vulnérabilités", icon: "bug_report", match: /trivy|grype|osv-scanner|npm audit|dependency-check|pip-audit/i },
  { id: "enrich", label: "Enrichissement", icon: "hub", match: /^\[(NVD|OSV|GHSA|EPSS|KEV|EXPLOITDB|ENRICH)\]/ },
  { id: "ml", label: "Modèles ML", icon: "psychology", match: /^\[(SUPPLY-CHAIN|SECRETS|ML)\]/ },
];

export type StageState = "pending" | "active" | "done";

export interface ScanProgress {
  stages: { def: StageDef; state: StageState }[];
  percent: number;
  counters: { cves: number | null; secrets: number | null; packages: number | null; suspects: number | null };
  lastActivityMs: number | null;
}

function lastNumber(re: RegExp, lines: string[]): number | null {
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = re.exec(lines[i]);
    if (m) return Number(m[1] ?? m[2]);
  }
  return null;
}

/**
 * The scan runs the stages in order. A stage is "active" while it is the last one seen, "done" once a later one
 * appeared, and every stage is "done" when the scan is complete (100 %). The ML stage only reaches "done" at the end:
 * the backend sends the completion marker after the supply-chain and secret-triage models have finished.
 */
export function computeProgress(entries: LogEntry[], complete: boolean, now: number = Date.now()): ScanProgress {
  const seenAt: number[] = STAGES.map(() => -1);
  entries.forEach((e, idx) => {
    const probe = e.tag ? `${e.tag} ${e.text}` : e.text;
    STAGES.forEach((s, si) => {
      if (s.match.test(probe)) seenAt[si] = idx;
    });
  });
  // the active stage is the one whose last line is the most recent
  let current = -1;
  let best = -1;
  seenAt.forEach((idx, si) => {
    if (idx > best) {
      best = idx;
      current = si;
    }
  });
  const highest = seenAt.reduce((acc, idx, si) => (idx >= 0 ? si : acc), -1);
  const front = Math.max(current, highest);
  const stages = STAGES.map((def, si) => {
    let state: StageState = "pending";
    if (complete) state = "done";
    else if (si < front && (seenAt[si] >= 0 || si < highest)) state = "done";
    else if (si === front && seenAt[si] >= 0) state = "active";
    return { def, state };
  });
  const doneCount = stages.filter((s) => s.state === "done").length;
  const activeBonus = stages.some((s) => s.state === "active") ? 0.5 : 0;
  const percent = complete ? 100 : Math.min(99, Math.round(((doneCount + activeBonus) / STAGES.length) * 100));

  const lines = entries.map((e) => (e.tag ? `${e.tag} ${e.text}` : e.text));
  const suspects = (() => {
    for (let i = lines.length - 1; i >= 0; i--) {
      const m = /\[SUPPLY-CHAIN\] Terminé.*?(\d+) connu\(s\) malveillant\(s\), (\d+) confiance élevée, (\d+) à vérifier/.exec(lines[i]);
      if (m) return Number(m[1]) + Number(m[2]) + Number(m[3]);
    }
    return null;
  })();
  return {
    stages,
    percent,
    counters: {
      cves: lastNumber(/(\d+) CVEs? found/i, lines),
      secrets: lastNumber(/(\d+) secret\(s\) found|leaks found: (\d+)/i, lines),
      packages: lastNumber(/(\d+) packages/i, lines),
      suspects,
    },
    lastActivityMs: entries.length ? now - entries[entries.length - 1].at : null,
  };
}

export function formatIdle(ms: number | null): string | null {
  if (ms == null || ms < 20_000) return null;
  const s = Math.round(ms / 1000);
  return s < 90 ? `${s} s` : `${Math.round(s / 60)} min`;
}

export const SOURCE_FILTERS: { key: Source | "all"; label: string }[] = [
  { key: "all", label: "Tout" },
  { key: "secrets", label: "Secrets" },
  { key: "sast", label: "SAST" },
  { key: "sbom", label: "SBOM" },
  { key: "cve", label: "CVE" },
  { key: "nvd", label: "NVD" },
  { key: "risk", label: "Risque" },
  { key: "ml", label: "ML" },
  { key: "warn", label: "Alertes" },
  { key: "error", label: "Erreurs" },
];
