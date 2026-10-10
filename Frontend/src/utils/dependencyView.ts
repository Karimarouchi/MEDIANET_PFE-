import type { CveDto, SbomComponent, SupplyChainBrief, SupplyChainItem } from "../services/api";

/**
 * Pure logic behind the "Dépendances" tab: which dependency needs attention FIRST, and why, in one sentence.
 * Kept free of React so it can be unit-tested on its own.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type DepView = "critical" | "cve" | "suspect" | "all";

export interface DepRow {
  pkg: SbomComponent;
  cves: CveDto[];
  worst: Severity | null;
  fixedVersion: string | null;
  hasKev: boolean;
  hasExploit: boolean;
  brief: SupplyChainBrief | null;
  flagged: SupplyChainItem | null;
  /** false for languages the supply-chain model does not cover (Java, Go...). */
  supplyCovered: boolean;
  /** 0 = most urgent. Used to sort the list. */
  priority: number;
  /** needs action first: malicious / very suspicious package, critical CVE, or a CVE exploited in the wild. */
  critical: boolean;
  suspect: boolean;
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SUSPECT_TIERS = ["KNOWN_MALICIOUS", "HIGH_CONFIDENCE", "REVIEW"];

export function severityRank(s?: string | null): number {
  const i = SEVERITY_ORDER.indexOf((s ?? "").toUpperCase() as Severity);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

export function worstSeverity(cves: CveDto[]): Severity | null {
  let best = SEVERITY_ORDER.length;
  for (const c of cves) best = Math.min(best, severityRank(c.severity));
  return best < SEVERITY_ORDER.length ? SEVERITY_ORDER[best] : null;
}

/** Version that fixes the most severe CVE of the package (falls back to any fix). */
export function bestFix(cves: CveDto[]): string | null {
  const ordered = [...cves].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  for (const c of ordered) {
    const v = (c.fixedVersion ?? "").trim();
    if (v) return v;
  }
  return null;
}

export function priorityOf(tier: string | null | undefined, worst: Severity | null, hasKev: boolean, hasExploit: boolean): number {
  if (tier === "KNOWN_MALICIOUS") return 0;
  if (tier === "HIGH_CONFIDENCE") return 1;
  if (worst === "CRITICAL" || ((hasKev || hasExploit) && worst === "HIGH")) return 2;
  if (worst === "HIGH") return 3;
  if (tier === "REVIEW") return 4;
  if (worst === "MEDIUM") return 5;
  if (worst === "LOW") return 6;
  if (worst) return 6; // unknown severity label still counts as a CVE
  return 9;
}

export function buildDependencyRows(
  components: SbomComponent[],
  cves: CveDto[],
  briefFor: (pkg: SbomComponent) => SupplyChainBrief | null,
  flaggedFor: (pkg: SbomComponent) => SupplyChainItem | null,
  supplyCovered: (pkg: SbomComponent) => boolean
): DepRow[] {
  const byName = new Map<string, CveDto[]>();
  for (const c of cves) {
    const key = (c.packageName ?? "").toLowerCase();
    if (!key) continue;
    const list = byName.get(key);
    if (list) list.push(c);
    else byName.set(key, [c]);
  }
  const rows = components.map<DepRow>((pkg) => {
    const own = byName.get(pkg.name.toLowerCase()) ?? [];
    const brief = briefFor(pkg);
    const tier = brief?.tier ?? null;
    const worst = worstSeverity(own);
    const hasKev = own.some((c) => c.kevListed);
    const hasExploit = own.some((c) => c.exploitAvailable);
    const priority = priorityOf(tier, worst, hasKev, hasExploit);
    return {
      pkg,
      cves: own,
      worst,
      fixedVersion: bestFix(own),
      hasKev,
      hasExploit,
      brief,
      flagged: flaggedFor(pkg),
      supplyCovered: supplyCovered(pkg),
      priority,
      critical: priority <= 2,
      suspect: SUSPECT_TIERS.includes(tier ?? ""),
    };
  });
  return rows.sort(
    (a, b) =>
      a.priority - b.priority ||
      b.cves.length - a.cves.length ||
      a.pkg.name.localeCompare(b.pkg.name)
  );
}

export function countViews(rows: DepRow[]): Record<DepView, number> {
  return {
    critical: rows.filter((r) => r.critical).length,
    cve: rows.filter((r) => r.cves.length > 0).length,
    suspect: rows.filter((r) => r.suspect).length,
    all: rows.length,
  };
}

/** Open on the most useful view: critical items if any, else packages with CVEs, else suspects, else everything. */
export function defaultView(counts: Record<DepView, number>): DepView {
  if (counts.critical > 0) return "critical";
  if (counts.cve > 0) return "cve";
  if (counts.suspect > 0) return "suspect";
  return "all";
}

export function filterRows(rows: DepRow[], view: DepView, search: string, ecosystem: string): DepRow[] {
  const q = search.trim().toLowerCase();
  return rows.filter((r) => {
    if (view === "critical" && !r.critical) return false;
    if (view === "cve" && r.cves.length === 0) return false;
    if (view === "suspect" && !r.suspect) return false;
    if (ecosystem && r.pkg.type !== ecosystem) return false;
    if (q) {
      const hay = `${r.pkg.name} ${r.pkg.version ?? ""} ${r.pkg.type ?? ""} ${r.pkg.license ?? ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

const SEVERITY_FR: Record<Severity, string> = {
  CRITICAL: "critique",
  HIGH: "élevée",
  MEDIUM: "moyenne",
  LOW: "faible",
};

/** One plain-language sentence saying why this dependency is in the list. */
export function reasonLine(r: DepRow): string {
  const parts: string[] = [];
  const tier = r.brief?.tier;
  if (tier === "KNOWN_MALICIOUS") parts.push("Paquet connu comme malveillant (liste OSSF)");
  else if (tier === "HIGH_CONFIDENCE") parts.push("Paquet très suspect (comportement de paquet malveillant)");
  else if (tier === "REVIEW") parts.push("Paquet à vérifier (supply chain)");
  if (r.cves.length > 0) {
    const crit = r.cves.filter((c) => (c.severity ?? "").toUpperCase() === "CRITICAL").length;
    const label = r.cves.length === 1 ? "1 vulnérabilité" : `${r.cves.length} vulnérabilités`;
    const sev = r.worst ? ` (la plus grave : ${SEVERITY_FR[r.worst]})` : "";
    parts.push(crit > 1 ? `${label}, dont ${crit} critiques` : `${label}${sev}`);
  }
  if (r.hasKev) parts.push("exploitée activement (CISA KEV)");
  else if (r.hasExploit) parts.push("exploit public connu");
  return parts.join(" · ");
}

export const VIEW_HELP: Record<DepView, string> = {
  critical:
    "Paquets malveillants ou très suspects, vulnérabilités critiques ou exploitées activement : à traiter en premier.",
  cve: "Tous les paquets qui ont au moins une vulnérabilité connue (CVE), les plus graves en premier.",
  suspect: "Paquets que le modèle supply chain signale comme ressemblant à un paquet malveillant.",
  all: "Toutes les dépendances du projet, les plus urgentes en premier.",
};
