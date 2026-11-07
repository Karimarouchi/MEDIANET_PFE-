/**
 * The three families of findings the matrix must never mix: a vulnerability of a dependency (CVE), a weakness in the
 * code (CWE, Semgrep) and an alert on a running application (DAST: ZAP, Nuclei). Misconfigurations are a fourth kind
 * but come from their own endpoint and never appear in this list.
 */
export type FindingFamily = "dependency" | "code" | "dast";

type FamilyInput = {
  findingKind?: string | null;
  source?: string | null;
  sources?: string | null;
  cveId?: string | null;
};

const DAST_TOOLS = ["zaproxy", "zap", "nuclei"];

export function findingFamily(f: FamilyInput): FindingFamily {
  if (f.findingKind === "CODE_WEAKNESS") return "code";
  if (f.findingKind === "DAST") return "dast";
  if (f.findingKind === "DEPENDENCY") return "dependency";
  const sources = `${f.source ?? ""} ${f.sources ?? ""}`.toLowerCase();
  const id = (f.cveId ?? "").toUpperCase();
  if (sources.includes("semgrep") || id.startsWith("CWE-")) return "code";
  if (DAST_TOOLS.some(t => sources.split(/[\s,]+/).includes(t)) || id.startsWith("ZAP-") || id.startsWith("NUCLEI-")) {
    return "dast";
  }
  return "dependency";
}

export const isDastFinding = (f: FamilyInput) => findingFamily(f) === "dast";
