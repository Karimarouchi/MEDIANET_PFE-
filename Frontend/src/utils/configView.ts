import type { ConfigFindingDto } from "../services/api";

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4, INFO: 5 };

export const CONFIG_SEVERITY_LABEL: Record<string, string> = {
  CRITICAL: "Critique",
  HIGH: "Élevée",
  MEDIUM: "Moyenne",
  LOW: "Faible",
  UNKNOWN: "Non évaluée",
  INFO: "Info",
};

export const CONFIG_CATEGORY_LABEL: Record<string, string> = {
  DOCKERFILE: "Dockerfile",
  KUBERNETES: "Kubernetes",
  TERRAFORM: "Terraform",
  CI_CD: "CI/CD",
  OTHER: "Autre",
};

const CATEGORY_ORDER = ["DOCKERFILE", "KUBERNETES", "TERRAFORM", "CI_CD", "OTHER"];

export const normalizeConfigSeverity = (s: string | null | undefined): string => {
  const v = (s ?? "").toUpperCase();
  return v in SEVERITY_RANK ? v : "UNKNOWN";
};

export const configSeverityLabel = (s: string | null | undefined): string =>
  CONFIG_SEVERITY_LABEL[normalizeConfigSeverity(s)];

export function configSeverityBadge(s: string | null | undefined): string {
  switch (normalizeConfigSeverity(s)) {
    case "CRITICAL":
      return "bg-error-container text-on-error-container";
    case "HIGH":
      return "bg-error/15 text-error";
    case "MEDIUM":
      return "bg-[#FFBD2E]/15 text-[#FFBD2E]";
    case "LOW":
      return "bg-primary/15 text-primary";
    default:
      return "bg-surface-container-high text-on-surface-variant";
  }
}

const byPlace = (a: ConfigFindingDto, b: ConfigFindingDto) =>
  SEVERITY_RANK[normalizeConfigSeverity(a.severity)] - SEVERITY_RANK[normalizeConfigSeverity(b.severity)] ||
  (a.file ?? "").localeCompare(b.file ?? "") ||
  (a.startLine ?? 0) - (b.startLine ?? 0) ||
  a.ruleId.localeCompare(b.ruleId);

/** Main list = everything rated above INFO (including "Non évaluée"); INFO-level hints are kept apart, not dropped. */
export function splitConfigFindings(list: ConfigFindingDto[]): { main: ConfigFindingDto[]; low: ConfigFindingDto[] } {
  const sorted = [...list].sort(byPlace);
  return {
    main: sorted.filter(f => normalizeConfigSeverity(f.severity) !== "INFO"),
    low: sorted.filter(f => normalizeConfigSeverity(f.severity) === "INFO"),
  };
}

export function groupConfigByCategory(
  list: ConfigFindingDto[],
): { category: string; label: string; items: ConfigFindingDto[] }[] {
  const groups = new Map<string, ConfigFindingDto[]>();
  for (const f of list) {
    const key = CATEGORY_ORDER.includes(f.category) ? f.category : "OTHER";
    groups.set(key, [...(groups.get(key) ?? []), f]);
  }
  return CATEGORY_ORDER.filter(c => groups.has(c)).map(c => ({
    category: c,
    label: CONFIG_CATEGORY_LABEL[c],
    items: groups.get(c)!,
  }));
}

export function countConfigBySeverity(list: ConfigFindingDto[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of list) {
    const k = normalizeConfigSeverity(f.severity);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

const TOOL_LABEL: Record<string, string> = {
  trivy: "Trivy",
  checkov: "Checkov",
  hadolint: "Hadolint",
  nuclei: "Nuclei",
  zaproxy: "ZAP",
  zap: "ZAP",
};

export const toolLabel = (t: string): string => TOOL_LABEL[t.trim().toLowerCase()] ?? t.trim();
