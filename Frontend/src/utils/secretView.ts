import type { SecretDto } from "../services/api";

/** What the page shows for a secret: the analyst's call wins over the model's verdict. */
export type EffectiveVerdict = "LIKELY_REAL" | "REVIEW" | "LIKELY_FALSE_POSITIVE" | "UNTRIAGED";

export function effectiveVerdict(s: SecretDto): EffectiveVerdict {
  if (s.analystVerdict === "REAL") return "LIKELY_REAL";
  if (s.analystVerdict === "FALSE_POSITIVE") return "LIKELY_FALSE_POSITIVE";
  const v = s.mlVerdict;
  if (v === "LIKELY_REAL" || v === "REVIEW" || v === "LIKELY_FALSE_POSITIVE") return v;
  return "UNTRIAGED";
}

/** 1 = look first. An analyst-confirmed secret is always first; test/doc files rank below production code. */
export function secretPriority(s: SecretDto): number {
  if (s.analystVerdict === "REAL") return 0;
  const v = effectiveVerdict(s);
  if (v === "LIKELY_REAL") return s.mlScope === "TEST_OR_DOC" ? 2 : 1;
  if (v === "UNTRIAGED") return 3; // no model verdict: cannot be hidden, shown with the ones to check
  if (v === "REVIEW") return 3;
  return 4;
}

export interface SecretGroups {
  toHandle: SecretDto[];
  /** Probably real values that sit in test, example or documentation files: shown apart, lower priority. */
  testAndDocs: SecretDto[];
  toCheck: SecretDto[];
  falsePositives: SecretDto[];
  untriaged: number;
}

export function groupSecrets(secrets: SecretDto[]): SecretGroups {
  const sorted = [...secrets].sort(
    (a, b) =>
      secretPriority(a) - secretPriority(b) ||
      (b.mlProba ?? 0) - (a.mlProba ?? 0) ||
      (a.file ?? "").localeCompare(b.file ?? ""),
  );
  const toHandle: SecretDto[] = [];
  const testAndDocs: SecretDto[] = [];
  const toCheck: SecretDto[] = [];
  const falsePositives: SecretDto[] = [];
  let untriaged = 0;
  for (const s of sorted) {
    const v = effectiveVerdict(s);
    if (v === "UNTRIAGED") untriaged += 1;
    if (v === "LIKELY_REAL") {
      // the analyst's "real" always goes to the top list, whatever the file
      (s.analystVerdict !== "REAL" && s.mlScope === "TEST_OR_DOC" ? testAndDocs : toHandle).push(s);
    }
    else if (v === "LIKELY_FALSE_POSITIVE") falsePositives.push(s);
    else toCheck.push(s);
  }
  return { toHandle, testAndDocs, toCheck, falsePositives, untriaged };
}

export const VERDICT_LABEL: Record<EffectiveVerdict, string> = {
  LIKELY_REAL: "Probablement réel",
  REVIEW: "À vérifier",
  LIKELY_FALSE_POSITIVE: "Probablement faux positif",
  UNTRIAGED: "Non trié",
};

export function verdictBadge(v: EffectiveVerdict): string {
  switch (v) {
    case "LIKELY_REAL":
      return "bg-error-container text-on-error-container";
    case "REVIEW":
      return "bg-secondary-container text-on-secondary-container";
    case "LIKELY_FALSE_POSITIVE":
      return "bg-tertiary-container text-on-tertiary-container";
    default:
      return "bg-surface-variant text-on-surface-variant";
  }
}

export function formatProba(p?: number | null): string {
  if (p == null || Number.isNaN(p)) return "—";
  return `${Math.round(p * 100)} %`;
}
