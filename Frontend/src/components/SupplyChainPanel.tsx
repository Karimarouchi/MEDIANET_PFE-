import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  analyzeSupplyChain,
  checkSupplyChain,
  getSupplyChain,
  type SupplyChainBrief,
  type SupplyChainCheckResult,
  type SupplyChainItem,
  type SupplyChainReport,
} from "../services/api";

type Props = {
  scanId: number;
};

export const TIER_LABEL: Record<string, string> = {
  KNOWN_MALICIOUS: "Connu malveillant",
  HIGH_CONFIDENCE: "Confiance élevée",
  REVIEW: "À vérifier",
};

const TYPE_LABEL: Record<string, string> = {
  empty_placeholder: "Coquille vide (nom squatté ?)",
  dependency_confusion: "Confusion de dépendances",
  credential_stealer: "Voleur d'informations",
  downloader_dropper: "Téléchargeur / dropper",
  obfuscated_payload: "Code obfusqué",
  spam_farm: "Spam / ferme de paquets",
  other_malicious: "Autre comportement suspect",
};

export function tierBadge(tier?: string | null): string {
  switch (tier) {
    case "KNOWN_MALICIOUS":
      return "bg-error text-on-error border-error";
    case "HIGH_CONFIDENCE":
      return "bg-error/15 text-error border-error/30";
    case "REVIEW":
      return "bg-amber-500/15 text-amber-300 border-amber-500/30";
    default:
      return "bg-surface-container-highest text-outline border-outline-variant/30";
  }
}

export function formatProba(p?: number | null): string {
  if (p == null || Number.isNaN(p)) return "—";
  return `${(p * 100).toFixed(p >= 0.995 || p < 0.01 ? 1 : 0)} %`;
}

export function normalizePypiName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
}

export function ecosystemOfPurl(purl?: string | null): "npm" | "pypi" | null {
  if (!purl) return null;
  if (purl.startsWith("pkg:npm/")) return "npm";
  if (purl.startsWith("pkg:pypi/")) return "pypi";
  return null;
}

/** Same key as the backend cache: PyPI names are compared in their normalised form (PEP 503). */
export function supplyChainKey(ecosystem: string, name: string, version: string): string {
  return `${ecosystem}:${ecosystem === "pypi" ? normalizePypiName(name) : name}@${version}`;
}

/**
 * Loads the supply-chain report of a scan, refreshes it while the background analysis runs (and for a short grace
 * period after a scan, so a freshly finished scan fills in by itself) and exposes a manual "analyse" action.
 * `enabled=false` pauses loading (for example when another tab is displayed).
 */
export function useSupplyChainReport(scanId: number | null, enabled = true) {
  const [report, setReport] = useState<SupplyChainReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<number | null>(null);
  const polls = useRef(0);

  const load = useCallback(async () => {
    if (scanId == null) return null;
    try {
      const res = await getSupplyChain(scanId);
      setReport(res.data);
      setError(null);
      return res.data;
    } catch {
      setError("Impossible de charger l'analyse supply chain.");
      return null;
    }
  }, [scanId]);

  useEffect(() => {
    setReport(null);
    polls.current = 0;
  }, [scanId]);

  useEffect(() => {
    if (!enabled || scanId == null) return;
    let alive = true;
    setLoading(true);
    load().finally(() => alive && setLoading(false));
    return () => {
      alive = false;
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [load, enabled, scanId]);

  useEffect(() => {
    if (timer.current) window.clearTimeout(timer.current);
    if (!enabled || !report) return;
    const waitingForStart =
      report.summary.pending > 0 && report.totalComponents > 0 && report.modelAvailable && polls.current < 15;
    if (report.analysisRunning || waitingForStart) {
      if (!report.analysisRunning) polls.current += 1;
      timer.current = window.setTimeout(() => void load(), 4000);
    }
  }, [report, load, enabled]);

  const analyze = async () => {
    if (scanId == null) return;
    setAnalyzing(true);
    try {
      const res = await analyzeSupplyChain(scanId);
      setReport(res.data);
      setError(null);
    } catch {
      setError("L'analyse a échoué. Réessayez dans un instant.");
    } finally {
      setAnalyzing(false);
    }
  };

  return { report, loading, analyzing, error, analyze, reload: load };
}

/** Counters, the flagged packages with their reasons, and the "analyse" button. */
export const SupplyChainSummary: React.FC<{
  report: SupplyChainReport;
  busy: boolean;
  error?: string | null;
  onAnalyze: () => void;
  compact?: boolean;
}> = ({ report, busy, error, onAnalyze, compact }) => {
  const s = report.summary;
  const flaggedCount = s.knownMalicious + s.highConfidence + s.review;
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-3xl">
          <h2 className="font-headline text-xl font-semibold text-on-surface">
            {compact ? "Risque supply chain" : "Supply chain des dépendances (npm et PyPI)"}
          </h2>
          <p className="text-xs text-on-surface-variant mt-1">
            Détecte les paquets <strong>npm et Python (PyPI)</strong> qui <strong>ressemblent à des paquets
            malveillants</strong>, même sans CVE (confusion de dépendances, voleurs d'informations, droppers…).
            Chaque paquet est lu en mémoire, jamais installé ni exécuté. Les autres langages (Java, Go…) ne sont
            pas couverts par ce modèle.
          </p>
        </div>
        <button
          onClick={onAnalyze}
          disabled={busy || !report.modelAvailable || report.totalComponents === 0}
          className="px-4 py-2 rounded-xl text-sm font-medium bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25 disabled:opacity-50"
        >
          {busy ? "Analyse en cours…" : s.pending > 0 ? `Analyser (${s.pending} à faire)` : "Réanalyser"}
        </button>
      </div>

      {!report.modelAvailable && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          Le modèle supply chain n'est pas installé sur ce serveur (dossier <code>ml/supplychain/artifacts</code>).
        </div>
      )}

      {report.totalComponents === 0 && (
        <p className="text-sm text-on-surface-variant">
          Aucune dépendance npm ou PyPI dans le SBOM de ce scan : rien à analyser.
        </p>
      )}

      {report.totalComponents > 0 && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5 text-sm">
          <Stat label="Dépendances npm / PyPI" value={report.totalComponents} />
          <Stat label="Connus malveillants" value={s.knownMalicious} danger={s.knownMalicious > 0} />
          <Stat label="Confiance élevée" value={s.highConfidence} danger={s.highConfidence > 0} />
          <Stat label="À vérifier" value={s.review} warn={s.review > 0} />
          <Stat label="Sans alerte" value={s.low} />
        </div>
      )}

      {(s.pending > 0 || s.notAnalysed > 0) && report.totalComponents > 0 && (
        <p className="text-xs text-outline">
          {s.pending > 0 && `${s.pending} dépendance(s) pas encore analysée(s). `}
          {s.notAnalysed > 0 && `${s.notAnalysed} non analysable(s) (paquet introuvable, trop volumineux…).`}
        </p>
      )}

      {flaggedCount === 0 && report.totalComponents > 0 && s.pending === 0 && (
        <div className="rounded-xl border border-tertiary/30 bg-tertiary/10 px-4 py-3 text-sm text-on-surface">
          Aucun paquet suspect parmi les {s.low} dépendance(s) analysée(s).
        </div>
      )}

      {report.flagged.length > 0 && (
        <div className="space-y-3">
          {report.flagged.map((item) => (
            <FlaggedRow key={`${item.ecosystem}:${item.name}@${item.version}`} item={item} />
          ))}
        </div>
      )}

      {error && <p className="text-xs text-error">{error}</p>}
      <p className="text-[11px] text-outline leading-relaxed">{report.disclaimer}</p>
    </section>
  );
};

/** One-line verdict of the supply-chain screening + the analyse button; the long explanation is folded away. */
export const SupplyChainBanner: React.FC<{
  report: SupplyChainReport | null;
  busy: boolean;
  error?: string | null;
  onAnalyze: () => void;
}> = ({ report, busy, error, onAnalyze }) => {
  if (!report) {
    return <p className="text-sm text-outline">{error ?? "Chargement de l'analyse supply chain…"}</p>;
  }
  const s = report.summary;
  const bad = s.knownMalicious + s.highConfidence;
  let tone = "border-tertiary/30 bg-tertiary/10";
  let icon = "verified_user";
  let text = `Aucun paquet suspect parmi les ${s.low} dépendances npm / PyPI analysées.`;
  if (!report.modelAvailable) {
    tone = "border-amber-500/30 bg-amber-500/10";
    icon = "info";
    text = "Le modèle supply chain n'est pas installé sur ce serveur.";
  } else if (report.totalComponents === 0) {
    tone = "border-outline-variant/30 bg-surface-container";
    icon = "info";
    text = "Aucune dépendance npm ou PyPI à analyser dans ce scan.";
  } else if (bad > 0) {
    tone = "border-error/40 bg-error/10";
    icon = "gpp_bad";
    text = `${bad} paquet(s) malveillant(s) ou très suspect(s) détecté(s) : à supprimer ou remplacer.`;
  } else if (s.review > 0) {
    tone = "border-amber-500/30 bg-amber-500/10";
    icon = "gpp_maybe";
    text = `${s.review} paquet(s) à vérifier manuellement (aucun n'est confirmé malveillant).`;
  } else if (s.pending > 0) {
    tone = "border-outline-variant/30 bg-surface-container";
    icon = "hourglass_top";
    text = `Analyse en cours : ${s.pending} dépendance(s) restante(s).`;
  }
  return (
    <div className={`rounded-xl border px-4 py-3 ${tone}`}>
      <div className="flex flex-wrap items-center gap-3">
        <span className="material-symbols-outlined text-xl">{icon}</span>
        <p className="text-sm text-on-surface flex-1 min-w-[220px]">
          <strong>Supply chain : </strong>
          {text}
        </p>
        <button
          onClick={onAnalyze}
          disabled={busy || !report.modelAvailable || report.totalComponents === 0}
          className="px-3 py-1.5 rounded-lg text-xs font-medium bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25 disabled:opacity-50"
        >
          {busy ? "Analyse en cours…" : s.pending > 0 ? `Analyser (${s.pending})` : "Réanalyser"}
        </button>
      </div>
      <details className="mt-2">
        <summary className="text-xs text-outline cursor-pointer">Comment ça marche ?</summary>
        <p className="text-xs text-on-surface-variant mt-2 leading-relaxed">
          Le modèle repère les paquets <strong>npm et PyPI</strong> qui <strong>ressemblent à des paquets
          malveillants</strong>, même sans CVE. Chaque paquet est lu en mémoire, jamais installé ni exécuté. Les autres
          langages (Java, Go…) ne sont pas couverts. {report.disclaimer}
        </p>
      </details>
      {error && <p className="text-xs text-error mt-2">{error}</p>}
    </div>
  );
};

/** Score + level of one dependency, for a table cell. Shows "—" for languages the model does not cover. */
export const SupplyChainCell: React.FC<{ brief?: SupplyChainBrief | null; supported: boolean; pending?: boolean }> = ({
  brief,
  supported,
  pending,
}) => {
  if (!supported) {
    return <span className="text-[11px] text-outline" title="Langage non couvert par le modèle supply chain">—</span>;
  }
  if (!brief) {
    return <span className="text-[11px] text-outline">{pending ? "en attente…" : "—"}</span>;
  }
  if (brief.status && brief.status !== "SCORED" && brief.tier !== "KNOWN_MALICIOUS") {
    return (
      <span className="text-[11px] text-outline" title={SKIP_LABEL[brief.status] ?? brief.status}>
        non analysé
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${tierBadge(brief.tier)}`}>
        {TIER_LABEL[brief.tier ?? ""] ?? "Sans alerte"}
      </span>
      {brief.tier !== "KNOWN_MALICIOUS" && (
        <span className="text-[11px] text-on-surface-variant">{formatProba(brief.suspicionProba)}</span>
      )}
    </span>
  );
};

/** Full page version (summary + all analysed dependencies + package checker). */
const SupplyChainPanel: React.FC<Props> = ({ scanId }) => {
  const { report, loading, analyzing, error, analyze } = useSupplyChainReport(scanId);
  if (loading && !report) {
    return <p className="text-sm text-outline py-6">Chargement de l'analyse supply chain…</p>;
  }
  if (!report) {
    return <p className="text-sm text-error py-6">{error ?? "Aucune donnée."}</p>;
  }
  return (
    <div className="space-y-5">
      <SupplyChainSummary
        report={report}
        busy={analyzing || report.analysisRunning}
        error={error}
        onAnalyze={() => void analyze()}
      />
      {report.totalComponents > 0 && <AnalyzedList analyzed={report.analyzed ?? []} skipped={report.skipped ?? []} />}
      <PackageChecker />
    </div>
  );
};

const PAGE = 40;

const AnalyzedList: React.FC<{ analyzed: SupplyChainBrief[]; skipped: SupplyChainBrief[] }> = ({ analyzed, skipped }) => {
  const [open, setOpen] = useState(false);
  const [all, setAll] = useState(false);
  if (analyzed.length === 0 && skipped.length === 0) return null;
  const rows = all ? analyzed : analyzed.slice(0, PAGE);
  const max = Math.max(0.5, ...analyzed.map((a) => a.suspicionProba ?? 0));
  return (
    <div className="rounded-2xl border border-outline-variant/[0.18] bg-surface-container">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-3 text-sm text-on-surface"
        aria-expanded={open}
      >
        <span>
          {open ? "Masquer" : "Voir"} les {analyzed.length} dépendances analysées avec leur score de suspicion
        </span>
        <span className="text-outline">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="px-5 pb-4 space-y-3">
          <p className="text-xs text-on-surface-variant">
            Score entre 0 % et 100 % : plus il est haut, plus le paquet ressemble à un paquet malveillant. « À vérifier »
            correspond à un seuil large, « Confiance élevée » à un seuil strict, « Connu malveillant » à la liste OSSF.</p>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-[10px] uppercase tracking-widest text-outline">
                <tr>
                  <th className="py-1 pr-3 font-medium">Paquet</th>
                  <th className="py-1 pr-3 font-medium">Type</th>
                  <th className="py-1 pr-3 font-medium">Suspicion</th>
                  <th className="py-1 font-medium">Niveau</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={`${a.ecosystem}:${a.name}@${a.version}`} className="border-t border-outline-variant/15">
                    <td className="py-1.5 pr-3 font-mono text-on-surface">
                      {a.name}
                      <span className="text-outline">@{a.version}</span>
                    </td>
                    <td className="py-1.5 pr-3 text-xs uppercase text-outline">{a.ecosystem}</td>
                    <td className="py-1.5 pr-3 w-48">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 flex-1 rounded bg-surface-container-highest overflow-hidden">
                          <div
                            className={`h-full ${(a.suspicionProba ?? 0) >= 0.5 ? "bg-error" : (a.suspicionProba ?? 0) >= 0.14 ? "bg-amber-400" : "bg-tertiary"}`}
                            style={{ width: `${Math.min(100, ((a.suspicionProba ?? 0) / max) * 100)}%` }}
                          />
                        </div>
                        <span className="w-12 text-right text-xs text-on-surface-variant">{formatProba(a.suspicionProba)}</span>
                      </div>
                    </td>
                    <td className="py-1.5">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${tierBadge(a.tier)}`}>
                        {TIER_LABEL[a.tier ?? ""] ?? "Sans alerte"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {analyzed.length > PAGE && (
            <button onClick={() => setAll(!all)} className="text-xs text-primary hover:underline">
              {all ? "Réduire la liste" : `Afficher les ${analyzed.length - PAGE} autres`}
            </button>
          )}
          {skipped.length > 0 && (
            <div className="pt-2 border-t border-outline-variant/15">
              <p className="text-xs text-on-surface-variant mb-1">Non analysées ({skipped.length}) :</p>
              <ul className="text-xs text-outline space-y-0.5">
                {skipped.map((k) => (
                  <li key={`${k.ecosystem}:${k.name}@${k.version}`}>
                    <span className="font-mono">{k.name}@{k.version}</span> : {SKIP_LABEL[k.status ?? ""] ?? k.status}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export const SKIP_LABEL: Record<string, string> = {
  NOT_FOUND: "introuvable sur le registre public (module interne ou privé ?)",
  TOO_LARGE: "trop volumineux pour être analysé",
  NO_SDIST: "pas d'archive source disponible",
  UNSUPPORTED_ECOSYSTEM: "langage non couvert",
};

export const PackageChecker: React.FC = () => {
  const [ecosystem, setEcosystem] = useState("npm");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SupplyChainCheckResult | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const run = async () => {
    if (!name.trim()) return;
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const res = await checkSupplyChain([{ ecosystem, name: name.trim(), version: version.trim() || undefined }]);
      setResult(res.data[0] ?? null);
    } catch {
      setErr("Vérification impossible (nom invalide ou modèle indisponible).");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-2xl border border-outline-variant/[0.18] bg-surface-container px-5 py-4 space-y-3">
      <div>
        <h3 className="font-headline text-base font-semibold text-on-surface">Tester un paquet</h3>
        <p className="text-xs text-on-surface-variant">
          Vérifiez un paquet <strong>avant</strong> de l'ajouter à un projet. Rien n'est installé ni enregistré.
        </p>
      </div>
      <div className="flex flex-wrap items-end gap-2">
        <select
          aria-label="Écosystème"
          value={ecosystem}
          onChange={(e) => setEcosystem(e.target.value)}
          className="rounded-lg bg-surface-container-high px-3 py-2 text-sm text-on-surface"
        >
          <option value="npm">npm</option>
          <option value="pypi">PyPI</option>
        </select>
        <input
          aria-label="Nom du paquet"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void run()}
          placeholder="nom du paquet (ex. lodash)"
          className="flex-1 min-w-[200px] rounded-lg bg-surface-container-high px-3 py-2 text-sm text-on-surface font-mono"
        />
        <input
          aria-label="Version"
          value={version}
          onChange={(e) => setVersion(e.target.value)}
          placeholder="version (facultatif)"
          className="w-40 rounded-lg bg-surface-container-high px-3 py-2 text-sm text-on-surface font-mono"
        />
        <button
          onClick={() => void run()}
          disabled={busy || !name.trim()}
          className="px-4 py-2 rounded-xl text-sm font-medium bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25 disabled:opacity-50"
        >
          {busy ? "Analyse…" : "Vérifier"}
        </button>
      </div>
      {err && <p className="text-xs text-error">{err}</p>}
      {result && <CheckResult r={result} />}
    </div>
  );
};

const CheckResult: React.FC<{ r: SupplyChainCheckResult }> = ({ r }) => {
  if (r.status !== "SCORED") {
    return (
      <p className="text-sm text-on-surface-variant">
        <span className="font-mono">{r.name}</span> n'a pas pu être analysé : {SKIP_LABEL[r.status] ?? r.status}.
      </p>
    );
  }
  const flagged = r.tier === "KNOWN_MALICIOUS" || r.tier === "HIGH_CONFIDENCE" || r.tier === "REVIEW";
  return (
    <div className="rounded-xl bg-surface-container-high/70 px-4 py-3 space-y-2" data-testid="check-result">
      <div className="flex flex-wrap items-center gap-3">
        <span className={`text-[11px] font-bold px-3 py-1 rounded-full border ${tierBadge(r.tier)}`}>
          {TIER_LABEL[r.tier ?? ""] ?? "Sans alerte"}
        </span>
        <span className="font-mono text-sm text-on-surface">
          {r.name}
          {(r.scoredVersion || r.version) && <span className="text-outline">@{r.scoredVersion || r.version}</span>}
        </span>
        {r.tier !== "KNOWN_MALICIOUS" && (
          <span className="text-xs text-on-surface-variant">Suspicion {formatProba(r.suspicionProba)}</span>
        )}
        {r.probableType && (
          <span className="text-xs text-on-surface-variant">Type probable : {TYPE_LABEL[r.probableType] ?? r.probableType}</span>
        )}
        {r.knownMaliciousId && <span className="text-xs text-outline">{r.knownMaliciousId}</span>}
      </div>
      {flagged ? (
        <ul className="list-disc pl-5 text-sm text-on-surface-variant space-y-0.5">
          {r.reasons.map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-on-surface-variant">
          Aucun signal inquiétant : ce paquet ne ressemble pas à un paquet malveillant connu.
        </p>
      )}
    </div>
  );
};

const Stat: React.FC<{ label: string; value: number; danger?: boolean; warn?: boolean }> = ({
  label,
  value,
  danger,
  warn,
}) => (
  <div className="rounded-xl bg-surface-container-high/80 px-4 py-3">
    <p className="text-[10px] uppercase tracking-widest text-outline">{label}</p>
    <p className={`mt-1 text-2xl font-semibold ${danger ? "text-error" : warn ? "text-amber-300" : "text-on-surface"}`}>
      {value}
    </p>
  </div>
);

const FlaggedRow: React.FC<{ item: SupplyChainItem }> = ({ item }) => (
  <div className="rounded-2xl border border-outline-variant/[0.18] bg-surface-container px-5 py-4">
    <div className="flex flex-wrap items-center gap-3">
      <span className={`text-[11px] font-bold px-3 py-1 rounded-full border ${tierBadge(item.tier)}`}>
        {TIER_LABEL[item.tier] ?? item.tier}
      </span>
      {item.ecosystem && (
        <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded bg-surface-container-high text-outline">
          {item.ecosystem}
        </span>
      )}
      <span className="font-mono text-sm text-on-surface">
        {item.name}
        <span className="text-outline">@{item.version}</span>
      </span>
      {item.tier !== "KNOWN_MALICIOUS" && (
        <span className="text-xs text-on-surface-variant">Suspicion {formatProba(item.suspicionProba)}</span>
      )}
      {item.probableType && (
        <span className="text-xs text-on-surface-variant">
          Type probable : {TYPE_LABEL[item.probableType] ?? item.probableType}
        </span>
      )}
      {item.knownMaliciousId && <span className="text-xs text-outline">{item.knownMaliciousId}</span>}
    </div>
    {item.reasons.length > 0 && (
      <ul className="mt-2 list-disc pl-5 text-sm text-on-surface-variant space-y-0.5">
        {item.reasons.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
    )}
  </div>
);

export default SupplyChainPanel;
