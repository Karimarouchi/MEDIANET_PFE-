import React from "react";
import { formatReleaseDeadline, type ReleaseReadinessDto } from "../services/api";

type Props = {
  readiness: ReleaseReadinessDto | null;
  loading?: boolean;
};

function riskBadge(risk?: string | null) {
  switch ((risk || "").toUpperCase()) {
    case "ELEVE":
      return "bg-error/15 text-error border-error/30";
    case "MOYEN":
      return "bg-amber-500/15 text-amber-300 border-amber-500/30";
    case "FAIBLE":
      return "bg-tertiary/15 text-tertiary border-tertiary/30";
    default:
      return "bg-surface-container-highest text-outline border-outline-variant/30";
  }
}

function riskPanel(risk?: string | null) {
  switch ((risk || "").toUpperCase()) {
    case "ELEVE":
      return "border-error/30 bg-error/10";
    case "MOYEN":
      return "border-amber-500/30 bg-amber-500/10";
    case "FAIBLE":
      return "border-tertiary/30 bg-tertiary/10";
    default:
      return "border-outline-variant/[0.18] bg-surface-container";
  }
}

function formatDays(value?: number | null): string {
  if (value == null || Number.isNaN(value)) return "—";
  const rounded = Math.round(value * 10) / 10;
  return `${rounded} j`;
}

function remainingLabel(days?: number | null): string {
  if (days == null) return "Date client non renseignée";
  if (days < 0) return `Échéance dépassée de ${Math.abs(days)} j`;
  if (days === 0) return "Livraison aujourd'hui";
  return `${days} j restants`;
}

const ReleaseReadinessPanel: React.FC<Props> = ({ readiness, loading }) => {
  if (loading && !readiness) {
    return (
      <section className="rounded-2xl border border-outline-variant/[0.18] bg-surface-container px-5 py-4 text-sm text-outline">
        Calcul du chemin critique de release…
      </section>
    );
  }
  if (!readiness) return null;

  const risk = readiness.delayRisk;
  const interval =
    readiness.estimatedDaysLow != null && readiness.estimatedDaysHigh != null
      ? `${formatDays(readiness.estimatedDaysLow)} – ${formatDays(readiness.estimatedDaysHigh)}`
      : null;

  return (
    <section className={`rounded-2xl border px-5 py-5 space-y-4 ${riskPanel(risk)}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.28em] text-outline">Release Readiness</p>
          <h2 className="font-headline text-xl font-semibold text-on-surface mt-1">
            Date client vs chemin critique
          </h2>
          <p className="text-xs text-on-surface-variant mt-1 max-w-2xl">
            {readiness.criticalPathNote}
          </p>
        </div>
        <span className={`text-[11px] font-bold px-3 py-1 rounded-full border ${riskBadge(risk)}`}>
          {risk ? `Retard ${risk}${readiness.delayRiskBasis === "RULES" ? " (indicatif)" : ""}` : "Pas de verdict sans date"}
        </span>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-sm">
        <div className="rounded-xl bg-surface-container-high/80 px-4 py-3">
          <p className="text-[10px] uppercase tracking-widest text-outline">Livraison client</p>
          <p className="mt-1 text-on-surface font-medium">
            {readiness.releaseLabel ? `${readiness.releaseLabel} · ` : ""}
            {formatReleaseDeadline(readiness.releaseDeadline) || "Non renseignée"}
          </p>
          <p className="text-xs text-outline mt-1">{remainingLabel(readiness.daysRemaining)}</p>
        </div>
        <div className="rounded-xl bg-surface-container-high/80 px-4 py-3">
          <p className="text-[10px] uppercase tracking-widest text-outline">Chemin critique</p>
          <p className="mt-1 text-on-surface font-medium">
            {readiness.estimateReliable === false
              ? "Non estimable"
              : `max ${formatDays(readiness.estimatedRemediationDays)}`}
          </p>
          <p className="text-xs text-outline mt-1">
            {readiness.estimateReliable === false
              ? "Pas assez de corrections réelles pour estimer"
              : interval
              ? `Intervalle ${readiness.marginSource === "MAE" ? "MAE" : "± 2 j (marge fixe)"} ${interval}`
              : "Sans somme des tickets"}
            {readiness.estimateIncomplete
              ? ` · ${readiness.unscoredBlockingCount ?? 0} bloqueur(s) sans estimation`
              : ""}
          </p>
        </div>
        <div className="rounded-xl bg-surface-container-high/80 px-4 py-3">
          <p className="text-[10px] uppercase tracking-widest text-outline">Bloqueurs CI</p>
          <p className="mt-1 text-on-surface font-medium">
            {readiness.blockingCount} / {readiness.openFindingCount} findings
          </p>
          <p className="text-xs text-outline mt-1">
            {readiness.scannedRepoCount} dépôt(s) au dernier scan
          </p>
        </div>
        <div className="rounded-xl bg-surface-container-high/80 px-4 py-3">
          <p className="text-[10px] uppercase tracking-widest text-outline">Modèle</p>
          <p className="mt-1 text-on-surface font-medium">
            {readiness.modelAvailable === false ? "Indisponible" : "Experiment A + régression"}
          </p>
          <p className="text-xs text-outline mt-1">Risque de retard, pas un go / no-go</p>
        </div>
      </div>

      {readiness.estimateReliable === false && readiness.reliabilityNote && (
        <p className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-200">
          {readiness.reliabilityNote}
        </p>
      )}

      {readiness.priorities.length === 0 ? (
        <p className="text-sm text-on-surface-variant">
          Aucun bloqueur CI (KEV ou CRITICAL/HIGH) sur le dernier scan terminé de chaque dépôt.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-outline-variant/20">
          <table className="w-full text-left text-sm">
            <thead className="text-[10px] uppercase tracking-widest text-outline bg-surface-container-high/70">
              <tr>
                <th className="px-3 py-2 font-medium">Priorité</th>
                <th className="px-3 py-2 font-medium">Sévérité</th>
                <th className="px-3 py-2 font-medium">Repos</th>
                <th className="px-3 py-2 font-medium">Remédiation</th>
                <th className="px-3 py-2 font-medium">
                  {readiness.estimateReliable === false ? "Ancienneté" : "Jours restants estimés"}
                </th>
              </tr>
            </thead>
            <tbody>
              {readiness.priorities.map((row) => (
                <tr key={`${row.cveId}|${row.packageName ?? ""}`} className="border-t border-outline-variant/15">
                  <td className="px-3 py-2">
                    <p className="font-medium text-on-surface">{row.cveId}</p>
                    <p className="text-xs text-outline">{row.packageName || "paquet inconnu"}</p>
                  </td>
                  <td className="px-3 py-2">
                    <span className="text-on-surface">{row.severity || "—"}</span>
                    {row.kevListed && (
                      <span className="ml-2 text-[10px] font-bold px-1.5 py-0.5 rounded bg-error/15 text-error">
                        KEV
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-on-surface-variant">
                    {row.repoCount ?? 0}
                    {row.repositories?.length ? (
                      <span className="block text-[11px] text-outline">{row.repositories.join(", ")}</span>
                    ) : null}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${riskBadge(row.remediationBand)}`}>
                      {row.remediationBand || "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-on-surface">
                    {readiness.estimateReliable === false
                      ? `ouvert depuis ${row.ageDays ?? 0} j`
                      : formatDays(row.remainingDays ?? row.estimatedDays)}
                    {readiness.estimateReliable !== false && row.ageDays != null && row.ageDays > 0 && row.estimatedDays != null && (
                      <span className="block text-[11px] text-outline">
                        total {formatDays(row.estimatedDays)} − ouvert depuis {row.ageDays} j
                      </span>
                    )}
                    {readiness.estimateReliable !== false && row.estimatedDaysLow != null && row.estimatedDaysHigh != null && (
                      <span className="block text-[11px] text-outline">
                        {formatDays(row.estimatedDaysLow)} – {formatDays(row.estimatedDaysHigh)}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {readiness.disclaimer && (
        <p className="text-[11px] text-outline leading-relaxed">{readiness.disclaimer}</p>
      )}
    </section>
  );
};

export default ReleaseReadinessPanel;
