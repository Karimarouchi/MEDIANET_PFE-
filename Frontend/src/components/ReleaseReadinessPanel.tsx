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

function remainingLabel(days?: number | null): string {
  if (days == null) return "Date de livraison non renseignée";
  if (days < 0) return `Échéance dépassée de ${Math.abs(days)} j`;
  if (days === 0) return "Livraison aujourd'hui";
  return `${days} j restants`;
}

/** Why the verdict is what it is, in one sentence a client can read. */
export function riskExplanation(r: ReleaseReadinessDto): string {
  if (r.delayRisk == null) return "Renseignez une date de livraison pour obtenir un verdict.";
  const blockers = r.blockingCount;
  const kev = r.kevBlockingCount ?? 0;
  if (r.daysRemaining != null && r.daysRemaining < 0) return "La date de livraison est dépassée.";
  if (blockers === 0) return "Aucun bloqueur ouvert : rien n'empêche la livraison côté vulnérabilités.";
  const days = r.daysRemaining ?? 0;
  if (r.delayRisk === "ELEVE") {
    return kev > 0 && days > 7
      ? `${blockers} bloqueur(s) ouvert(s), dont ${kev} exploité(s) activement, et il reste ${days} j : marge insuffisante.`
      : `${blockers} bloqueur(s) ouvert(s) et il ne reste que ${days} j.`;
  }
  return `${blockers} bloqueur(s) ouvert(s) : à traiter avant la livraison, il reste ${days} j.`;
}

const ReleaseReadinessPanel: React.FC<Props> = ({ readiness, loading }) => {
  if (loading && !readiness) {
    return (
      <section className="rounded-2xl border border-outline-variant/[0.18] bg-surface-container px-5 py-4 text-sm text-outline">
        Calcul de l'état de la livraison…
      </section>
    );
  }
  if (!readiness) return null;

  const risk = readiness.delayRisk;

  return (
    <section className={`rounded-2xl border px-5 py-5 space-y-4 ${riskPanel(risk)}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.28em] text-outline">État de la livraison</p>
          <h2 className="font-headline text-xl font-semibold text-on-surface mt-1">Date de livraison et bloqueurs</h2>
          <p className="text-xs text-on-surface-variant mt-1 max-w-2xl">{riskExplanation(readiness)}</p>
        </div>
        <span className={`text-[11px] font-bold px-3 py-1 rounded-full border ${riskBadge(risk)}`}>
          {risk ? `Risque de retard ${risk}` : "Pas de verdict sans date"}
        </span>
      </div>

      <div className="grid gap-3 sm:grid-cols-3 text-sm">
        <div className="rounded-xl bg-surface-container-high/80 px-4 py-3">
          <p className="text-[10px] uppercase tracking-widest text-outline">Livraison</p>
          <p className="mt-1 text-on-surface font-medium">
            {readiness.releaseLabel ? `${readiness.releaseLabel} · ` : ""}
            {formatReleaseDeadline(readiness.releaseDeadline) || "Non renseignée"}
          </p>
          <p className="text-xs text-outline mt-1">{remainingLabel(readiness.daysRemaining)}</p>
        </div>
        <div className="rounded-xl bg-surface-container-high/80 px-4 py-3">
          <p className="text-[10px] uppercase tracking-widest text-outline">Bloqueurs ouverts</p>
          <p className="mt-1 text-on-surface font-medium">
            {readiness.blockingCount} / {readiness.openFindingCount} CVE
          </p>
          <p className="text-xs text-outline mt-1">
            {(readiness.kevBlockingCount ?? 0) > 0 ? `${readiness.kevBlockingCount} exploitée(s) activement · ` : ""}
            critiques, élevées ou exploitées
          </p>
        </div>
        <div className="rounded-xl bg-surface-container-high/80 px-4 py-3">
          <p className="text-[10px] uppercase tracking-widest text-outline">Périmètre</p>
          <p className="mt-1 text-on-surface font-medium">{readiness.scannedRepoCount} dépôt(s)</p>
          <p className="text-xs text-outline mt-1">au dernier scan terminé</p>
        </div>
      </div>

      {readiness.priorities.length === 0 ? (
        <p className="text-sm text-on-surface-variant">
          Aucun bloqueur (CVE exploitée, critique ou élevée) sur le dernier scan terminé de chaque dépôt.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-outline-variant/20">
          <table className="w-full text-left text-sm">
            <thead className="text-[10px] uppercase tracking-widest text-outline bg-surface-container-high/70">
              <tr>
                <th className="px-3 py-2 font-medium">À traiter en premier</th>
                <th className="px-3 py-2 font-medium">Gravité</th>
                <th className="px-3 py-2 font-medium">Dépôts</th>
              </tr>
            </thead>
            <tbody>
              {readiness.priorities.slice(0, 25).map((row) => (
                <tr key={`${row.cveId}|${row.packageName ?? ""}`} className="border-t border-outline-variant/15">
                  <td className="px-3 py-2">
                    <p className="font-medium text-on-surface">{row.cveId}</p>
                    <p className="text-xs text-outline">{row.packageName || "paquet inconnu"}</p>
                  </td>
                  <td className="px-3 py-2">
                    <span className="text-on-surface">{row.severity || "—"}</span>
                    {row.kevListed && (
                      <span className="ml-2 text-[10px] font-bold px-1.5 py-0.5 rounded bg-error/15 text-error">KEV</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-on-surface-variant">
                    {row.repoCount ?? 0}
                    {row.repositories?.length ? (
                      <span className="block text-[11px] text-outline">{row.repositories.join(", ")}</span>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {readiness.priorities.length > 25 && (
            <p className="px-3 py-2 text-[11px] text-outline border-t border-outline-variant/15">
              + {readiness.priorities.length - 25} autres bloqueurs : voir la liste des vulnérabilités.
            </p>
          )}
        </div>
      )}

      {readiness.disclaimer && <p className="text-[11px] text-outline leading-relaxed">{readiness.disclaimer}</p>}
    </section>
  );
};

export default ReleaseReadinessPanel;
