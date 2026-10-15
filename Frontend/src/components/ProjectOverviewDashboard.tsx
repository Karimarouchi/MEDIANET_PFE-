import React from "react";
import { daysLeft } from "./DeadlineBadge";
import { formatReleaseDeadline, type ProjectServerDto, type ReleaseReadinessDto, type RepositoryDto, type ScanResultDto } from "../services/api";

type Props = {
  repos: RepositoryDto[];
  servers: ProjectServerDto[];
  scans: ScanResultDto[];
  readiness: ReleaseReadinessDto | null;
  deadline?: string | null;
  onOpenServers: () => void;
  onOpenBlockers: () => void;
  onOpenRepos: () => void;
};

export type ProjectPulse = {
  onProd: number;
  withoutServer: number;
  completedScans: number;
  blockers: number;
  kev: number;
  daysRemaining: number | null;
  risk?: string | null;
  missingScan: number;
  deployedIds: Set<number>;
};

function isProd(environment?: string | null): boolean {
  return (environment ?? "").toUpperCase().startsWith("PROD");
}

function deployedIds(servers: ProjectServerDto[], prodOnly: boolean): Set<number> {
  const ids = new Set<number>();
  for (const server of servers) {
    if (prodOnly && !isProd(server.environment)) continue;
    for (const deployment of server.deployments ?? []) {
      if (deployment.linkedRepositoryId != null) ids.add(deployment.linkedRepositoryId);
    }
  }
  return ids;
}

export function projectPulse(
  repos: RepositoryDto[],
  servers: ProjectServerDto[],
  scans: ScanResultDto[],
  readiness: ReleaseReadinessDto | null,
  deadline?: string | null,
): ProjectPulse {
  const onAny = deployedIds(servers, false);
  const completed = scans.filter((scan) => scan.status === "COMPLETED");
  const scannedRepoIds = new Set(completed.map((scan) => scan.repoId));
  return {
    onProd: deployedIds(servers, true).size,
    withoutServer: repos.filter((repo) => !onAny.has(repo.id)).length,
    completedScans: completed.length,
    blockers: readiness?.blockingCount ?? 0,
    kev: readiness?.kevBlockingCount ?? 0,
    daysRemaining: readiness?.daysRemaining ?? daysLeft(deadline),
    risk: readiness?.delayRisk,
    missingScan: repos.filter((repo) => !scannedRepoIds.has(repo.id)).length,
    deployedIds: onAny,
  };
}

function riskLabel(risk?: string | null): string {
  switch ((risk || "").toUpperCase()) {
    case "ELEVE":
      return "Élevé";
    case "MOYEN":
      return "Moyen";
    case "FAIBLE":
      return "Faible";
    default:
      return "Sans date";
  }
}

function riskSurface(risk?: string | null): string {
  switch ((risk || "").toUpperCase()) {
    case "ELEVE":
      return "border-error/40 bg-error/10 text-error";
    case "MOYEN":
      return "border-amber-500/40 bg-amber-500/10 text-amber-300";
    case "FAIBLE":
      return "border-tertiary/30 bg-tertiary/10 text-tertiary";
    default:
      return "border-outline-variant/[0.18] bg-surface-container text-outline";
  }
}

function jours(n: number): string {
  const abs = Math.abs(n);
  return `${abs} jour${abs > 1 ? "s" : ""}`;
}

export function decisionLine(
  deadline: string | null | undefined,
  pulse: Pick<ProjectPulse, "daysRemaining" | "blockers" | "withoutServer">,
): string {
  const date = formatReleaseDeadline(deadline);
  const days = pulse.daysRemaining;
  let when: string;
  if (!date) {
    when = "Aucune date de livraison.";
  } else if (days == null) {
    when = `Livraison le ${date}.`;
  } else if (days < 0) {
    when = `Livraison le ${date}, échéance dépassée de ${jours(days)}.`;
  } else if (days === 0) {
    when = `Livraison le ${date}, aujourd'hui.`;
  } else {
    when = `Livraison le ${date}, dans ${jours(days)}.`;
  }
  const blockers =
    pulse.blockers === 0
      ? "Aucun bloqueur ouvert"
      : pulse.blockers === 1
        ? "1 bloqueur ouvert"
        : `${pulse.blockers} bloqueurs ouverts`;
  const tail =
    pulse.withoutServer === 0
      ? "."
      : pulse.withoutServer === 1
        ? ", 1 dépôt sans serveur."
        : `, ${pulse.withoutServer} dépôts sans serveur.`;
  return `${when} ${blockers}${tail}`;
}

function deploymentLabel(name?: string | null, repoId?: number | null): string {
  if (name && name.trim()) return name;
  return repoId != null ? `Dépôt #${repoId}` : "Dépôt";
}

const actionClass =
  "flex items-center gap-2 rounded-xl border border-primary/30 bg-primary/10 px-4 py-2.5 text-sm font-semibold text-primary hover:bg-primary/20 transition-all";

const ProjectOverviewDashboard: React.FC<Props> = ({
  repos,
  servers,
  scans,
  readiness,
  deadline,
  onOpenServers,
  onOpenBlockers,
  onOpenRepos,
}) => {
  const pulse = projectPulse(repos, servers, scans, readiness, deadline);
  const daysHint =
    pulse.daysRemaining == null
      ? "date non renseignée"
      : pulse.daysRemaining < 0
        ? `dépassée de ${jours(pulse.daysRemaining)}`
        : pulse.daysRemaining === 0
          ? "aujourd'hui"
          : `${jours(pulse.daysRemaining)} restants`;

  return (
    <section className="space-y-4">
      <div className="grid gap-3 lg:grid-cols-[minmax(16rem,0.9fr)_minmax(0,1.4fr)]">
        <button
          type="button"
          onClick={onOpenBlockers}
          className={`rounded-2xl border p-5 text-left transition-all hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${riskSurface(pulse.risk)}`}
        >
          <p className="text-[10px] uppercase tracking-[0.28em] opacity-80">Risque de retard</p>
          <p className="font-headline text-4xl font-bold mt-2">{riskLabel(pulse.risk)}</p>
          <p className="text-sm mt-2 opacity-90">{daysHint}</p>
        </button>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Kpi
            label="Bloqueurs"
            value={String(pulse.blockers)}
            hint={`${pulse.kev} KEV`}
            tone={pulse.blockers > 0 ? "text-error" : "text-tertiary"}
            onClick={onOpenBlockers}
          />
          <Kpi
            label="Sans serveur"
            value={String(pulse.withoutServer)}
            hint="dépôts non déployés"
            tone={pulse.withoutServer > 0 ? "text-amber-300" : "text-on-surface"}
            onClick={onOpenServers}
          />
          <Kpi
            label="En production"
            value={String(pulse.onProd)}
            hint="dépôts sur un serveur PROD"
            tone="text-on-surface"
            onClick={onOpenServers}
          />
        </div>
      </div>

      <p className="text-xs text-outline">
        {repos.length} dépôt{repos.length === 1 ? "" : "s"} · {servers.length} serveur{servers.length === 1 ? "" : "s"} · {pulse.completedScans} scan{pulse.completedScans === 1 ? "" : "s"} terminé{pulse.completedScans === 1 ? "" : "s"}
      </p>

      <ServerReminder servers={servers} onOpenServers={onOpenServers} />

      {(pulse.withoutServer > 0 || pulse.blockers > 0 || pulse.missingScan > 0) && (
        <div className="flex flex-wrap gap-2">
          {pulse.withoutServer > 0 && (
            <button type="button" onClick={onOpenServers} className={actionClass}>
              <span className="material-symbols-outlined text-base">dns</span>
              Lier les dépôts sans serveur
            </button>
          )}
          {pulse.blockers > 0 && (
            <button type="button" onClick={onOpenBlockers} className={actionClass}>
              <span className="material-symbols-outlined text-base">priority_high</span>
              Voir les bloqueurs
            </button>
          )}
          {pulse.missingScan > 0 && (
            <button type="button" onClick={onOpenRepos} className={actionClass}>
              <span className="material-symbols-outlined text-base">radar</span>
              Lancer un scan
            </button>
          )}
        </div>
      )}

      {servers.length === 0 ? (
        <button type="button" onClick={onOpenServers} className={actionClass}>
          <span className="material-symbols-outlined text-base">add</span>
          Ajouter un serveur
        </button>
      ) : (
        <div className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4 space-y-2">
          <p className="text-[10px] uppercase tracking-widest text-outline">Serveurs et dépôts déployés</p>
          <ul className="divide-y divide-outline-variant/[0.12]">
            {servers.map((server) => {
              const names = (server.deployments ?? [])
                .filter((deployment) => deployment.linkedRepositoryId != null)
                .map((deployment) => deploymentLabel(deployment.repositoryName, deployment.linkedRepositoryId));
              return (
                <li key={server.id}>
                  <button
                    type="button"
                    onClick={onOpenServers}
                    className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 py-2 text-left text-sm hover:text-primary transition-colors"
                  >
                    <span className="font-headline font-semibold text-on-surface">{server.name}</span>
                    <span className="font-mono text-[11px] text-outline">{server.host}</span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                        isProd(server.environment)
                          ? "bg-error-container text-on-error-container"
                          : "bg-surface-variant text-on-surface-variant"
                      }`}
                    >
                      {server.environment || "—"}
                    </span>
                    <span className="text-xs text-on-surface-variant">
                      {names.length > 0 ? names.join(", ") : "Aucun dépôt déployé"}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </section>
  );
};

function ServerReminder({ servers, onOpenServers }: { servers: ProjectServerDto[]; onOpenServers: () => void }) {
  const critical = servers.reduce((sum, server) => sum + (server.posture?.criticalCount ?? 0), 0);
  const unexpected = servers.reduce((sum, server) => sum + (server.posture?.unexpectedPortCount ?? 0), 0);
  if (critical === 0 && unexpected === 0) return null;
  const parts: string[] = [];
  if (critical > 0) parts.push(critical === 1 ? "1 faille critique" : `${critical} failles critiques`);
  if (unexpected > 0) {
    parts.push(unexpected === 1 ? "1 port ouvert hors usage attendu" : `${unexpected} ports ouverts hors usage attendu`);
  }
  return (
    <button
      type="button"
      onClick={onOpenServers}
      className="flex w-full items-center justify-between gap-3 rounded-2xl border border-error/30 bg-error/10 px-4 py-3 text-left hover:bg-error/15"
    >
      <span>
        <span className="block text-[10px] uppercase tracking-widest text-error">Rappel serveur</span>
        <span className="mt-1 block text-sm text-on-surface">{parts.join(" · ")} sur les serveurs de ce projet.</span>
      </span>
      <span className="shrink-0 text-xs font-semibold text-error">Voir les serveurs</span>
    </button>
  );
}

const Kpi: React.FC<{
  label: string;
  value: string;
  hint: string;
  tone: string;
  onClick: () => void;
}> = ({ label, value, hint, tone, onClick }) => (
  <button
    type="button"
    onClick={onClick}
    className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4 text-left hover:border-primary/40 hover:bg-primary/5 transition-all focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
  >
    <p className="text-[10px] uppercase tracking-widest text-outline">{label}</p>
    <p className={`text-3xl font-bold font-headline mt-1 ${tone}`}>{value}</p>
    <p className="text-[10px] text-on-surface-variant mt-1">{hint}</p>
  </button>
);

export default ProjectOverviewDashboard;
