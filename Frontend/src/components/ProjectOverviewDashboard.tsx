import React from "react";
import { daysLeft } from "./DeadlineBadge";
import { formatReleaseDeadline, type ProjectServerDto, type ReleaseReadinessDto, type RepositoryDto, type ScanResultDto, type SslResultDto } from "../services/api";

export type SolutionRole = "FRONT" | "BACK" | "DATABASE" | "OTHER";

export const SOLUTION_ROLES: { role: SolutionRole; label: string }[] = [
  { role: "FRONT", label: "Front" },
  { role: "BACK", label: "Back" },
  { role: "DATABASE", label: "Base de données" },
  { role: "OTHER", label: "Autre" },
];

type Props = {
  repos: RepositoryDto[];
  servers: ProjectServerDto[];
  scans: ScanResultDto[];
  readiness: ReleaseReadinessDto | null;
  deadline?: string | null;
  domainName?: string | null;
  sslGrade?: string | null;
  sslScannedAt?: string | null;
  /** yyyy-MM-dd from the latest certificate, when the scan recorded one. */
  certExpiresOn?: string | null;
  certExpired?: boolean;
  certDaysLeft?: number | null;
  /** yyyy-MM-dd chosen for the inbox alert. */
  sslAlertDate?: string | null;
  sslAlertError?: string | null;
  onSslAlertDate: (alertDate: string | null) => void;
  /** Absent entries are shown as Autre. */
  roles?: Partial<Record<number, SolutionRole>>;
  roleError?: string | null;
  onRoleChange: (repoId: number, role: SolutionRole) => void;
  onOpenServers: () => void;
  onOpenBlockers: () => void;
  onOpenRepos: () => void;
  onOpenSsl: () => void;
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

function repoShortName(url: string): string {
  if (!url) return "";
  return url.replace(/\.git$/, "").split("/").pop() ?? url;
}

export function solutionRoleOf(
  roles: Partial<Record<number, SolutionRole>> | undefined,
  repoId: number,
): SolutionRole {
  return roles?.[repoId] ?? "OTHER";
}

export function roleLabel(role: SolutionRole): string {
  return SOLUTION_ROLES.find((item) => item.role === role)?.label ?? "Autre";
}

export function reposByRole(
  repos: RepositoryDto[],
  roles?: Partial<Record<number, SolutionRole>>,
): Record<SolutionRole, RepositoryDto[]> {
  const groups: Record<SolutionRole, RepositoryDto[]> = {
    FRONT: [],
    BACK: [],
    DATABASE: [],
    OTHER: [],
  };
  for (const repo of repos) groups[solutionRoleOf(roles, repo.id)].push(repo);
  return groups;
}

function formatScanDate(iso?: string | null): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric" });
}

/** Calendar day yyyy-MM-dd taken from an ISO instant or a plain date. */
export function certExpiryYmd(raw?: string | null): string | null {
  if (!raw || raw.trim() === "" || raw.trim() === "—") return null;
  const match = /^(\d{4}-\d{2}-\d{2})/.exec(raw.trim());
  return match ? match[1] : null;
}

export function readCertExpiry(result: Pick<SslResultDto, "certExpired" | "certDaysLeft" | "certNotAfterStr" | "certificateDetail">): {
  expiresOn: string | null;
  expired: boolean;
  daysLeft: number | null;
} {
  const detail = result.certificateDetail;
  const expiresOn = certExpiryYmd(detail?.notAfter) ?? certExpiryYmd(result.certNotAfterStr);
  const rawDays = detail?.daysRemaining ?? result.certDaysLeft;
  const daysLeft = typeof rawDays === "number" && rawDays !== -1 ? rawDays : null;
  const expired = Boolean(detail?.expired ?? result.certExpired) || (daysLeft != null && daysLeft < 0);
  return { expiresOn, expired, daysLeft };
}

/** True once the chosen alert day has arrived. */
export function sslAlertDue(alertDate?: string | null, today = new Date()): boolean {
  const ymd = certExpiryYmd(alertDate);
  if (!ymd) return false;
  const [year, month, day] = ymd.split("-").map(Number);
  const alert = new Date(year, month - 1, day);
  const start = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  return alert.getTime() <= start.getTime();
}

export function alertDateAllowed(alertYmd: string, expiryYmd: string | null): boolean {
  if (!certExpiryYmd(alertYmd)) return false;
  if (!expiryYmd) return true;
  return alertYmd <= expiryYmd;
}

function expirySentence(expiresOn: string | null, expired: boolean, daysLeft: number | null): string {
  const label = formatReleaseDeadline(expiresOn);
  if (!label) return "Date d'expiration absente de ce scan.";
  if (expired) return `Certificat expiré le ${label}.`;
  if (daysLeft === 0) return `Expire le ${label}, aujourd'hui.`;
  if (daysLeft === 1) return `Expire le ${label}, dans 1 jour.`;
  if (daysLeft != null && daysLeft > 1) return `Expire le ${label}, dans ${daysLeft} jours.`;
  return `Expire le ${label}.`;
}

function environmentLabel(environment?: string | null): string {
  const value = (environment ?? "").toUpperCase();
  if (value.startsWith("PROD")) return "Production";
  if (value.startsWith("TEST")) return "Test";
  return environment?.trim() || "—";
}

function gradeTone(grade?: string | null): string {
  if (!grade) return "text-outline";
  if (grade.startsWith("A")) return "text-tertiary";
  if (grade === "B") return "text-primary";
  if (grade === "C") return "text-amber-300";
  return "text-error";
}

const actionClass =
  "flex items-center gap-2 rounded-xl border border-primary/30 bg-primary/10 px-4 py-2.5 text-sm font-semibold text-primary hover:bg-primary/20 transition-all";

const ProjectOverviewDashboard: React.FC<Props> = ({
  repos,
  servers,
  scans,
  readiness,
  deadline,
  domainName,
  sslGrade,
  sslScannedAt,
  certExpiresOn,
  certExpired,
  certDaysLeft,
  sslAlertDate,
  sslAlertError,
  roles,
  roleError,
  onRoleChange,
  onOpenServers,
  onOpenBlockers,
  onOpenRepos,
  onOpenSsl,
  onSslAlertDate,
}) => {
  const pulse = projectPulse(repos, servers, scans, readiness, deadline);
  const grouped = reposByRole(repos, roles);
  const criticalFlaws = servers.reduce((sum, server) => sum + (server.posture?.criticalCount ?? 0), 0);
  const unexpectedPorts = servers.reduce((sum, server) => sum + (server.posture?.unexpectedPortCount ?? 0), 0);
  const domain = domainName?.trim() || "";
  const sslDate = formatScanDate(sslScannedAt);
  const expiryYmd = certExpiryYmd(certExpiresOn);
  const alertYmd = certExpiryYmd(sslAlertDate);
  const alertDue = sslAlertDue(alertYmd);
  const [alertDraftError, setAlertDraftError] = React.useState<string | null>(null);
  const [dropRole, setDropRole] = React.useState<SolutionRole | null>(null);
  const skipClick = React.useRef(false);
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
      <div className="rounded-3xl border border-outline-variant/[0.15] bg-surface-container-high/60 p-4 space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-2">
          <p className="text-[10px] uppercase tracking-[0.28em] text-outline">Rappel du projet</p>
          <p className="text-xs text-outline">
            {repos.length} dépôt{repos.length === 1 ? "" : "s"} · {servers.length} serveur{servers.length === 1 ? "" : "s"} · {pulse.completedScans} scan{pulse.completedScans === 1 ? "" : "s"} terminé{pulse.completedScans === 1 ? "" : "s"}
          </p>
        </div>

        <div className="grid gap-3 lg:grid-cols-[minmax(14rem,0.8fr)_minmax(0,1.6fr)]">
          <button
            type="button"
            onClick={onOpenBlockers}
            className={`rounded-2xl border p-5 text-left transition-all hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${riskSurface(pulse.risk)}`}
          >
            <p className="text-[10px] uppercase tracking-[0.28em] opacity-80">Risque de retard</p>
            <p className="font-headline text-4xl font-bold mt-2">{riskLabel(pulse.risk)}</p>
            <p className="text-sm mt-2 opacity-90">{daysHint}</p>
          </button>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            <Kpi
              label="Bloqueurs"
              value={String(pulse.blockers)}
              hint={pulse.kev === 1 ? "dont 1 KEV" : `dont ${pulse.kev} KEV`}
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
            <Kpi
              label="Scans terminés"
              value={String(pulse.completedScans)}
              hint={pulse.missingScan === 0 ? "chaque dépôt a un scan" : `${pulse.missingScan} dépôt${pulse.missingScan > 1 ? "s" : ""} sans scan`}
              tone="text-on-surface"
              onClick={onOpenRepos}
            />
            <Kpi
              label="Failles serveur"
              value={String(criticalFlaws)}
              hint={
                unexpectedPorts === 0
                  ? "aucun port public inattendu"
                  : unexpectedPorts === 1
                    ? "1 port hors 22, 80, 443"
                    : `${unexpectedPorts} ports hors 22, 80, 443`
              }
              tone={criticalFlaws > 0 ? "text-error" : "text-on-surface"}
              onClick={onOpenServers}
            />
            <Kpi
              label="KEV"
              value={String(pulse.kev)}
              hint="bloquantes, priorité CISA"
              tone={pulse.kev > 0 ? "text-error" : "text-tertiary"}
              onClick={onOpenBlockers}
            />
          </div>
        </div>
      </div>

      <div className="grid gap-3 xl:grid-cols-2">
        <div className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4">
          <div className="flex items-baseline justify-between gap-3">
            <p className="text-[10px] uppercase tracking-widest text-outline">La solution</p>
            <p className="text-[10px] text-outline">Glissez un dépôt pour changer son rôle.</p>
          </div>
          <ul className="mt-2 divide-y divide-outline-variant/[0.12]">
            {SOLUTION_ROLES.map(({ role, label }) => {
              const items = grouped[role];
              const active = dropRole === role;
              return (
                <li
                  key={role}
                  onDragOver={(event) => {
                    event.preventDefault();
                    event.dataTransfer.dropEffect = "move";
                    setDropRole(role);
                  }}
                  onDrop={(event) => {
                    event.preventDefault();
                    const repoId = Number(event.dataTransfer.getData("text/plain"));
                    setDropRole(null);
                    if (!repoId || solutionRoleOf(roles, repoId) === role) return;
                    onRoleChange(repoId, role);
                  }}
                  className={`grid grid-cols-[8.5rem_minmax(0,1fr)] items-start gap-3 rounded-xl px-2 py-2.5 ${
                    active ? "bg-primary/10 ring-1 ring-primary/40" : ""
                  }`}
                >
                  <span className="pt-1 text-xs font-semibold text-on-surface">{label}</span>
                  <span className="flex min-h-8 flex-wrap items-center gap-1.5">
                    {items.length === 0 && (
                      <span className="text-xs text-outline">{active ? "Déposer ici" : "Aucun"}</span>
                    )}
                    {items.map((repo) => (
                      <button
                        key={repo.id}
                        type="button"
                        draggable
                        title="Glisser pour changer le rôle"
                        onDragStart={(event) => {
                          skipClick.current = true;
                          event.dataTransfer.setData("text/plain", String(repo.id));
                          event.dataTransfer.effectAllowed = "move";
                        }}
                        onDragEnd={() => {
                          setDropRole(null);
                          window.setTimeout(() => {
                            skipClick.current = false;
                          }, 0);
                        }}
                        onClick={() => {
                          if (skipClick.current) return;
                          onOpenRepos();
                        }}
                        className="cursor-grab rounded-full border border-outline-variant/30 bg-surface-container-high px-2.5 py-1 text-xs text-on-surface hover:border-primary/50 hover:text-primary active:cursor-grabbing transition-colors"
                      >
                        {repoShortName(repo.repoUrl) || `Dépôt #${repo.id}`}
                      </button>
                    ))}
                  </span>
                </li>
              );
            })}
          </ul>
          {roleError && <p className="mt-2 text-xs text-error">{roleError}</p>}
        </div>

        <div
          className={`rounded-2xl border bg-surface-container p-5 ${
            certExpired
              ? "border-error/40"
              : alertDue
                ? "border-amber-500/40"
                : "border-outline-variant/[0.15]"
          }`}
        >
          <button
            type="button"
            onClick={onOpenSsl}
            className="w-full text-left rounded-xl hover:bg-primary/5 transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
          >
            <p className="text-[10px] uppercase tracking-widest text-outline">Domaine et SSL</p>
            <p className="mt-3 font-headline text-lg font-semibold text-primary break-all">
              {domain || "Aucun domaine sur ce projet"}
            </p>
            {domain && sslScannedAt ? (
              <div className="mt-4 flex items-end justify-between gap-4">
                <div>
                  <p className="text-[10px] uppercase tracking-widest text-outline">Note</p>
                  <p className={`font-headline text-5xl font-bold leading-none mt-1 ${gradeTone(sslGrade)}`}>
                    {sslGrade || "…"}
                  </p>
                </div>
                <p className="text-sm text-on-surface-variant">Scan du {sslDate}</p>
              </div>
            ) : (
              <p className="mt-6 text-sm text-on-surface-variant">
                {domain ? "Aucun scan SSL pour ce domaine" : "Le domaine se renseigne sur la fiche du projet."}
              </p>
            )}
            {domain && sslScannedAt && (
              <p className={`mt-4 text-sm font-semibold ${certExpired ? "text-error" : alertDue ? "text-amber-300" : "text-on-surface"}`}>
                {expirySentence(expiryYmd, Boolean(certExpired), certDaysLeft ?? null)}
              </p>
            )}
          </button>

          {domain && sslScannedAt && expiryYmd && !certExpired && (
            <div className="mt-4 border-t border-outline-variant/[0.12] pt-4">
              <label className="block text-[10px] uppercase tracking-widest text-outline" htmlFor="ssl-alert-date">
                Recevoir l'alerte le
              </label>
              <input
                id="ssl-alert-date"
                type="date"
                max={expiryYmd}
                value={alertYmd ?? ""}
                onChange={(event) => {
                  const value = event.target.value;
                  if (!value) {
                    setAlertDraftError(null);
                    onSslAlertDate(null);
                    return;
                  }
                  if (!alertDateAllowed(value, expiryYmd)) {
                    setAlertDraftError("L'alerte doit être le jour de l'expiration ou avant.");
                    return;
                  }
                  setAlertDraftError(null);
                  onSslAlertDate(value);
                }}
                className="mt-2 w-full rounded-xl border border-outline-variant/30 bg-surface-container-high px-3 py-2 text-sm text-on-surface [color-scheme:dark]"
              />
              <p className="mt-2 text-[11px] text-outline">
                Au plus tard le {formatReleaseDeadline(expiryYmd)}. Ce jour-là, l'alerte arrive dans les notifications et sur cette carte.
              </p>
              {alertDue && alertYmd && (
                <p className="mt-2 text-sm font-semibold text-amber-300">
                  Alerte en cours depuis le {formatReleaseDeadline(alertYmd)}.
                </p>
              )}
              {(alertDraftError || sslAlertError) && (
                <p className="mt-2 text-xs text-error">{alertDraftError || sslAlertError}</p>
              )}
            </div>
          )}
          {domain && sslScannedAt && certExpired && (
            <p className="mt-4 text-sm text-error">Le certificat est expiré. Renouvelez-le, puis relancez un scan SSL.</p>
          )}
        </div>
      </div>

      <ServerReminder servers={servers} onOpenServers={onOpenServers} />

      {(pulse.withoutServer > 0 || pulse.blockers > 0 || pulse.missingScan > 0 || servers.length === 0) && (
        <div className="flex flex-wrap gap-2">
          {servers.length === 0 && (
            <button type="button" onClick={onOpenServers} className={actionClass}>
              <span className="material-symbols-outlined text-base">add</span>
              Ajouter un serveur
            </button>
          )}
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

      <div className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4 space-y-2">
        <p className="text-[10px] uppercase tracking-widest text-outline">Serveurs et dépôts déployés</p>
        {servers.length === 0 ? (
          <p className="py-3 text-sm text-outline">Aucun serveur sur ce projet.</p>
        ) : (
          <ul className="divide-y divide-outline-variant/[0.12]">
            {servers.map((server) => {
              const names = (server.deployments ?? [])
                .filter((deployment) => deployment.linkedRepositoryId != null)
                .map((deployment) => {
                  const raw = deploymentLabel(deployment.repositoryName, deployment.linkedRepositoryId);
                  const name = raw.includes("/") ? repoShortName(raw) || raw : raw;
                  const role = roleLabel(solutionRoleOf(roles, deployment.linkedRepositoryId as number));
                  return `${name} (${role})`;
                });
              return (
                <li key={server.id}>
                  <button
                    type="button"
                    onClick={onOpenServers}
                    className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 py-2.5 text-left text-sm hover:text-primary transition-colors"
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
                      {environmentLabel(server.environment)}
                    </span>
                    <span className="text-xs text-on-surface-variant">
                      {names.length > 0 ? names.join(", ") : "Aucun dépôt déployé"}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
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
