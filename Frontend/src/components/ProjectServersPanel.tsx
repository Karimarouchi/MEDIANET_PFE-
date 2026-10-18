import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ServerVulnPanel from "./ServerVulnPanel";
import { roleLabel, solutionRoleOf, type SolutionRole } from "./ProjectOverviewDashboard";
import {
  createLightweightClientServer,
  getServerNode,
  getServerNodes,
  linkClientServer,
  unlinkClientServer,
  type PortExposureDto,
  type ProjectDeploymentDto,
  type ProjectServerDto,
  type ProjectServerPosture,
  type RepositoryDto,
  type ServerNodeDto,
} from "../services/api";

const errMsg = (err: any, fallback: string): string => {
  const d = err?.response?.data;
  return (typeof d === "string" && d) || d?.message || fallback;
};

/** Servers (VPS) of a project: a project can run on several; each one feeds the project's attack map. */
const ProjectServersPanel: React.FC<{
  clientId: number;
  servers: ProjectServerDto[];
  repos: RepositoryDto[];
  roles?: Partial<Record<number, SolutionRole>>;
  canLinkExisting: boolean;
  onChange: () => void;
}> = ({ clientId, servers, repos, roles, canLinkExisting, onChange }) => {
  const [options, setOptions] = useState<ServerNodeDto[]>([]);
  const [pick, setPick] = useState("");
  const [draft, setDraft] = useState({ name: "", host: "", environment: "TEST" as "TEST" | "PROD" });
  const [role, setRole] = useState<"FRONT" | "BACK" | "OTHER">("FRONT");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [openVulnId, setOpenVulnId] = useState<number | null>(null);
  const [knownPorts, setKnownPorts] = useState<PortExposureDto[] | null>(null);

  useEffect(() => {
    if (!canLinkExisting) return;
    getServerNodes()
      .then((res) => setOptions(res.data))
      .catch(() => setOptions([]));
  }, [canLinkExisting, servers.length]);

  useEffect(() => {
    if (!pick) {
      setKnownPorts(null);
      return;
    }
    let active = true;
    getServerNode(Number(pick))
      .then((res) => {
        if (active) setKnownPorts(res.data.ports ?? []);
      })
      .catch(() => {
        if (active) setKnownPorts([]);
      });
    return () => {
      active = false;
    };
  }, [pick]);

  const linkedIds = new Set(servers.map((s) => s.id));
  const available = options.filter((o) => !linkedIds.has(o.id));
  const deployedRepoIds = new Set(
    servers.flatMap((s) =>
      (s.deployments ?? [])
        .map((d) => d.linkedRepositoryId)
        .filter((id): id is number => id != null),
    ),
  );
  const undeployed = repos.filter((r) => !deployedRepoIds.has(r.id));

  const run = async (action: () => Promise<unknown>, fallback: string) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      onChange();
    } catch (err: any) {
      setError(errMsg(err, fallback));
    } finally {
      setBusy(false);
    }
  };

  const createServer = () => {
    const host = draft.host.trim();
    if (!host) return;
    const roleName = role === "FRONT" ? "Front" : role === "BACK" ? "Back" : "Autre";
    const name = draft.name.trim() || roleName;
    return run(async () => {
      await createLightweightClientServer(clientId, {
        name,
        host,
        environment: draft.environment,
      });
      setDraft((current) => ({ ...current, name: "", host: "" }));
    }, "Création du serveur impossible.");
  };

  return (
    <section className="space-y-5">
      <div>
        <h2 className="text-sm font-bold font-headline uppercase tracking-widest text-outline flex items-center gap-2">
          <span className="material-symbols-outlined text-base">dns</span>
          Serveurs du projet ({servers.length})
        </h2>
        <p className="text-xs text-on-surface-variant mt-1 max-w-2xl">
          Un serveur front et un serveur back restent deux machines. Chaque carte montre les dépôts qui y sont déployés.
        </p>
      </div>

      {undeployed.length > 0 && (
        <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 px-4 py-3">
          <p className="text-[10px] uppercase tracking-widest text-amber-300 font-bold">
            Dépôts du projet sans serveur ({undeployed.length})
          </p>
          <ul className="mt-2 flex flex-wrap gap-2">
            {undeployed.map((repo) => (
              <li
                key={repo.id}
                title={repo.repoUrl}
                className="rounded-full border border-amber-500/30 bg-surface-container px-3 py-1 text-xs text-on-surface"
              >
                {repoShortName(repo.repoUrl)}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11px] text-amber-200/80">
            {servers.length === 0
              ? "Créez ou liez un serveur, puis placez chaque dépôt depuis sa configuration."
              : "Ouvrez la configuration d'un serveur pour y placer un de ces dépôts."}
          </p>
        </div>
      )}

      {servers.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-outline-variant/30 px-4 py-8 text-center">
          <span className="material-symbols-outlined text-4xl text-outline">dns</span>
          <p className="mt-2 font-headline text-on-surface">Aucun serveur lié à ce projet</p>
          <p className="mt-1 text-xs text-outline">Le formulaire ci-dessous crée la machine, ou rattache une machine déjà enregistrée.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          {servers.map((server) => {
            const deployed = (server.deployments ?? []).filter((item) => item.linkedRepositoryId != null);
            const prod = (server.environment ?? "").toUpperCase().startsWith("PROD");
            return (
              <div key={server.id} className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="font-headline font-bold text-on-surface truncate">{server.name}</p>
                    <p className="text-xs font-mono text-outline truncate">{server.host}</p>
                  </div>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${prod ? "bg-error-container text-on-error-container" : "bg-surface-variant text-on-surface-variant"}`}>
                    {prod ? "PROD" : server.environment || "TEST"}
                  </span>
                </div>
                <p className="mt-2 text-[11px] text-outline">
                  {deployed.length === 0 ? "Aucun dépôt déployé" : `${deployed.length} dépôt${deployed.length > 1 ? "s" : ""} déployé${deployed.length > 1 ? "s" : ""}`}
                </p>
                <DeployedRepos deployments={server.deployments ?? []} roles={roles} />
                <ServerPosture posture={server.posture} />
                <div className="flex flex-wrap items-center justify-between gap-2 mt-3 text-[11px]">
                  <div className="flex flex-wrap items-center gap-3">
                    <Link to={`/server-config/${server.id}`} className="inline-flex items-center gap-1 rounded-lg bg-primary/10 px-2.5 py-1.5 font-semibold text-primary hover:bg-primary/20">
                      <span className="material-symbols-outlined text-[14px]">tune</span>
                      Configuration
                    </Link>
                    {canLinkExisting && (
                      <button
                        type="button"
                        onClick={() => setOpenVulnId(openVulnId === server.id ? null : server.id)}
                        className="inline-flex items-center gap-1 text-primary hover:underline font-semibold"
                      >
                        <span className="material-symbols-outlined text-[14px]">shield</span>
                        {openVulnId === server.id ? "Masquer" : "Vulnérabilités"}
                      </button>
                    )}
                  </div>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => run(() => unlinkClientServer(clientId, server.id), "Retrait impossible.")}
                    className="text-error/70 hover:text-error font-semibold disabled:opacity-40"
                  >
                    Retirer
                  </button>
                </div>
                {canLinkExisting && openVulnId === server.id && <ServerVulnPanel serverId={server.id} hasSsh={server.sshConfigured} />}
              </div>
            );
          })}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <form
          className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4 space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            createServer();
          }}
        >
          <div>
            <h3 className="font-headline text-sm font-bold text-on-surface">Créer un serveur</h3>
            <p className="mt-1 text-[11px] text-outline">
              Sans accès SSH : il sert à la cartographie. Le scan de configuration se fait ensuite dans Configuration.
            </p>
          </div>
          <fieldset className="space-y-1">
            <legend className="text-[10px] uppercase tracking-widest text-outline">Nom proposé</legend>
            <p className="text-[10px] text-outline">Ce choix remplit le nom quand le champ reste vide.</p>
            <div className="flex flex-wrap gap-2">
              {([
                ["FRONT", "Front"],
                ["BACK", "Back"],
                ["OTHER", "Autre"],
              ] as const).map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  aria-pressed={role === value}
                  onClick={() => setRole(value)}
                  className={`rounded-full px-3 py-1.5 text-xs font-semibold border ${
                    role === value
                      ? "border-primary/40 bg-primary/15 text-primary"
                      : "border-outline-variant/30 text-outline hover:text-on-surface"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </fieldset>
          <label className="block space-y-1">
            <span className="text-[10px] uppercase tracking-widest text-outline">Nom</span>
            <input
              value={draft.name}
              onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))}
              placeholder={role === "FRONT" ? "Front" : role === "BACK" ? "Back" : "Autre"}
              className={fieldClass}
            />
          </label>
          <label className="block space-y-1">
            <span className="text-[10px] uppercase tracking-widest text-outline">Adresse</span>
            <input
              value={draft.host}
              onChange={(event) => setDraft((current) => ({ ...current, host: event.target.value }))}
              placeholder="IP ou domaine"
              required
              className={fieldClass}
            />
          </label>
          <fieldset className="space-y-1">
            <legend className="text-[10px] uppercase tracking-widest text-outline">Environnement</legend>
            <div className="grid grid-cols-2 gap-2">
              {(["TEST", "PROD"] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  aria-pressed={draft.environment === value}
                  onClick={() => setDraft((current) => ({ ...current, environment: value }))}
                  className={`rounded-xl border px-3 py-2 text-xs font-semibold ${
                    draft.environment === value
                      ? "border-primary/40 bg-primary/15 text-primary"
                      : "border-outline-variant/30 text-outline hover:text-on-surface"
                  }`}
                >
                  {value === "TEST" ? "Test" : "Production"}
                </button>
              ))}
            </div>
          </fieldset>
          <button
            type="submit"
            disabled={!draft.host.trim() || busy}
            className="w-full rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-on-primary hover:opacity-90 disabled:opacity-40"
          >
            Créer le serveur
          </button>
        </form>

        {canLinkExisting && (
          <form
            className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4 space-y-3"
            onSubmit={(event) => {
              event.preventDefault();
              if (!pick) return;
              run(async () => {
                await linkClientServer(clientId, Number(pick));
                setPick("");
              }, "Liaison impossible (serveur déjà pris par un autre projet ?).");
            }}
          >
            <div>
              <h3 className="font-headline text-sm font-bold text-on-surface">Lier un serveur existant</h3>
              <p className="mt-1 text-[11px] text-outline">
                Une machine déjà enregistrée dans Server Config, pas encore rattachée à ce projet.
              </p>
            </div>
            {available.length === 0 ? (
              <p className="rounded-xl border border-dashed border-outline-variant/30 px-3 py-6 text-center text-xs text-outline">
                Aucun serveur disponible à lier.
              </p>
            ) : (
              <label className="block space-y-1">
                <span className="text-[10px] uppercase tracking-widest text-outline">Serveur</span>
                <select
                  value={pick}
                  onChange={(event) => setPick(event.target.value)}
                  className={`${fieldClass} [color-scheme:dark]`}
                >
                  <option value="">Choisir un serveur</option>
                  {available.map((option) => (
                    <option key={option.id} value={option.id}>
                      {option.name} · {option.host}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {pick && <KnownPorts ports={knownPorts} />}
            <button
              type="submit"
              disabled={!pick || busy}
              className="w-full rounded-xl border border-primary/30 bg-primary/10 px-4 py-2.5 text-sm font-semibold text-primary hover:bg-primary/20 disabled:opacity-40"
            >
              Lier ce serveur
            </button>
          </form>
        )}
      </div>
      {error && <p className="text-xs text-error">{error}</p>}
    </section>
  );
};

const fieldClass =
  "w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-3 py-2.5 text-sm text-on-surface placeholder:text-outline focus:outline-none focus:border-primary/50";

export default ProjectServersPanel;

function unexpectedPublicPort(exposure: string | null | undefined, port: number): boolean {
  return (exposure ?? "").toUpperCase() === "PUBLIC" && port !== 22 && port !== 80 && port !== 443;
}

function KnownPorts({ ports }: { ports: PortExposureDto[] | null }) {
  if (ports == null) {
    return <p className="text-[11px] text-outline">Lecture des ports déjà ouverts…</p>;
  }
  if (ports.length === 0) {
    return (
      <p className="text-[11px] text-outline">
        Aucun port relevé sur ce serveur. Un scan dans Configuration indiquera les ports déjà pris.
      </p>
    );
  }
  const seen = new Set<string>();
  const unique = ports.filter((port: PortExposureDto) => {
    const key = `${port.portNumber}|${(port.protocol || "tcp").toLowerCase()}|${port.exposureLevel || ""}|${port.serviceName || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const extra = unique.filter((port: PortExposureDto) => unexpectedPublicPort(port.exposureLevel, port.portNumber));
  return (
    <div className="rounded-xl border border-outline-variant/20 bg-surface-container-high px-3 py-2 space-y-1.5">
      <p className="text-[10px] uppercase tracking-widest text-outline">Ports déjà utilisés sur ce serveur</p>
      <ul className="flex flex-wrap gap-1.5">
        {unique.map((port: PortExposureDto, index: number) => {
          const extraPort = unexpectedPublicPort(port.exposureLevel, port.portNumber);
          return (
            <li
              key={`${port.portNumber}-${port.protocol}-${index}`}
              className={`rounded-full border px-2 py-0.5 text-[10px] font-mono ${
                extraPort ? "border-amber-500/40 bg-amber-500/10 text-amber-200" : "border-outline-variant/30 text-on-surface-variant"
              }`}
            >
              {port.portNumber}/{port.protocol || "tcp"}
              {port.serviceName ? ` ${port.serviceName}` : ""}
            </li>
          );
        })}
      </ul>
      {extra.length > 0 && (
        <p className="text-[11px] text-amber-200">
          {extra.length === 1 ? "1 port est ouvert" : `${extra.length} ports sont ouverts`} sur internet en dehors de 22, 80 et 443.
        </p>
      )}
    </div>
  );
}

function ServerPosture({ posture }: { posture?: ProjectServerPosture | null }) {
  if (!posture?.scanned) {
    return (
      <p className="mt-3 text-[11px] text-outline">
        Aucun scan de ce serveur. Les ports déjà utilisés et les failles s'affichent ici après un scan dans Configuration.
      </p>
    );
  }
  const critical = posture.issues.filter((issue) => issue.severity === "CRITICAL");
  const others = posture.issues.filter((issue) => issue.severity !== "CRITICAL");
  return (
    <div className="mt-3 space-y-2 border-t border-outline-variant/15 pt-3">
      <p className="text-[10px] uppercase tracking-widest text-outline">Failles et ports</p>
      {posture.criticalCount > 0 && (
        <p className="text-xs font-semibold text-error">
          {posture.criticalCount === 1 ? "1 faille critique" : `${posture.criticalCount} failles critiques`}
        </p>
      )}
      {critical.length > 0 && (
        <ul className="space-y-1">
          {critical.map((issue) => (
            <li key={`c-${issue.title}`} className="text-[11px] text-on-surface">{issue.title}</li>
          ))}
        </ul>
      )}
      {others.length > 0 && (
        <ul className="space-y-1">
          {others.map((issue) => (
            <li key={`w-${issue.title}`} className="text-[11px] text-on-surface-variant">{issue.title}</li>
          ))}
        </ul>
      )}
      {posture.ports.length > 0 && (
        <div className="space-y-1">
          <p className="text-[10px] uppercase tracking-widest text-outline">Ports déjà utilisés</p>
          <ul className="flex flex-wrap gap-1.5">
            {posture.ports.map((port, index) => (
              <li
                key={`${port.port}-${port.protocol}-${index}`}
                className={`rounded-full border px-2 py-0.5 text-[10px] font-mono ${
                  port.unexpected ? "border-amber-500/40 bg-amber-500/10 text-amber-200" : "border-outline-variant/30 text-on-surface-variant"
                }`}
              >
                {port.port}/{port.protocol || "tcp"}
                {port.service ? ` ${port.service}` : ""}
              </li>
            ))}
          </ul>
          {posture.unexpectedPortCount > 0 && (
            <p className="text-[11px] text-amber-200">
              {posture.unexpectedPortCount === 1
                ? "1 port est ouvert sur internet en dehors de 22, 80 et 443."
                : `${posture.unexpectedPortCount} ports sont ouverts sur internet en dehors de 22, 80 et 443.`}
            </p>
          )}
        </div>
      )}
      {posture.issues.length === 0 && posture.ports.length === 0 && (
        <p className="text-[11px] text-outline">Scan terminé : aucune faille critique et aucun port relevé.</p>
      )}
    </div>
  );
}

function repoShortName(url: string): string {
  if (!url) return "Dépôt";
  return url.replace(/\.git$/, "").split("/").pop() ?? url;
}

function strategyLabel(strategy?: string | null): string {
  if (strategy === "STATIC_NGINX") return "Nginx statique";
  if (strategy === "DOCKER_COMPOSE") return "Docker Compose";
  return strategy || "—";
}

function statusLabel(status?: string | null): string {
  switch (status) {
    case "SUCCESS":
      return "Réussi";
    case "FAILED":
      return "Échec";
    case "BLOCKED":
      return "Bloqué";
    case "RUNNING":
      return "En cours";
    default:
      return status || "Aucun";
  }
}

function DeployedRepos({
  deployments,
  roles,
}: {
  deployments: ProjectDeploymentDto[];
  roles?: Partial<Record<number, SolutionRole>>;
}) {
  const linked = deployments.filter((d) => d.linkedRepositoryId != null);
  if (linked.length === 0) return null;
  return (
    <ul className="mt-3 space-y-2">
      {linked.map((d) => {
        const name = d.repositoryName || d.name || `Dépôt #${d.linkedRepositoryId}`;
        const role = roleLabel(solutionRoleOf(roles, d.linkedRepositoryId as number));
        return (
        <li
          key={d.id ?? `legacy-${d.linkedRepositoryId}`}
          className="rounded-xl border border-outline-variant/[0.12] bg-surface-container-high px-3 py-2 space-y-1"
        >
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-semibold text-on-surface truncate">
              {name}
              <span className="font-normal text-on-surface-variant"> · {role}</span>
            </p>
            <span className="text-[10px] font-bold text-outline shrink-0">{statusLabel(d.lastStatus)}</span>
          </div>
          <dl className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[10px] text-on-surface-variant">
            <div><dt className="inline text-outline">Branche </dt><dd className="inline">{d.deployBranch || "—"}</dd></div>
            <div><dt className="inline text-outline">Domaine </dt><dd className="inline">{d.domain || "—"}</dd></div>
            <div className="col-span-2 truncate" title={d.deployPath || undefined}>
              <dt className="inline text-outline">Chemin </dt><dd className="inline font-mono">{d.deployPath || "—"}</dd>
            </div>
            <div><dt className="inline text-outline">Stratégie </dt><dd className="inline">{strategyLabel(d.deployStrategy)}</dd></div>
            <div><dt className="inline text-outline">Auto-deploy </dt><dd className="inline">{d.autoDeployEnabled ? "Oui" : "Non"}</dd></div>
            {d.lastCommitSha && (
              <div className="col-span-2">
                <dt className="inline text-outline">Commit </dt>
                <dd className="inline font-mono">{d.lastCommitSha.slice(0, 7)}</dd>
              </div>
            )}
          </dl>
        </li>
        );
      })}
    </ul>
  );
}
