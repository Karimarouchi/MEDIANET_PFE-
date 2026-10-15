import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import DeadlineBadge, { daysLeft } from "../components/DeadlineBadge";
import { useAuth } from "../context/AuthContext";
import { getAllScans, getClients, type ClientDto, type ScanResultDto } from "../services/api";

type ProjectFilter = "all" | "late" | "noscan" | "cve";

const FILTERS: { id: ProjectFilter; label: string }[] = [
  { id: "all", label: "Tous" },
  { id: "late", label: "En retard" },
  { id: "noscan", label: "Sans scan" },
  { id: "cve", label: "Avec CVE" },
];

function scansFor(client: ClientDto, scans: ScanResultDto[]): ScanResultDto[] {
  return scans.filter((scan) => (scan.clientIds ?? []).includes(client.id));
}

function scanTime(scan: ScanResultDto): number {
  const raw = scan.startedAt || scan.finishedAt;
  const parsed = raw ? Date.parse(raw) : NaN;
  return Number.isNaN(parsed) ? 0 : parsed;
}

function latestScan(list: ScanResultDto[]): ScanResultDto | null {
  if (list.length === 0) return null;
  return [...list].sort((a, b) => {
    const delta = scanTime(b) - scanTime(a);
    return delta !== 0 ? delta : b.id - a.id;
  })[0];
}

function latestCompletedByRepo(list: ScanResultDto[]): ScanResultDto[] {
  const byRepo = new Map<number, ScanResultDto>();
  for (const scan of list) {
    if (scan.status !== "COMPLETED") continue;
    const previous = byRepo.get(scan.repoId);
    if (!previous || scanTime(scan) > scanTime(previous) || (scanTime(scan) === scanTime(previous) && scan.id > previous.id)) {
      byRepo.set(scan.repoId, scan);
    }
  }
  return Array.from(byRepo.values());
}

function cveOfLatestCompleted(list: ScanResultDto[]): number {
  return latestCompletedByRepo(list).reduce((total, scan) => total + (scan.cveCount ?? 0), 0);
}

function hasCompletedScan(list: ScanResultDto[]): boolean {
  return list.some((scan) => scan.status === "COMPLETED");
}

function shortRepo(url?: string | null): string {
  if (!url) return "dépôt";
  const name = url.split("/").pop()?.replace(/\.git$/, "");
  return name || url;
}

function scanWhen(scan: ScanResultDto): string {
  const raw = scan.finishedAt || scan.startedAt;
  if (!raw) return "—";
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleDateString("fr-FR");
}

function scanMeta(status: string): { icon: string; label: string; tone: string } {
  switch (status) {
    case "COMPLETED":
      return { icon: "check_circle", label: "Terminé", tone: "text-tertiary" };
    case "FAILED":
      return { icon: "error", label: "Échec", tone: "text-error" };
    case "RUNNING":
      return { icon: "progress_activity", label: "En cours", tone: "text-primary" };
    default:
      return { icon: "schedule", label: "En attente", tone: "text-outline" };
  }
}

function compareProjects(a: ClientDto, b: ClientDto): number {
  const leftA = daysLeft(a.releaseDeadline);
  const leftB = daysLeft(b.releaseDeadline);
  const rank = (left: number | null) => (left === null ? Number.POSITIVE_INFINITY : left);
  const rankA = rank(leftA);
  const rankB = rank(leftB);
  if (rankA !== rankB) return rankA < rankB ? -1 : 1;
  return a.name.localeCompare(b.name, "fr", { sensitivity: "base" });
}

const ProjectsPage: React.FC = () => {
  const navigate = useNavigate();
  const { user, hasPermission } = useAuth();
  const canCreate = user?.systemRole === "ADMIN" && hasPermission("ADMIN_PROJECTS");

  const [clients, setClients] = useState<ClientDto[]>([]);
  const [scans, setScans] = useState<ScanResultDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<ProjectFilter>("all");

  const load = useCallback(() => {
    setLoading(true);
    setFailed(false);
    Promise.all([getClients(), getAllScans()])
      .then(([clientsResponse, scansResponse]) => {
        setClients(clientsResponse.data);
        setScans(scansResponse.data);
      })
      .catch(() => setFailed(true))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const summaries = useMemo(
    () =>
      clients.map((client) => {
        const related = scansFor(client, scans);
        const left = daysLeft(client.releaseDeadline);
        return {
          client,
          related,
          latest: latestScan(related),
          cveCount: cveOfLatestCompleted(related),
          completed: hasCompletedScan(related),
          late: left !== null && left < 0,
          soon: left !== null && left <= 7,
        };
      }),
    [clients, scans],
  );

  const urgentCount = summaries.filter((item) => item.soon).length;
  const withoutCompletedScan = summaries.filter((item) => !item.completed).length;

  const visible = summaries
    .filter((item) => {
      const needle = query.trim().toLowerCase();
      if (!needle) return true;
      const name = item.client.name.toLowerCase();
      const company = (item.client.company ?? "").toLowerCase();
      return name.includes(needle) || company.includes(needle);
    })
    .filter((item) => {
      if (filter === "late") return item.late;
      if (filter === "noscan") return !item.completed;
      if (filter === "cve") return item.cveCount > 0;
      return true;
    })
    .sort((a, b) => compareProjects(a.client, b.client));

  const resetFilters = () => {
    setQuery("");
    setFilter("all");
  };

  return (
    <div className="space-y-8">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.35em] text-outline mb-1">Vue d'ensemble</p>
          <h1 className="font-headline text-3xl font-bold text-on-surface tracking-tight">Projets</h1>
          <p className="text-sm text-on-surface-variant mt-1 max-w-2xl">
            Chaque projet regroupe des dépôts, leurs scans et leurs serveurs.
          </p>
        </div>
        {canCreate && (
          <button
            type="button"
            onClick={() => navigate("/admin/projects?create=1")}
            className="flex-shrink-0 flex items-center gap-2 rounded-2xl bg-primary px-5 py-3 font-headline text-sm font-semibold text-on-primary hover:opacity-90 active:scale-95 transition-all shadow-lg shadow-primary/20"
          >
            <span className="material-symbols-outlined text-base">add</span>
            Créer un projet
          </button>
        )}
      </header>

      {!loading && !failed && clients.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Counter value={clients.length} label={clients.length === 1 ? "projet" : "projets"} />
          <Counter value={urgentCount} label={urgentCount === 1 ? "échéance proche" : "échéances proches"} tone={urgentCount > 0 ? "text-amber-300" : "text-on-surface"} />
          <Counter value={withoutCompletedScan} label="sans scan terminé" tone={withoutCompletedScan > 0 ? "text-amber-300" : "text-on-surface"} />
        </div>
      )}

      {!loading && !failed && clients.length > 0 && (
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <label className="relative flex-1">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-base">search</span>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Rechercher un nom ou une société"
              aria-label="Rechercher un projet"
              className="w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container-high py-2.5 pl-10 pr-4 text-sm text-on-surface placeholder:text-outline focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30"
            />
          </label>
          <div className="flex flex-wrap gap-2" role="group" aria-label="Filtrer les projets">
            {FILTERS.map((item) => {
              const active = filter === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  aria-pressed={active}
                  onClick={() => setFilter(item.id)}
                  className={`rounded-full px-3 py-1.5 text-xs font-semibold border transition-all ${
                    active
                      ? "bg-primary/15 border-primary/40 text-primary"
                      : "bg-surface-container border-outline-variant/[0.2] text-outline hover:text-on-surface"
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {loading && <SkeletonGrid />}

      {!loading && failed && (
        <div className="flex flex-col items-center justify-center py-24 text-center space-y-4">
          <span className="material-symbols-outlined text-5xl text-error">cloud_off</span>
          <p className="text-lg font-headline text-on-surface">Impossible de charger les projets</p>
          <p className="text-sm text-outline max-w-sm">La liste n'a pas pu être récupérée. Réessayez dans un instant.</p>
          <button
            type="button"
            onClick={load}
            className="mt-2 flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary/10 border border-primary/30 text-primary text-sm font-semibold hover:bg-primary/20 transition-all"
          >
            <span className="material-symbols-outlined text-base">refresh</span>
            Réessayer
          </button>
        </div>
      )}

      {!loading && !failed && clients.length === 0 && (
        <div className="flex flex-col items-center justify-center py-24 text-outline space-y-4">
          <span className="material-symbols-outlined text-6xl">folder_special</span>
          <p className="text-lg font-headline text-on-surface">Aucun projet</p>
          <p className="text-sm text-center max-w-xs text-outline">
            {canCreate
              ? "Créez un projet pour regrouper des dépôts, des scans et des serveurs."
              : "Un administrateur peut créer un projet et vous y donner accès."}
          </p>
          {canCreate && (
            <button
              type="button"
              onClick={() => navigate("/admin/projects?create=1")}
              className="mt-2 flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary text-on-primary text-sm font-semibold hover:opacity-90 transition-all"
            >
              <span className="material-symbols-outlined text-base">add</span>
              Créer un projet
            </button>
          )}
        </div>
      )}

      {!loading && !failed && clients.length > 0 && visible.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 text-center space-y-3">
          <span className="material-symbols-outlined text-5xl text-outline">filter_alt_off</span>
          <p className="text-lg font-headline text-on-surface">Aucun projet pour ce filtre</p>
          <button
            type="button"
            onClick={resetFilters}
            className="mt-1 flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary/10 border border-primary/30 text-primary text-sm font-semibold hover:bg-primary/20 transition-all"
          >
            Tout afficher
          </button>
        </div>
      )}

      {!loading && !failed && visible.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {visible.map((item) => {
            const { client, latest, cveCount, late, soon } = item;
            const border = late
              ? "border-error/50"
              : soon
                ? "border-amber-500/50"
                : "border-outline-variant/[0.15]";
            const meta = latest ? scanMeta(latest.status) : null;
            return (
              <Link
                key={client.id}
                to={`/projects/${client.id}`}
                className={`glass-panel rounded-2xl border ${border} bg-surface-container p-5 hover:border-primary/40 hover:bg-primary/5 hover:shadow-[0_0_20px_rgba(0,209,255,0.08)] transition-all group focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary`}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0">
                      <span className="material-symbols-outlined text-primary text-lg">folder_special</span>
                    </div>
                    <div className="min-w-0">
                      <h2 className="font-headline font-bold text-on-surface group-hover:text-primary transition-colors truncate">
                        {client.name}
                      </h2>
                      {client.company && <p className="text-[11px] text-outline truncate">{client.company}</p>}
                    </div>
                  </div>
                  <span className="material-symbols-outlined text-outline group-hover:text-primary transition-colors text-base">
                    arrow_forward
                  </span>
                </div>

                {client.releaseDeadline && (
                  <div className="mb-4">
                    <DeadlineBadge deadline={client.releaseDeadline} label={client.releaseLabel} compact />
                  </div>
                )}

                <div className="grid grid-cols-3 gap-3 mb-4">
                  <Stat value={client.repositoryIds?.length ?? 0} label="Dépôts" />
                  <Stat value={item.related.length} label="Scans" />
                  <Stat value={cveCount} label="CVE" alert={cveCount > 0} />
                </div>

                {latest && meta ? (
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-container-lowest/60 border border-outline-variant/[0.1]">
                    <span className={`material-symbols-outlined text-[13px] ${meta.tone}`}>{meta.icon}</span>
                    <span className="text-[10px] text-outline flex-1 truncate">
                      Dernier scan : <span className="text-on-surface-variant font-medium">{shortRepo(latest.repoUrl)}</span>
                    </span>
                    <span className={`text-[10px] font-semibold shrink-0 ${meta.tone}`}>{meta.label}</span>
                    <span className="text-[10px] text-outline shrink-0">{scanWhen(latest)}</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-container-lowest/60 border border-outline-variant/[0.1]">
                    <span className="material-symbols-outlined text-outline text-[13px]">schedule</span>
                    <span className="text-[10px] text-outline italic">Aucun scan effectué</span>
                  </div>
                )}

                {client.employeeLogins?.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1">
                    {client.employeeLogins.slice(0, 3).map((login) => (
                      <span key={login} className="px-2 py-0.5 rounded-full bg-secondary/10 text-secondary text-[10px] font-medium">
                        {login}
                      </span>
                    ))}
                    {client.employeeLogins.length > 3 && (
                      <span className="px-2 py-0.5 rounded-full bg-surface-container-high text-outline text-[10px]">
                        +{client.employeeLogins.length - 3}
                      </span>
                    )}
                  </div>
                )}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
};

const Counter: React.FC<{ value: number; label: string; tone?: string }> = ({ value, label, tone = "text-on-surface" }) => (
  <div className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container px-4 py-3">
    <p className={`text-2xl font-bold font-headline ${tone}`}>{value}</p>
    <p className="text-[11px] uppercase tracking-widest text-outline mt-0.5">{label}</p>
  </div>
);

const Stat: React.FC<{ value: number; label: string; alert?: boolean }> = ({ value, label, alert }) => (
  <div className={`rounded-xl px-3 py-2 text-center ${alert ? "bg-error/10" : "bg-surface-container-high"}`}>
    <p className={`text-lg font-bold font-headline ${alert ? "text-error" : "text-on-surface"}`}>{value}</p>
    <p className="text-[9px] uppercase tracking-widest text-outline mt-0.5">{label}</p>
  </div>
);

const SkeletonGrid: React.FC = () => (
  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5" aria-hidden="true">
    {Array.from({ length: 6 }, (_, index) => (
      <div key={index} className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-5 animate-pulse space-y-4">
        <div className="h-10 w-2/3 rounded-xl bg-surface-container-high" />
        <div className="grid grid-cols-3 gap-3">
          <div className="h-14 rounded-xl bg-surface-container-high" />
          <div className="h-14 rounded-xl bg-surface-container-high" />
          <div className="h-14 rounded-xl bg-surface-container-high" />
        </div>
        <div className="h-8 rounded-lg bg-surface-container-high" />
      </div>
    ))}
  </div>
);

export default ProjectsPage;
