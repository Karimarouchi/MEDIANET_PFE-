import React, { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import SSLAnalysis, { computeScoreBreakdown, SSLScheduleModal } from "./SSLAnalysis";
import {
  getClient,
  getRepositories,
  getAllScans,
  getScanSeveritySummary,
  startScan,
  getScheduledSummary,
  getRepositoryScheduledScans,
  createScheduledScan,
  pauseScheduledScan,
  resumeScheduledScan,
  deleteScheduledScan,
  getSslResult,
  setClientSslAlert,
  setClientRepoRole,
  getReleaseReadiness,
  getClientServers,
  updateClient,
  type ProjectServerDto,
  type ClientDto,
  type ReleaseReadinessDto,
  type RepositoryDto,
  type ScanResultDto,
  type ScanSeveritySummary,
  type ScheduledScan,
  type ScheduleType,
  apiUrl,
} from "../services/api";
import ReleaseReadinessPanel from "../components/ReleaseReadinessPanel";
import ProjectServersPanel from "../components/ProjectServersPanel";
import ProjectOverviewDashboard, { SOLUTION_ROLES, decisionLine, projectPulse, readCertExpiry, type SolutionRole } from "../components/ProjectOverviewDashboard";
import AddProjectRepoPanel from "../components/AddProjectRepoPanel";
import DeadlineBadge from "../components/DeadlineBadge";
import ProjectCiPanel from "../components/ProjectCiPanel";
import DeleteProjectDialog from "../components/DeleteProjectDialog";
import CiOverviewCard from "../components/CiOverviewCard";
import { SslAlertBanner, SslAlertDialog } from "../components/SslAlertNotice";
import { dueSslAlerts, markPopupSeen, popupSeenToday } from "../utils/sslAlert";
import AttackGraph from "./AttackGraph";
import { useAuth } from "../context/AuthContext";

// ── helpers ──────────────────────────────────────────────────────────────────

interface LogLine {
  time: string;
  prefix: string;
  text: string;
}

function parseLogLine(raw: string): LogLine {
  const time = new Date().toTimeString().slice(0, 8);
  for (const p of [
    "[SYSTEM]",
    "[SUCCESS]",
    "[SCAN]",
    "[WARN]",
    "[ERROR]",
    "[INFO]",
  ]) {
    if (raw.includes(p))
      return { time, prefix: p, text: raw.replace(p, "").trim() };
  }
  return { time, prefix: "", text: raw };
}

function prefixColor(p: string): string {
  switch (p) {
    case "[SYSTEM]":
      return "text-outline";
    case "[SUCCESS]":
      return "text-tertiary";
    case "[SCAN]":
      return "text-primary";
    case "[WARN]":
      return "text-[#FFBD2E]";
    case "[ERROR]":
      return "text-error";
    case "[INFO]":
      return "text-secondary";
    default:
      return "text-on-surface-variant";
  }
}

function repoShortName(url: string): string {
  if (!url) return "";
  return (
    url
      .replace(/\.git$/, "")
      .split("/")
      .pop() ?? url
  );
}

function countLabel(count: number, singular: string, plural: string): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

function timeAgo(d: string | null | undefined): string {
  if (!d) return "—";
  const diff = Date.now() - new Date(d).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "il y a quelques secondes";
  if (m < 60) return `il y a ${m}min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `il y a ${h}h`;
  return `il y a ${Math.floor(h / 24)}j`;
}

const scheduleTypeLabel: Record<string, string> = {
  ONCE: "Une seule fois",
  WEEKLY: "Hebdomadaire",
  EVERY_15_DAYS: "Tous les 15 jours",
  MONTHLY: "Mensuel",
};
const scheduleStatusLabel: Record<string, string> = {
  ACTIVE: "Actif",
  PAUSED: "Pausé",
  RUNNING: "En cours",
  COMPLETED: "Terminé",
  FAILED: "Échec",
};

// ── Component ─────────────────────────────────────────────────────────────────

const ProjectDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const loadedId = useRef<string | null>(null);

  // Data
  const [client, setClient] = useState<ClientDto | null>(null);
  const [repos, setRepos] = useState<RepositoryDto[]>([]);
  const [scans, setScans] = useState<ScanResultDto[]>([]);
  const [scheduledSummary, setScheduledSummary] = useState<
    Record<string, ScheduledScan>
  >({});
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const [readiness, setReadiness] = useState<ReleaseReadinessDto | null>(null);
  const [servers, setServers] = useState<ProjectServerDto[]>([]);
  const [tab, setTab] = useState<"overview" | "repos" | "ci" | "domain" | "servers" | "map">("overview");
  const [blockersOpen, setBlockersOpen] = useState(false);
  const { hasPermission, user } = useAuth();
  const canDeleteProject = user?.systemRole === "ADMIN";
  const [deleteOpen, setDeleteOpen] = useState(false);

  // Scan
  const [scanning, setScanning] = useState<number | null>(null); // repo.id
  const [logs, setLogs] = useState<LogLine[]>([]);
  const evtSourceRef = useRef<EventSource | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const [selectedSslScanId, setSelectedSslScanId] = useState<number | null>(null);
  const [latestSslGrade, setLatestSslGrade] = useState<string | null>(null);
  const [sslCert, setSslCert] = useState<{ expiresOn: string | null; expired: boolean; daysLeft: number | null } | null>(null);
  const [sslAlertError, setSslAlertError] = useState<string | null>(null);
  const [roleError, setRoleError] = useState<string | null>(null);
  const [severityByScan, setSeverityByScan] = useState<Record<number, ScanSeveritySummary> | null>(null);

  // SSL schedule modal (separate from the CVE schedule modal)
  const [sslScheduleOpen, setSslScheduleOpen] = useState(false);
  const [sslScheduleDate, setSslScheduleDate] = useState('');
  const [sslScheduleHour, setSslScheduleHour] = useState('09');
  const [sslScheduleMinute, setSslScheduleMinute] = useState('00');
  const [sslScheduleFrequency, setSslScheduleFrequency] = useState<ScheduleType>('ONCE');
  const [sslScheduleSubmitting, setSslScheduleSubmitting] = useState(false);
  const [sslScheduleError, setSslScheduleError] = useState('');
  const [sslScheduleSuccess, setSslScheduleSuccess] = useState('');

  // Schedule modal
  const [scheduleModalOpen, setScheduleModalOpen] = useState(false);
  const [scheduleModalRepo, setScheduleModalRepo] =
    useState<RepositoryDto | null>(null);
  const [existingSchedules, setExistingSchedules] = useState<ScheduledScan[]>(
    [],
  );
  const [scheduleDate, setScheduleDate] = useState("");
  const [scheduleHour, setScheduleHour] = useState("08");
  const [scheduleMinute, setScheduleMinute] = useState("00");
  const [scheduleFrequency, setScheduleFrequency] =
    useState<ScheduleType>("WEEKLY");
  const [scheduleScanMode, setScheduleScanMode] = useState("auto");
  const [scheduleSubmitting, setScheduleSubmitting] = useState(false);
  const [scheduleError, setScheduleError] = useState("");
  const [scheduleSuccess, setScheduleSuccess] = useState("");

  // ── Load data ──────────────────────────────────────────────────────────────

  const loadData = useCallback(async () => {
    if (!id) return;
    if (loadedId.current !== id) {
      setClient(null);
      loadedId.current = id;
    }
    setLoading(true);
    setLoadError(null);
    setMissing(false);
    try {
      const [clientRes, reposRes, scansRes, summaryRes, readinessRes, serversRes] = await Promise.all([
        getClient(Number(id)),
        getRepositories(),
        getAllScans(),
        getScheduledSummary(),
        getReleaseReadiness(Number(id)).catch(() => null),
        getClientServers(Number(id)).catch(() => null),
      ]);
      const c = clientRes.data;
      setClient(c);
      setReadiness(readinessRes?.data ?? null);
      setServers(serversRes?.data ?? []);
      setRepos(
        reposRes.data.filter((r) => (c.repositoryIds ?? []).includes(r.id)),
      );
      setScans(scansRes.data.filter((s) => {
        const isClientScan = (s.clientIds ?? []).includes(c.id);
        const isSslForDomain = s.scanMode === 'ssl-only' && c.domainName && s.targetDomain === c.domainName;
        return isClientScan || isSslForDomain;
      }));
      setScheduledSummary(summaryRes.data);
    } catch (err) {
      const status = typeof err === "object" && err && "response" in err
        ? (err as { response?: { status?: number } }).response?.status
        : undefined;
      if (status === 404) setMissing(true);
      else setLoadError("Impossible de charger ce projet.");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadData();
  }, [loadData]);
  
  useEffect(() => {
    const domain = client?.domainName?.trim();
    const latestSslScan = scans
      .filter((scan) => scan.scanMode === "ssl-only" && scan.status === "COMPLETED" && (!domain || scan.targetDomain === domain))
      .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())[0];
    if (latestSslScan) {
      getSslResult(latestSslScan.id).then(res => {
        const bd = computeScoreBreakdown(res.data);
        setLatestSslGrade(bd.grade);
        setSslCert(readCertExpiry(res.data));
      }).catch(() => {
        setLatestSslGrade(null);
        setSslCert(null);
      });
    } else {
      setLatestSslGrade(null);
      setSslCert(null);
    }
  }, [scans, client?.domainName]);

  // Alert day reached: banner on every tab, and a window once a day when entering the project.
  const dueSslAlert = client
    ? dueSslAlerts([{ ...client, sslCertExpiresOn: sslCert?.expiresOn ?? client.sslCertExpiresOn }])[0] ?? null
    : null;
  const [sslDialogOpen, setSslDialogOpen] = useState(false);
  const dueAlertClientId = dueSslAlert?.clientId;
  useEffect(() => {
    if (dueAlertClientId != null && !popupSeenToday(dueAlertClientId)) setSslDialogOpen(true);
  }, [dueAlertClientId]);
  const closeSslDialog = () => {
    if (dueAlertClientId != null) markPopupSeen(dueAlertClientId);
    setSslDialogOpen(false);
  };

  useEffect(() => {
    const ids: number[] = [];
    const seen = new Set<number>();
    for (const scan of scans) {
      if (scan.status !== "COMPLETED" || scan.scanMode === "ssl-only" || seen.has(scan.repoId)) continue;
      seen.add(scan.repoId);
      ids.push(scan.id);
    }
    if (ids.length === 0) {
      setSeverityByScan({});
      return;
    }
    let cancelled = false;
    getScanSeveritySummary(ids)
      .then((res) => {
        if (cancelled) return;
        const next: Record<number, ScanSeveritySummary> = {};
        for (const row of res.data) next[row.scanId] = row;
        setSeverityByScan(next);
      })
      .catch(() => {
        if (!cancelled) setSeverityByScan(null);
      });
    return () => {
      cancelled = true;
    };
  }, [scans]);
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // ── SSL Schedule handler ──────────────────────────────────────────────────

  const handleOpenSslSchedule = () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    setSslScheduleDate(tomorrow.toISOString().slice(0, 10));
    setSslScheduleError('');
    setSslScheduleSuccess('');
    setSslScheduleOpen(true);
  };

  const handleCreateSslSchedule = async () => {
    const d = client?.domainName?.trim();
    if (!d) return;
    if (!sslScheduleDate || !sslScheduleHour || !sslScheduleMinute) {
      setSslScheduleError('Veuillez choisir une date et une heure.');
      return;
    }
    setSslScheduleSubmitting(true);
    setSslScheduleError('');
    setSslScheduleSuccess('');
    try {
      await createScheduledScan({
        repositoryName: d,
        repoUrl: `ssl://${d}`,
        scanMode: 'ssl-only',
        targetDomain: d,
        scheduleType: sslScheduleFrequency,
        startAt: `${sslScheduleDate}T${sslScheduleHour}:${sslScheduleMinute}:00`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      });
      setSslScheduleSuccess(`Scan SSL planifié pour ${d} !`);
    } catch (err: any) {
      setSslScheduleError(
        err?.response?.data?.message ||
        err?.response?.data ||
        'Erreur lors de la planification.'
      );
    } finally {
      setSslScheduleSubmitting(false);
    }
  };

  // ── Scan handler ───────────────────────────────────────────────────────────

  const handleScan = async (repo: RepositoryDto) => {
    setScanning(repo.id);
    setLogs([]);
    try {
      const { data } = await startScan({
        repoUrl: repo.repoUrl,
        scanMode: "auto",
      });
      const evtSource = new EventSource(
        apiUrl(`/api/scans/${data.scanId}/logs`),
        { withCredentials: true },
      );
      evtSourceRef.current = evtSource;
      evtSource.onmessage = (event) => {
        const raw = event.data;
        if (raw === "%%SCAN_COMPLETE%%") {
          evtSource.close();
          evtSourceRef.current = null;
          setScanning(null);
          loadData();
          setTimeout(
            () =>
              navigate(
                `/vulnerabilities?scanId=${data.scanId}&repoId=${data.repoId}`,
              ),
            2000,
          );
          return;
        }
        setLogs((prev) => [...prev, parseLogLine(raw)]);
      };
      evtSource.onerror = () => {
        evtSource.close();
        evtSourceRef.current = null;
        setScanning(null);
      };
    } catch {
      setLogs((prev) => [
        ...prev,
        parseLogLine("[ERROR] Impossible de démarrer le scan."),
      ]);
      setScanning(null);
    }
  };

  const handleStopScan = () => {
    if (evtSourceRef.current) {
      evtSourceRef.current.close();
      evtSourceRef.current = null;
    }
    setScanning(null);
    setLogs([]);
  };

  // ── Schedule handlers ──────────────────────────────────────────────────────

  const refreshSummary = () =>
    getScheduledSummary()
      .then((r) => setScheduledSummary(r.data))
      .catch(() => {});

  const formatNextRun = (iso: string) => {
    try {
      return new Date(iso).toLocaleString("fr-FR", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return iso;
    }
  };

  const openScheduleModal = (repo: RepositoryDto) => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    setScheduleDate(tomorrow.toISOString().split("T")[0]);
    setScheduleHour("08");
    setScheduleMinute("00");
    setScheduleFrequency("WEEKLY");
    setScheduleScanMode("auto");
    setScheduleError("");
    setScheduleSuccess("");
    setScheduleModalRepo(repo);
    setScheduleModalOpen(true);
    getRepositoryScheduledScans(repo.id)
      .then((r) => setExistingSchedules(r.data))
      .catch(() => setExistingSchedules([]));
  };

  const closeScheduleModal = () => {
    setScheduleModalOpen(false);
    setScheduleModalRepo(null);
    setScheduleError("");
    setScheduleSuccess("");
  };

  const handleCreateSchedule = async () => {
    if (!scheduleModalRepo || !client) return;
    if (!scheduleDate) {
      setScheduleError("Choisissez une date.");
      return;
    }
    setScheduleSubmitting(true);
    setScheduleError("");
    setScheduleSuccess("");
    try {
      await createScheduledScan({
        repositoryId: scheduleModalRepo.id,
        repositoryName: `${client.name} / ${repoShortName(scheduleModalRepo.repoUrl)}`,
        repoUrl: scheduleModalRepo.repoUrl,
        branch: scheduleModalRepo.branch || "main",
        scanMode: scheduleScanMode || "auto",
        scheduleType: scheduleFrequency,
        startAt: `${scheduleDate}T${scheduleHour}:${scheduleMinute}:00`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      });
      setScheduleSuccess("Scan planifié avec succès !");
      refreshSummary();
      getRepositoryScheduledScans(scheduleModalRepo.id)
        .then((r) => setExistingSchedules(r.data))
        .catch(() => {});
    } catch (err: any) {
      setScheduleError(
        err?.response?.data?.message || "Erreur lors de la planification.",
      );
    } finally {
      setScheduleSubmitting(false);
    }
  };

  const handlePause = async (sid: number) => {
    await pauseScheduledScan(sid).catch(() => {});
    if (scheduleModalRepo)
      getRepositoryScheduledScans(scheduleModalRepo.id)
        .then((r) => setExistingSchedules(r.data))
        .catch(() => {});
    refreshSummary();
  };

  const handleResume = async (sid: number) => {
    await resumeScheduledScan(sid).catch(() => {});
    if (scheduleModalRepo)
      getRepositoryScheduledScans(scheduleModalRepo.id)
        .then((r) => setExistingSchedules(r.data))
        .catch(() => {});
    refreshSummary();
  };

  const handleDeleteSched = async (sid: number) => {
    await deleteScheduledScan(sid).catch(() => {});
    setExistingSchedules((prev) => prev.filter((s) => s.id !== sid));
    refreshSummary();
  };

  // ── Project scans (latest per repo) ───────────────────────────────────────

  // ── Loading ───────────────────────────────────────────────────────────────

  if (loading && !client) {
    return <ProjectDetailSkeleton />;
  }

  if (!client && missing) {
    return (
      <div className="max-w-xl mx-auto py-24 text-center text-outline">
        <span className="material-symbols-outlined text-5xl mb-4 block">
          error
        </span>
        <p>Projet introuvable.</p>
        <button
          onClick={() => navigate("/projects")}
          className="mt-4 text-primary text-sm hover:underline"
        >
          ← Retour aux projets
        </button>
      </div>
    );
  }

  if (!client) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center space-y-4">
        <span className="material-symbols-outlined text-5xl text-error">cloud_off</span>
        <p className="text-lg font-headline text-on-surface">{loadError ?? "Impossible de charger ce projet."}</p>
        <button
          type="button"
          onClick={() => loadData()}
          className="mt-2 flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary/10 border border-primary/30 text-primary text-sm font-semibold hover:bg-primary/20 transition-all"
        >
          <span className="material-symbols-outlined text-base">refresh</span>
          Réessayer
        </button>
      </div>
    );
  }

  const pulse = projectPulse(repos, servers, scans, readiness, client.releaseDeadline);
  const latestSslScan = scans
    .filter((scan) => scan.scanMode === "ssl-only" && scan.status === "COMPLETED" && !!client.domainName && scan.targetDomain === client.domainName)
    .sort((a, b) => new Date(b.finishedAt || b.startedAt).getTime() - new Date(a.finishedAt || a.startedAt).getTime())[0];
  const sslScans = scans
    .filter((scan) => scan.scanMode === "ssl-only" && !!client.domainName && scan.targetDomain === client.domainName)
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
  const activeSslScan = sslScans.find((scan) => scan.id === selectedSslScanId) ?? sslScans[0] ?? null;
  const cveScans = scans.filter((scan) => scan.scanMode !== "ssl-only");
  const openBlockers = () => {
    setTab("overview");
    setBlockersOpen(true);
    window.setTimeout(() => {
      document.getElementById("project-blockers")?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 60);
  };
  const saveRole = (repoId: number, role: SolutionRole) => {
    setRoleError(null);
    setClient((current) => current ? {
      ...current,
      repositoryRoles: [
        ...(current.repositoryRoles ?? []).filter((item) => item.repositoryId !== repoId),
        { repositoryId: repoId, role },
      ],
    } : current);
    setClientRepoRole(client.id, repoId, role)
      .then((res) => setClient(res.data))
      .catch(() => {
        setRoleError("Impossible d'enregistrer le rôle.");
        loadData();
      });
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-8">
      {/* Breadcrumb + header */}
      <header>
        <button
          onClick={() => navigate("/projects")}
          className="flex items-center gap-1 text-xs text-outline hover:text-primary transition-colors mb-3"
        >
          <span className="material-symbols-outlined text-sm">arrow_back</span>
          Projets
        </button>
        {loadError && (
          <div className="mb-3 flex flex-wrap items-center gap-3 rounded-xl border border-error/30 bg-error/10 px-4 py-2 text-sm text-error">
            <span>{loadError}</span>
            <button type="button" onClick={() => loadData()} className="font-semibold underline">
              Réessayer
            </button>
          </div>
        )}
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 shrink-0 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center">
            <span className="material-symbols-outlined text-primary text-2xl">
              folder_special
            </span>
          </div>
          <div>
            <h1 className="font-headline text-3xl font-bold text-on-surface">
              {client.name}
            </h1>
            {(client.company || client.domainName) && (
              <p className="text-sm text-outline">
                {client.company}
                {client.company && client.domainName ? " · " : ""}
                {client.domainName && <span className="text-primary">{client.domainName}</span>}
              </p>
            )}
            <p className="text-sm text-on-surface-variant mt-1 max-w-3xl">
              {decisionLine(client.releaseDeadline, pulse)}
            </p>
          </div>
          {canDeleteProject && (
            <button type="button" onClick={() => setDeleteOpen(true)}
              className="ml-auto self-start flex items-center gap-1.5 rounded-xl border border-error/30 px-3 py-2 text-sm font-semibold text-error hover:bg-error/10">
              <span className="material-symbols-outlined text-base" aria-hidden="true">delete</span>
              Supprimer le projet
            </button>
          )}
        </div>
        {canDeleteProject && (
          <DeleteProjectDialog projectId={client.id} open={deleteOpen} onClose={() => setDeleteOpen(false)}
            onDeleted={() => navigate("/projects", { replace: true })} />
        )}
        <div className="mt-4 max-w-xl">
          <DeadlineBadge
            deadline={client.releaseDeadline}
            label={client.releaseLabel}
            onChange={async (d) => {
              await updateClient(client.id, {
                name: client.name,
                company: client.company ?? "",
                domainName: client.domainName ?? "",
                email: client.email ?? "",
                releaseDeadline: d,
                releaseLabel: client.releaseLabel ?? null,
              });
              await loadData();
            }}
          />
        </div>
      </header>

      {dueSslAlert && <SslAlertBanner alert={dueSslAlert} onOpenSsl={() => setTab("domain")} />}
      {dueSslAlert && sslDialogOpen && (
        <SslAlertDialog
          alert={dueSslAlert}
          onClose={closeSslDialog}
          onOpenSsl={() => {
            closeSslDialog();
            setTab("domain");
          }}
        />
      )}

      <nav className="flex flex-wrap gap-1 rounded-2xl bg-surface-container-high p-1 w-fit">
        {([
          { key: "overview", icon: "dashboard", label: "Vue d'ensemble" },
          { key: "repos", icon: "code_blocks", label: `Dépôts & scans (${repos.length})` },
          { key: "domain", icon: "language", label: "Domaine" },
          { key: "ci", icon: "rocket_launch", label: "CI/CD" },
          { key: "servers", icon: "dns", label: `Serveurs (${servers.length})` },
          { key: "map", icon: "hub", label: "Cartographie d'attaque" },
        ] as const).map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-headline font-semibold transition-colors ${
              tab === t.key ? "bg-primary text-on-primary shadow-sm" : "text-on-surface-variant hover:text-on-surface"
            }`}
          >
            <span className="material-symbols-outlined text-sm">{t.icon}</span>
            {t.label}
          </button>
        ))}
      </nav>

      {tab === "overview" && (
        <div className="space-y-6">
          <ProjectOverviewDashboard
            repos={repos}
            servers={servers}
            scans={scans}
            readiness={readiness}
            deadline={client.releaseDeadline}
            domainName={client.domainName}
            sslGrade={latestSslScan ? latestSslGrade : null}
            sslScannedAt={latestSslScan ? (latestSslScan.finishedAt || latestSslScan.startedAt) : null}
            certExpiresOn={latestSslScan ? sslCert?.expiresOn : null}
            certExpired={latestSslScan ? sslCert?.expired : false}
            certDaysLeft={latestSslScan ? sslCert?.daysLeft : null}
            sslAlertDate={client.sslAlertDate}
            sslAlertError={sslAlertError}
            roles={Object.fromEntries((client.repositoryRoles ?? []).map((item) => [item.repositoryId, item.role])) as Partial<Record<number, SolutionRole>>}
            roleError={roleError}
            onRoleChange={saveRole}
            onSslAlertDate={(date) => {
              setSslAlertError(null);
              setClientSslAlert(client.id, date)
                .then((res) => setClient(res.data))
                .catch((err: { response?: { status?: number; data?: { message?: string; error?: string } } }) => {
                  const detail = err?.response?.data?.message || err?.response?.data?.error;
                  const status = err?.response?.status;
                  setSslAlertError(detail || (status ? `Enregistrement refusé (${status}).` : "Impossible d'enregistrer la date d'alerte."));
                });
            }}
            onOpenServers={() => setTab("servers")}
            onOpenBlockers={openBlockers}
            onOpenRepos={() => setTab("repos")}
            onOpenSsl={() => setTab("domain")}
          />
          <CiOverviewCard clientId={client.id} onOpenCi={() => setTab("ci")} />
          <ReleaseReadinessPanel
            readiness={readiness}
            loading={loading}
            listOpen={blockersOpen}
            onListOpenChange={setBlockersOpen}
          />
        </div>
      )}

      {tab === "domain" && (
        <section className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <nav className="flex flex-wrap gap-1 rounded-2xl bg-surface-container-high p-1 w-fit">
                <span className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-headline font-semibold bg-primary text-on-primary shadow-sm">
                  <span className="material-symbols-outlined text-sm">language</span>
                  {client.domainName?.trim() || "Aucun domaine"}
                </span>
              </nav>
              {sslScans.length > 0 && (
                <nav className="flex flex-wrap gap-1 rounded-2xl bg-surface-container-high p-1 w-fit">
                  {sslScans.map((scan) => {
                    const active = scan.id === (activeSslScan?.id ?? null);
                    return (
                      <button
                        key={scan.id}
                        type="button"
                        onClick={() => setSelectedSslScanId(scan.id)}
                        className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-headline font-semibold transition-colors ${
                          active ? "bg-primary text-on-primary shadow-sm" : "text-on-surface-variant hover:text-on-surface"
                        }`}
                      >
                        <span className="material-symbols-outlined text-sm">verified_user</span>
                        {timeAgo(scan.finishedAt || scan.startedAt)}
                        {scan.id === latestSslScan?.id && latestSslGrade ? ` · ${latestSslGrade}` : ""}
                      </button>
                    );
                  })}
                </nav>
              )}
            </div>
            {client.domainName?.trim() && (
              <button
                onClick={handleOpenSslSchedule}
                className="flex items-center gap-2 px-4 py-2 rounded-xl border border-violet-500/30 bg-violet-500/10 text-violet-300 font-headline font-bold text-xs hover:bg-violet-500/20 hover:border-violet-500/50 hover:shadow-[0_0_14px_rgba(167,139,250,0.25)] transition-all active:scale-95 whitespace-nowrap"
              >
                <span className="material-symbols-outlined text-sm" style={{ fontVariationSettings: "'FILL' 1" }}>calendar_clock</span>
                Planifier scan SSL
              </button>
            )}
          </div>
          {activeSslScan?.status === "COMPLETED" ? (
            <SSLAnalysis
              key={activeSslScan.id}
              embeddedScanId={activeSslScan.id}
              initialDomain={client.domainName ?? undefined}
            />
          ) : (
            <div className="text-center py-12 text-outline">
              <span className="material-symbols-outlined text-4xl mb-2 block">verified_user</span>
              <p className="text-sm">
                {client.domainName?.trim()
                  ? "Aucun scan SSL terminé pour ce domaine."
                  : "Ce projet n'a pas de domaine."}
              </p>
            </div>
          )}
        </section>
      )}

      {tab === "servers" && (
        <ProjectServersPanel
          clientId={client.id}
          servers={servers}
          repos={repos}
          roles={Object.fromEntries((client.repositoryRoles ?? []).map((item) => [item.repositoryId, item.role])) as Partial<Record<number, SolutionRole>>}
          canLinkExisting={hasPermission("SERVER_CONFIG")}
          onChange={loadData}
        />
      )}

      {tab === "ci" && <ProjectCiPanel clientId={client.id} />}

      {tab === "map" && (
        <AttackGraph
          clientId={client.id}
          onOpenServers={() => setTab("servers")}
          kevCves={(readiness?.priorities ?? []).filter((item) => item.kevListed).slice(0, 5)}
        />
      )}

      {tab === "repos" && (
        <>

      {/* ── Repos section ──────────────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-bold font-headline uppercase tracking-widest text-outline mb-4 flex items-center gap-2">
          <span className="material-symbols-outlined text-base">
            code_blocks
          </span>
          Dépôts liés ({repos.length})
        </h2>
        <AddProjectRepoPanel
          clientId={client.id}
          linkedIds={repos.map((r) => r.id)}
          onAdded={loadData}
        />

        {repos.length === 0 ? (
          <div className="text-center py-12 text-outline">
            <span className="material-symbols-outlined text-4xl mb-2 block">
              link_off
            </span>
            <p className="text-sm">Aucun dépôt lié à ce projet.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {repos.map((repo) => {
              const sched = scheduledSummary[String(repo.id)];
              const hasActiveSched =
                sched && ["ACTIVE", "RUNNING", "PAUSED"].includes(sched.status);
              const isScanning = scanning === repo.id;
              const repoScans = scans.filter(
                (s) => s.repoId === repo.id && s.status === "COMPLETED" && s.scanMode !== "ssl-only",
              );
              const latestRepoScan = repoScans[0];
              const role = (client.repositoryRoles ?? []).find((item) => item.repositoryId === repo.id)?.role ?? "OTHER";
              const severity = latestRepoScan && severityByScan ? severityByScan[latestRepoScan.id] : undefined;
              const openLatest = () => {
                if (!latestRepoScan) return;
                navigate(`/vulnerabilities?scanId=${latestRepoScan.id}&repoId=${latestRepoScan.repoId}`);
              };

              return (
                <div
                  key={repo.id}
                  className="rounded-xl border border-outline-variant/[0.15] bg-surface-container p-4 space-y-3"
                >
                  {/* Name */}
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-sm text-outline">
                      folder_open
                    </span>
                    <span className="font-headline font-semibold text-sm text-on-surface truncate">
                      {repoShortName(repo.repoUrl)}
                    </span>
                    <span
                      className={`ml-auto shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                        pulse.deployedIds.has(repo.id)
                          ? "bg-tertiary/15 text-tertiary"
                          : "bg-amber-500/15 text-amber-300"
                      }`}
                    >
                      {pulse.deployedIds.has(repo.id) ? "Sur un serveur" : "Sans serveur"}
                    </span>
                  </div>

                  {/* Repo URL */}
                  <p
                    className="text-[10px] text-outline truncate"
                    title={repo.repoUrl}
                  >
                    {repo.repoUrl}
                  </p>

                  <label className="flex items-center gap-2 text-[10px] text-outline">
                    Rôle
                    <select
                      aria-label={`Rôle de ${repoShortName(repo.repoUrl)}`}
                      value={role}
                      onChange={(event) => saveRole(repo.id, event.target.value as SolutionRole)}
                      className="rounded-lg border border-outline-variant/30 bg-surface-container-high px-2 py-1 text-xs text-on-surface [color-scheme:dark]"
                    >
                      {SOLUTION_ROLES.map((item) => (
                        <option key={item.role} value={item.role}>{item.label}</option>
                      ))}
                    </select>
                  </label>

                  {latestRepoScan ? (
                    <>
                      <button
                        onClick={openLatest}
                        className="flex items-center gap-1.5 text-[10px] text-tertiary hover:text-tertiary/80 transition-colors"
                      >
                        <span className="material-symbols-outlined text-[11px]">
                          check_circle
                        </span>
                        {latestRepoScan.cveCount} CVEs ·{" "}
                        {timeAgo(latestRepoScan.finishedAt)}
                      </button>
                      {severityByScan && (
                        <button
                          type="button"
                          onClick={openLatest}
                          className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] font-semibold"
                        >
                          <span className={severity && severity.critical > 0 ? "text-error" : "text-on-surface-variant"}>
                            {countLabel(severity?.critical ?? 0, "critique", "critiques")}
                          </span>
                          <span className={severity && severity.high > 0 ? "text-amber-300" : "text-on-surface-variant"}>
                            {countLabel(severity?.high ?? 0, "élevée", "élevées")}
                          </span>
                          <span className={severity && severity.kev > 0 ? "text-error" : "text-on-surface-variant"}>
                            {countLabel(severity?.kev ?? 0, "KEV", "KEV")}
                          </span>
                        </button>
                      )}
                    </>
                  ) : (
                    <p className="text-[10px] text-outline">Aucun scan terminé</p>
                  )}

                  {/* Schedule badge */}
                  {hasActiveSched && (
                    <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-violet-500/10 border border-violet-500/20">
                      <span className="material-symbols-outlined text-[11px] text-violet-400">
                        schedule
                      </span>
                      <span className="text-[10px] text-violet-300 font-medium">
                        {sched.status === "PAUSED" ? "Pausé" : "Planifié"} ·{" "}
                        {formatNextRun(sched.nextRunAt)}
                      </span>
                    </div>
                  )}

                  {/* Buttons */}
                  <div className="flex gap-2 pt-1">
                    {/* Scan */}
                    <button
                      onClick={() => handleScan(repo)}
                      disabled={isScanning || scanning !== null}
                      className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-semibold border bg-primary/10 text-primary border-primary/20 hover:bg-primary hover:text-on-primary hover:shadow-[0_0_16px_rgba(0,209,255,0.3)] disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                    >
                      <span className="material-symbols-outlined text-sm">
                        {isScanning ? "progress_activity" : "radar"}
                      </span>
                      {isScanning ? "Scan..." : "Scanner"}
                    </button>
                    {/* Schedule */}
                    <button
                      onClick={() => openScheduleModal(repo)}
                      title="Planifier un scan"
                      className="flex items-center justify-center px-3 py-2 rounded-lg text-xs border border-violet-500/25 text-violet-400 hover:bg-violet-500/10 hover:border-violet-500/50 transition-all"
                    >
                      <span className="material-symbols-outlined text-sm">
                        calendar_clock
                      </span>
                    </button>
                    {/* Open results */}
                    {latestRepoScan && (
                      <button
                        onClick={openLatest}
                        title="Voir les résultats"
                        className="flex items-center justify-center px-3 py-2 rounded-lg text-xs border border-outline-variant/[0.2] text-outline hover:text-on-surface hover:border-outline-variant/50 transition-all"
                      >
                        <span className="material-symbols-outlined text-sm">
                          open_in_new
                        </span>
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* ── Live log terminal ──────────────────────────────────────────────── */}
      {(scanning !== null || logs.length > 0) && (
        <section className="glass-panel rounded-t-2xl border-t border-x border-outline-variant/[0.15] overflow-hidden">
          <div className="bg-surface-container-highest/50 px-6 py-3 flex items-center justify-between border-b border-outline-variant/[0.1]">
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5">
                <span className="w-3 h-3 rounded-full bg-error/70"></span>
                <span className="w-3 h-3 rounded-full bg-[#FFBD2E]/70"></span>
                <span className="w-3 h-3 rounded-full bg-tertiary/70"></span>
              </div>
              <span className="text-[10px] font-mono text-outline ml-2">
                {repos.find((r) => r.id === scanning)
                  ? repoShortName(repos.find((r) => r.id === scanning)!.repoUrl)
                  : "terminal"}
              </span>
            </div>
            <div className="flex items-center gap-3">
              {scanning !== null && (
                <button
                  onClick={handleStopScan}
                  className="flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-mono font-semibold bg-error/10 text-error border border-error/30 hover:bg-error/20 transition-all"
                >
                  <span className="material-symbols-outlined text-xs">
                    stop_circle
                  </span>
                  Arrêter
                </button>
              )}
              <span className="text-[10px] font-mono text-tertiary flex items-center gap-1.5">
                {scanning !== null ? (
                  <>
                    <span className="w-1.5 h-1.5 bg-tertiary rounded-full animate-pulse"></span>{" "}
                    Scan en cours...
                  </>
                ) : (
                  <>
                    <span className="w-1.5 h-1.5 bg-tertiary rounded-full"></span>{" "}
                    Terminé
                  </>
                )}
              </span>
            </div>
          </div>
          <div className="p-6 font-mono text-xs leading-relaxed h-48 overflow-y-auto bg-surface-container-lowest/80 custom-scrollbar">
            {logs.map((log, i) => (
              <div key={i} className="flex gap-4 mb-1">
                <span className="text-outline opacity-40 shrink-0">
                  {log.time}
                </span>
                {log.prefix && (
                  <span className={`${prefixColor(log.prefix)} shrink-0`}>
                    {log.prefix}
                  </span>
                )}
                <span className="text-on-surface-variant break-all">
                  {log.text}
                </span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </section>
      )}

      {/* ── Scan history ───────────────────────────────────────────────────── */}
      <section>
        <div className="flex items-center justify-between gap-4 mb-4">
          <h2 className="text-sm font-bold font-headline uppercase tracking-widest text-outline flex items-center gap-2">
            <span className="material-symbols-outlined text-base">history</span>
            Historique des scans ({cveScans.length})
          </h2>
        </div>

        {cveScans.some((scan) => scan.status === "RUNNING") && (
          <div className="mb-4 flex items-center gap-2 px-4 py-2.5 rounded-xl bg-primary/10 border border-primary/20 text-primary text-sm">
            <span className="material-symbols-outlined text-base animate-spin">
              progress_activity
            </span>
            {cveScans.filter((scan) => scan.status === "RUNNING").length} scan(s) en cours sur ce projet
          </div>
        )}

        {cveScans.length === 0 ? (
            <div className="text-center py-12 text-outline">
              <span className="material-symbols-outlined text-4xl mb-2 block">
                radar
              </span>
              <p className="text-sm">Aucun scan CVE effectué sur ce projet.</p>
            </div>
          ) : (
            <div className="glass-panel rounded-2xl border border-outline-variant/[0.1] overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-outline-variant/[0.1] bg-surface-container-highest/30">
                    <th className="px-4 py-3 font-headline font-semibold text-outline uppercase tracking-wider">
                      Dépôt
                    </th>
                    <th className="px-4 py-3 font-headline font-semibold text-outline uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-4 py-3 font-headline font-semibold text-outline uppercase tracking-wider">
                      CVEs
                    </th>
                    <th className="px-4 py-3 font-headline font-semibold text-outline uppercase tracking-wider">
                      Mode
                    </th>
                    <th className="px-4 py-3 font-headline font-semibold text-outline uppercase tracking-wider">
                      Date
                    </th>
                    <th className="px-4 py-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {cveScans.slice(0, 20).map((scan) => (
                    <tr
                      key={scan.id}
                      onClick={() => {
                        if (scan.status === "COMPLETED") {
                          navigate(`/vulnerabilities?scanId=${scan.id}&repoId=${scan.repoId}`);
                        }
                      }}
                      className={`border-b border-outline-variant/[0.06] transition-colors ${scan.status === "COMPLETED" ? "hover:bg-primary/5 cursor-pointer" : ""}`}
                    >
                      <td className="px-4 py-3">
                        <span className="font-medium text-on-surface">
                          {repoShortName(scan.repoUrl ?? "")}
                        </span>
                        <span className="text-outline ml-1.5 text-[10px]">
                          #{scan.id}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold border ${
                            scan.status === "COMPLETED"
                              ? "bg-tertiary/10 text-tertiary border-tertiary/20"
                              : scan.status === "RUNNING"
                                ? "bg-primary/10 text-primary border-primary/20"
                                : "bg-error/10 text-error border-error/20"
                          }`}
                        >
                          <span
                            className={`material-symbols-outlined text-[10px] ${scan.status === "RUNNING" ? "animate-spin" : ""}`}
                          >
                            {scan.status === "COMPLETED"
                              ? "check_circle"
                              : scan.status === "RUNNING"
                                ? "progress_activity"
                                : "error"}
                          </span>
                          {scan.status}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {scan.status === "COMPLETED" ? (
                          <span
                            className={`font-bold ${scan.cveCount > 0 ? "text-error" : "text-tertiary"}`}
                          >
                            {scan.cveCount}
                          </span>
                        ) : (
                          <span className="text-outline">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-outline">
                        {scan.scanMode || "auto"}
                      </td>
                      <td className="px-4 py-3 text-outline">
                        {timeAgo(scan.finishedAt || scan.startedAt)}
                      </td>
                      <td className="px-4 py-3">
                        {scan.status === "COMPLETED" && (
                          <span className="material-symbols-outlined text-outline text-sm">
                            arrow_forward
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </section>

        </>
      )}

      {/* ════════════════════ SCHEDULE MODAL ════════════════════ */}
      {scheduleModalOpen && scheduleModalRepo && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          onClick={closeScheduleModal}
        >
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
          <div
            className="relative z-10 w-full max-w-lg bg-surface-container rounded-2xl border border-outline-variant/[0.2] shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 bg-surface-container-highest/50 border-b border-outline-variant/[0.1]">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-violet-400 text-lg">
                  calendar_clock
                </span>
                <div>
                  <h2 className="font-headline font-bold text-on-surface text-sm">
                    Planifier un scan
                  </h2>
                  <p className="text-[11px] text-outline">
                    {client.name} / {repoShortName(scheduleModalRepo.repoUrl)}
                  </p>
                </div>
              </div>
              <button
                onClick={closeScheduleModal}
                className="text-outline hover:text-on-surface transition-colors"
              >
                <span className="material-symbols-outlined text-lg">close</span>
              </button>
            </div>

            <div className="p-5 space-y-4 max-h-[75vh] overflow-y-auto custom-scrollbar">
              {/* Date + Heure */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[10px] text-outline mb-1">
                    Date
                  </label>
                  <input
                    type="date"
                    className="w-full bg-surface-container-low border border-outline-variant/[0.2] rounded-lg px-3 py-2 text-sm text-on-surface focus:ring-1 focus:ring-violet-500 focus:border-violet-500/50 [color-scheme:dark] cursor-pointer"
                    value={scheduleDate}
                    onChange={(e) => setScheduleDate(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-outline mb-1">
                    Heure
                  </label>
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <select
                        className="w-full bg-surface-container-low border border-outline-variant/[0.2] rounded-lg px-3 py-2 pr-7 text-sm text-on-surface focus:ring-1 focus:ring-violet-500 appearance-none cursor-pointer [color-scheme:dark]"
                        value={scheduleHour}
                        onChange={(e) => setScheduleHour(e.target.value)}
                      >
                        {Array.from({ length: 24 }, (_, i) =>
                          String(i).padStart(2, "0"),
                        ).map((h) => (
                          <option key={h} value={h}>
                            {h}h
                          </option>
                        ))}
                      </select>
                      <span className="material-symbols-outlined absolute right-1.5 top-1/2 -translate-y-1/2 text-outline text-[14px] pointer-events-none">
                        expand_more
                      </span>
                    </div>
                    <div className="relative flex-1">
                      <select
                        className="w-full bg-surface-container-low border border-outline-variant/[0.2] rounded-lg px-3 py-2 pr-7 text-sm text-on-surface focus:ring-1 focus:ring-violet-500 appearance-none cursor-pointer [color-scheme:dark]"
                        value={scheduleMinute}
                        onChange={(e) => setScheduleMinute(e.target.value)}
                      >
                        {[
                          "00",
                          "05",
                          "10",
                          "15",
                          "20",
                          "25",
                          "30",
                          "35",
                          "40",
                          "45",
                          "50",
                          "55",
                        ].map((m) => (
                          <option key={m} value={m}>
                            :{m}
                          </option>
                        ))}
                      </select>
                      <span className="material-symbols-outlined absolute right-1.5 top-1/2 -translate-y-1/2 text-outline text-[14px] pointer-events-none">
                        expand_more
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Fréquence */}
              <div>
                <label className="block text-[10px] text-outline mb-2">
                  Fréquence
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {(
                    ["ONCE", "WEEKLY", "EVERY_15_DAYS", "MONTHLY"] as const
                  ).map((f) => (
                    <button
                      key={f}
                      onClick={() => setScheduleFrequency(f)}
                      className={`py-2 px-3 rounded-lg text-xs font-medium border transition-all ${
                        scheduleFrequency === f
                          ? "bg-violet-500/20 border-violet-500/50 text-violet-300"
                          : "bg-surface-container-low border-outline-variant/[0.15] text-outline hover:border-violet-500/30 hover:text-violet-400"
                      }`}
                    >
                      {scheduleTypeLabel[f]}
                    </button>
                  ))}
                </div>
              </div>

              {/* Mode */}
              <div>
                <label className="block text-[10px] text-outline mb-1">
                  Mode de scan
                </label>
                <div className="relative">
                  <select
                    className="w-full bg-surface-container-low border border-outline-variant/[0.2] rounded-lg px-3 py-2 pr-7 text-sm text-on-surface focus:ring-1 focus:ring-violet-500 appearance-none cursor-pointer [color-scheme:dark]"
                    value={scheduleScanMode}
                    onChange={(e) => setScheduleScanMode(e.target.value)}
                  >
                    <option value="auto">Auto</option>
                    <option value="full">Full Scan</option>
                    <option value="java">Java</option>
                    <option value="nodejs">Node.js</option>
                    <option value="python">Python</option>
                  </select>
                  <span className="material-symbols-outlined absolute right-1.5 top-1/2 -translate-y-1/2 text-outline text-[14px] pointer-events-none">
                    expand_more
                  </span>
                </div>
              </div>

              {/* Messages */}
              {scheduleError && (
                <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-error/10 border border-error/20 text-xs text-error">
                  <span className="material-symbols-outlined text-sm shrink-0">
                    error
                  </span>
                  <span>{scheduleError}</span>
                </div>
              )}
              {scheduleSuccess && (
                <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-tertiary/10 border border-tertiary/20 text-xs text-tertiary">
                  <span className="material-symbols-outlined text-sm shrink-0">
                    check_circle
                  </span>
                  <span>{scheduleSuccess}</span>
                </div>
              )}

              {/* Confirm button */}
              <button
                onClick={handleCreateSchedule}
                disabled={scheduleSubmitting}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold bg-violet-500/20 text-violet-300 border border-violet-500/40 hover:bg-violet-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                <span className="material-symbols-outlined text-sm">
                  {scheduleSubmitting ? "progress_activity" : "add_circle"}
                </span>
                {scheduleSubmitting
                  ? "Planification..."
                  : "Confirmer la planification"}
              </button>

              {/* Existing schedules */}
              {existingSchedules.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-[10px] font-bold text-outline uppercase tracking-widest">
                    Planifications existantes
                  </h3>
                  {existingSchedules.map((sched) => (
                    <div
                      key={sched.id}
                      className="flex items-start justify-between gap-3 px-3 py-2.5 rounded-lg bg-surface-container-low border border-outline-variant/[0.12]"
                    >
                      <div className="space-y-0.5 min-w-0">
                        <div className="flex items-center gap-2">
                          <span
                            className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                              sched.status === "ACTIVE"
                                ? "bg-tertiary/15 text-tertiary"
                                : sched.status === "PAUSED"
                                  ? "bg-outline/15 text-outline"
                                  : sched.status === "RUNNING"
                                    ? "bg-primary/15 text-primary"
                                    : "bg-error/15 text-error"
                            }`}
                          >
                            {scheduleStatusLabel[sched.status] || sched.status}
                          </span>
                          <span className="text-[11px] text-on-surface-variant font-medium">
                            {scheduleTypeLabel[sched.scheduleType]}
                          </span>
                        </div>
                        <p className="text-[10px] text-outline">
                          {sched.status === "COMPLETED"
                            ? "Terminé"
                            : `Prochain : ${formatNextRun(sched.nextRunAt)}`}
                        </p>
                        {sched.lastError && (
                          <p
                            className="text-[10px] text-error truncate"
                            title={sched.lastError}
                          >
                            {sched.lastError}
                          </p>
                        )}
                      </div>
                      <div className="flex gap-1 shrink-0">
                        {sched.status === "ACTIVE" && (
                          <button
                            onClick={() => handlePause(sched.id)}
                            title="Pause"
                            className="p-1.5 rounded text-outline hover:text-amber-400 hover:bg-amber-500/10 transition-all"
                          >
                            <span className="material-symbols-outlined text-sm">
                              pause
                            </span>
                          </button>
                        )}
                        {sched.status === "PAUSED" && (
                          <button
                            onClick={() => handleResume(sched.id)}
                            title="Reprendre"
                            className="p-1.5 rounded text-outline hover:text-tertiary hover:bg-tertiary/10 transition-all"
                          >
                            <span className="material-symbols-outlined text-sm">
                              play_arrow
                            </span>
                          </button>
                        )}
                        <button
                          onClick={() => handleDeleteSched(sched.id)}
                          title="Supprimer"
                          className="p-1.5 rounded text-outline hover:text-error hover:bg-error/10 transition-all"
                        >
                          <span className="material-symbols-outlined text-sm">
                            delete
                          </span>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
      {/* ── SSL Schedule Modal ──────────────────────────────────────────────── */}
      <SSLScheduleModal
        domain={client?.domainName ?? ''}
        open={sslScheduleOpen}
        scheduleDate={sslScheduleDate}
        scheduleHour={sslScheduleHour}
        scheduleMinute={sslScheduleMinute}
        scheduleFrequency={sslScheduleFrequency}
        scheduleSubmitting={sslScheduleSubmitting}
        scheduleError={sslScheduleError}
        scheduleSuccess={sslScheduleSuccess}
        onClose={() => setSslScheduleOpen(false)}
        onDateChange={setSslScheduleDate}
        onHourChange={setSslScheduleHour}
        onMinuteChange={setSslScheduleMinute}
        onFrequencyChange={setSslScheduleFrequency}
        onSubmit={handleCreateSslSchedule}
      />
    </div>
  );
};

const ProjectDetailSkeleton: React.FC = () => (
  <div className="space-y-8" aria-hidden="true">
    <div className="space-y-3 animate-pulse">
      <div className="h-4 w-24 rounded bg-surface-container-high" />
      <div className="h-10 w-64 rounded-xl bg-surface-container-high" />
      <div className="h-4 w-96 max-w-full rounded bg-surface-container-high" />
    </div>
    <div className="h-10 w-full max-w-xl rounded-2xl bg-surface-container-high animate-pulse" />
    <div className="grid gap-3 lg:grid-cols-[minmax(16rem,0.9fr)_minmax(0,1.4fr)]">
      <div className="h-36 rounded-2xl bg-surface-container animate-pulse" />
      <div className="grid grid-cols-3 gap-3">
        <div className="h-36 rounded-2xl bg-surface-container animate-pulse" />
        <div className="h-36 rounded-2xl bg-surface-container animate-pulse" />
        <div className="h-36 rounded-2xl bg-surface-container animate-pulse" />
      </div>
    </div>
  </div>
);

export default ProjectDetailPage;
