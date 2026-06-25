import React, { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  getClient,
  getRepositories,
  getAllScans,
  startScan,
  getScheduledSummary,
  getRepositoryScheduledScans,
  createScheduledScan,
  pauseScheduledScan,
  resumeScheduledScan,
  deleteScheduledScan,
  type ClientDto,
  type RepositoryDto,
  type ScanResultDto,
  type ScheduledScan,
  type ScheduleType,
} from "../services/api";

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

  // Data
  const [client, setClient] = useState<ClientDto | null>(null);
  const [repos, setRepos] = useState<RepositoryDto[]>([]);
  const [scans, setScans] = useState<ScanResultDto[]>([]);
  const [scheduledSummary, setScheduledSummary] = useState<
    Record<string, ScheduledScan>
  >({});
  const [loading, setLoading] = useState(true);

  // Scan
  const [scanning, setScanning] = useState<number | null>(null); // repo.id
  const [logs, setLogs] = useState<LogLine[]>([]);
  const evtSourceRef = useRef<EventSource | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

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
    setLoading(true);
    try {
      const [clientRes, reposRes, scansRes, summaryRes] = await Promise.all([
        getClient(Number(id)),
        getRepositories(),
        getAllScans(),
        getScheduledSummary(),
      ]);
      const c = clientRes.data;
      setClient(c);
      setRepos(
        reposRes.data.filter((r) => (c.repositoryIds ?? []).includes(r.id)),
      );
      setScans(scansRes.data.filter((s) => (s.clientIds ?? []).includes(c.id)));
      setScheduledSummary(summaryRes.data);
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadData();
  }, [loadData]);
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // ── Scan handler ───────────────────────────────────────────────────────────

  const handleScan = async (repo: RepositoryDto) => {
    setScanning(repo.id);
    setLogs([]);
    try {
      const { data } = await startScan({
        repoUrl: repo.repoUrl,
        scanMode: "auto",
      });
      const token = localStorage.getItem("vulnix_token") ?? "";
      const evtSource = new EventSource(
        `http://localhost:8080/api/scans/${data.scanId}/logs?token=${encodeURIComponent(token)}`,
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

  const runningScans = scans.filter((s) => s.status === "RUNNING");

  // ── Loading ───────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <span className="material-symbols-outlined text-5xl text-primary animate-spin">
          progress_activity
        </span>
      </div>
    );
  }

  if (!client) {
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
          Projects
        </button>
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center">
            <span className="material-symbols-outlined text-primary text-2xl">
              folder_special
            </span>
          </div>
          <div>
            <h1 className="font-headline text-3xl font-bold text-on-surface">
              {client.name}
            </h1>
            <p className="text-sm text-outline">
              {client.company && <>{client.company} · </>}
              {repos.length} repo(s) · {scans.length} scan(s)
            </p>
          </div>
        </div>
      </header>

      {/* ── Repos section ──────────────────────────────────────────────────── */}
      <section>
        <h2 className="text-sm font-bold font-headline uppercase tracking-widest text-outline mb-4 flex items-center gap-2">
          <span className="material-symbols-outlined text-base">
            code_blocks
          </span>
          Dépôts liés ({repos.length})
        </h2>

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
                (s) => s.repoId === repo.id && s.status === "COMPLETED",
              );
              const latestRepoScan = repoScans[0];

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
                  </div>

                  {/* Repo URL */}
                  <p
                    className="text-[10px] text-outline truncate"
                    title={repo.repoUrl}
                  >
                    {repo.repoUrl}
                  </p>

                  {/* Latest scan badge */}
                  {latestRepoScan && (
                    <button
                      onClick={() =>
                        navigate(
                          `/vulnerabilities?scanId=${latestRepoScan.id}&repoId=${latestRepoScan.repoId}`,
                        )
                      }
                      className="flex items-center gap-1.5 text-[10px] text-tertiary hover:text-tertiary/80 transition-colors"
                    >
                      <span className="material-symbols-outlined text-[11px]">
                        check_circle
                      </span>
                      {latestRepoScan.cveCount} CVEs ·{" "}
                      {timeAgo(latestRepoScan.finishedAt)}
                    </button>
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
                        onClick={() =>
                          navigate(
                            `/vulnerabilities?scanId=${latestRepoScan.id}&repoId=${latestRepoScan.repoId}`,
                          )
                        }
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
        <h2 className="text-sm font-bold font-headline uppercase tracking-widest text-outline mb-4 flex items-center gap-2">
          <span className="material-symbols-outlined text-base">history</span>
          Historique des scans ({scans.length})
        </h2>

        {runningScans.length > 0 && (
          <div className="mb-4 flex items-center gap-2 px-4 py-2.5 rounded-xl bg-primary/10 border border-primary/20 text-primary text-sm">
            <span className="material-symbols-outlined text-base animate-spin">
              progress_activity
            </span>
            {runningScans.length} scan(s) en cours sur ce projet
          </div>
        )}

        {scans.length === 0 ? (
          <div className="text-center py-12 text-outline">
            <span className="material-symbols-outlined text-4xl mb-2 block">
              radar
            </span>
            <p className="text-sm">Aucun scan effectué sur ce projet.</p>
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
                {scans.slice(0, 20).map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() =>
                      scan.status === "COMPLETED" &&
                      navigate(
                        `/vulnerabilities?scanId=${scan.id}&repoId=${scan.repoId}`,
                      )
                    }
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
    </div>
  );
};

export default ProjectDetailPage;
