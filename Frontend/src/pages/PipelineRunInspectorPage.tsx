import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  approvePipelineRun,
  getPipeline,
  getPipelineRuns,
  getPipelineRunLogsStreamUrl,
  runPipeline,
  type PipelineDefinitionDto,
  type PipelineLogEventDto,
  type PipelineRunDto,
} from '../services/api';

// ── Helpers ───────────────────────────────────────────────────────────────────

const extractApiError = (error: any, fallback: string) =>
  error?.response?.data?.message || error?.response?.data?.error || error?.message || fallback;

const formatStageName = (value?: string | null) =>
  (value ?? '')
    .split('_')
    .filter(Boolean)
    .map((chunk) => chunk.charAt(0) + chunk.slice(1).toLowerCase())
    .join(' ');

const formatDateTime = (value?: string | null) => {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString('fr-FR');
  } catch {
    return value;
  }
};

const formatRelative = (value?: string | null) => {
  if (!value) return 'jamais';
  const now = Date.now();
  const diffMinutes = Math.max(0, Math.round((now - new Date(value).getTime()) / 60000));
  if (diffMinutes < 1) return "à l'instant";
  if (diffMinutes < 60) return `il y a ${diffMinutes} min`;
  const diffHours = Math.round(diffMinutes / 60);
  if (diffHours < 24) return `il y a ${diffHours} h`;
  const diffDays = Math.round(diffHours / 24);
  return `il y a ${diffDays} j`;
};

const appendText = (existing?: string | null, line?: string | null) => {
  if (!line?.trim()) return existing ?? null;
  if (!existing?.trim()) return line;
  return `${existing}\n${line}`;
};

const sortRuns = (items: PipelineRunDto[]) =>
  [...items].sort((left, right) => {
    const rightTime = right.startedAt ? new Date(right.startedAt).getTime() : 0;
    const leftTime = left.startedAt ? new Date(left.startedAt).getTime() : 0;
    return rightTime - leftTime || right.id - left.id;
  });

const mergeRun = (runs: PipelineRunDto[], nextRun: PipelineRunDto) =>
  sortRuns([nextRun, ...runs.filter((run) => run.id !== nextRun.id)]);

const appendLogEventToRuns = (runs: PipelineRunDto[], event: PipelineLogEventDto) =>
  runs.map((run) => {
    if (run.id !== event.runId) return run;

    const stageMatcher =
      (stageId?: number | null, stageType?: string | null) =>
      (stage: PipelineRunDto['stages'][number]) =>
        (stageId ? stage.id === stageId : false) ||
        (!!stageType && stage.stageType === stageType);

    const nextStages = run.stages.map((stage) =>
      stageMatcher(event.stageId, event.stageType)(stage)
        ? {
            ...stage,
            details: stage.details ?? event.message ?? null,
            logOutput: appendText(stage.logOutput, event.message),
          }
        : stage,
    );

    return { ...run, summary: event.message ?? run.summary, stages: nextStages };
  });

// ── Constants ─────────────────────────────────────────────────────────────────

const statusClasses: Record<string, string> = {
  SUCCESS: 'border-tertiary/30 bg-tertiary/10 text-tertiary',
  RUNNING: 'border-primary/30 bg-primary/10 text-primary',
  FAILED: 'border-error/30 bg-error/10 text-error',
  BLOCKED: 'border-error/30 bg-error/10 text-error',
  SKIPPED: 'border-outline-variant/30 bg-surface-container-high text-outline',
  AWAITING_APPROVAL: 'border-secondary/30 bg-secondary/10 text-secondary',
  PENDING: 'border-outline-variant/30 bg-surface-container text-outline',
};

const stageIcon: Record<string, string> = {
  SOURCE: 'source_environment',
  BUILD: 'deployed_code',
  TEST: 'biotech',
  SECURITY_SCAN: 'security',
  QUALITY_GATE: 'shield_lock',
  DOCKER_BUILD: 'inventory_2',
  CONTAINER_SCAN: 'rule_folder',
  DEPLOY_STAGING: 'rocket_launch',
  DAST_SCAN: 'web_traffic',
  APPROVAL: 'fact_check',
  DEPLOY_PRODUCTION: 'cloud_upload',
};

const streamStatusClasses: Record<string, string> = {
  idle: 'border-outline-variant/30 bg-surface-container text-outline',
  connecting: 'border-secondary/30 bg-secondary/10 text-secondary',
  live: 'border-tertiary/30 bg-tertiary/10 text-tertiary',
  closed: 'border-outline-variant/30 bg-surface-container text-outline',
};

// ── Component ─────────────────────────────────────────────────────────────────

const PipelineRunInspectorPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const pipelineId = Number(id);

  const [pipeline, setPipeline] = useState<PipelineDefinitionDto | null>(null);
  const [runs, setRuns] = useState<PipelineRunDto[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [streamState, setStreamState] = useState<'idle' | 'connecting' | 'live' | 'closed'>('idle');
  const [busyRun, setBusyRun] = useState(false);
  const [approvingRunId, setApprovingRunId] = useState<number | null>(null);

  const selectedRun = runs.find((run) => run.id === selectedRunId) ?? runs[0] ?? null;

  const aggregatedLogs = useMemo(() => {
    if (!selectedRun) return 'Sélectionne un run pour consulter les logs consolidés.';
    const blocks = selectedRun.stages
      .filter((stage) => stage.details || stage.logOutput)
      .map((stage) => {
        const header = `[${formatStageName(stage.stageType)}] ${stage.status}`;
        const body = [stage.details, stage.logOutput].filter(Boolean).join('\n');
        return `${header}\n${body}`.trim();
      });
    return blocks.length ? blocks.join('\n\n') : 'Aucun log détaillé disponible pour ce run.';
  }, [selectedRun]);

  const loadData = useCallback(async () => {
    if (!pipelineId) return;
    setLoading(true);
    setError(null);
    try {
      const [pipelineRes, runsRes] = await Promise.all([
        getPipeline(pipelineId),
        getPipelineRuns(pipelineId),
      ]);
      setPipeline(pipelineRes.data);
      const sorted = sortRuns(runsRes.data);
      setRuns(sorted);
      setSelectedRunId(sorted[0]?.id ?? null);
    } catch (err) {
      setError(extractApiError(err, 'Impossible de charger le pipeline.'));
    } finally {
      setLoading(false);
    }
  }, [pipelineId]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  // SSE live logs
  useEffect(() => {
    if (!selectedRunId) {
      setStreamState('idle');
      return undefined;
    }
    const token = localStorage.getItem('vulnix_token');
    const streamUrl = getPipelineRunLogsStreamUrl(selectedRunId, token);
    const source = new EventSource(streamUrl);
    setStreamState('connecting');

    source.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data) as PipelineLogEventDto;
        setStreamState('live');

        if (payload.run) {
          setRuns((current) => mergeRun(current, payload.run!));
        } else if (payload.type === 'log') {
          setRuns((current) => appendLogEventToRuns(current, payload));
        }

        if (payload.type === 'complete') {
          setStreamState('closed');
          source.close();
        }
      } catch {
        setStreamState('closed');
      }
    };

    source.onerror = () => {
      setStreamState('closed');
      source.close();
    };

    return () => {
      source.close();
      setStreamState('idle');
    };
  }, [selectedRunId]);

  const handleRunPipeline = async () => {
    if (!pipeline) return;
    setBusyRun(true);
    setError(null);
    setMessage(null);
    try {
      const response = await runPipeline(pipeline.id);
      const newRun = response.data;
      setRuns((current) => mergeRun(current, newRun));
      setSelectedRunId(newRun.id);
      setMessage('Run pipeline déclenché.');
    } catch (err) {
      setError(extractApiError(err, 'Impossible de démarrer le pipeline.'));
    } finally {
      setBusyRun(false);
    }
  };

  const handleApproveRun = async (runId: number) => {
    setApprovingRunId(runId);
    setError(null);
    setMessage(null);
    try {
      const response = await approvePipelineRun(runId);
      setRuns((current) => mergeRun(current, response.data));
      setSelectedRunId(response.data.id);
      setMessage('Approbation enregistrée, reprise du run.');
    } catch (err) {
      setError(extractApiError(err, "Impossible d'approuver ce run."));
    } finally {
      setApprovingRunId(null);
    }
  };

  // ── Render ──────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <span className="material-symbols-outlined animate-spin text-5xl text-primary">progress_activity</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <header className="rounded-[28px] border border-outline-variant/[0.16] bg-[radial-gradient(circle_at_top_left,rgba(164,230,255,0.12),transparent_35%),linear-gradient(180deg,rgba(16,18,24,0.94),rgba(10,12,18,0.98))] px-6 py-6 shadow-[0_18px_80px_rgba(0,0,0,0.24)]">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-4">
            <button
              type="button"
              onClick={() => navigate('/pipeline')}
              className="flex items-center gap-2 rounded-2xl border border-outline-variant/[0.22] px-4 py-2.5 text-sm font-semibold text-on-surface transition hover:border-primary/30 hover:text-primary"
            >
              <span className="material-symbols-outlined text-[18px]">arrow_back</span>
              Retour
            </button>
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-tertiary/20 bg-tertiary/10 px-3 py-1 text-[11px] uppercase tracking-[0.28em] text-tertiary">
                <span className="h-2 w-2 rounded-full bg-tertiary shadow-[0_0_12px_rgba(0,252,146,0.6)]" />
                Run Inspector
              </div>
              <h1 className="mt-2 font-headline text-2xl font-bold tracking-tight text-on-surface md:text-3xl">
                {pipeline?.name ?? `Pipeline #${pipelineId}`}
              </h1>
              {pipeline?.description && (
                <p className="mt-1 text-sm text-on-surface-variant">{pipeline.description}</p>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <span
              className={`rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] ${streamStatusClasses[streamState]}`}
            >
              {streamState === 'connecting'
                ? 'SSE connecting'
                : streamState === 'live'
                  ? 'SSE live'
                  : streamState === 'closed'
                    ? 'SSE closed'
                    : 'SSE idle'}
            </span>

            {selectedRun?.status === 'AWAITING_APPROVAL' && (
              <button
                type="button"
                onClick={() => void handleApproveRun(selectedRun.id)}
                disabled={approvingRunId === selectedRun.id}
                className="rounded-2xl bg-secondary px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-70"
              >
                {approvingRunId === selectedRun.id ? 'Validation…' : 'Approuver la production'}
              </button>
            )}

            <button
              type="button"
              onClick={() => void handleRunPipeline()}
              disabled={busyRun}
              className="rounded-2xl bg-primary px-5 py-2.5 text-sm font-bold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {busyRun ? 'Lancement…' : 'Lancer un run'}
            </button>

            <button
              type="button"
              onClick={() => void loadData()}
              className="rounded-2xl border border-outline-variant/[0.22] px-4 py-2.5 text-sm font-semibold text-on-surface transition hover:border-primary/30 hover:text-primary"
            >
              <span className="material-symbols-outlined text-[18px]">refresh</span>
            </button>
          </div>
        </div>
      </header>

      {/* Notifications */}
      {(message || error) && (
        <div
          className={`rounded-2xl border px-4 py-3 text-sm ${
            error
              ? 'border-error/40 bg-error/10 text-error'
              : 'border-primary/30 bg-primary/10 text-primary'
          }`}
        >
          {error ?? message}
        </div>
      )}

      {/* Metadata band */}
      {pipeline && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: 'Source', value: pipeline.repositoryLabel || pipeline.repoUrl || '—', sub: `Branch: ${pipeline.branch || 'main'}` },
            { label: 'Runner', value: pipeline.runnerServerName || '—', sub: '' },
            { label: 'Staging', value: pipeline.stagingServerName || '—', sub: '' },
            { label: 'Production', value: pipeline.productionServerName || '—', sub: '' },
          ].map((item) => (
            <div
              key={item.label}
              className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container px-4 py-4"
            >
              <p className="text-[10px] uppercase tracking-[0.24em] text-outline">{item.label}</p>
              <p className="mt-2 truncate font-mono text-sm font-semibold text-on-surface">{item.value}</p>
              {item.sub && <p className="mt-1 text-xs text-outline">{item.sub}</p>}
            </div>
          ))}
        </div>
      )}

      {/* Main content: Historique + Stages/Logs */}
      <div className="grid gap-6 xl:grid-cols-[300px,1fr]">
        {/* Left — Historique des runs */}
        <aside className="space-y-3 rounded-[24px] border border-outline-variant/[0.16] bg-surface-container p-5 shadow-[0_8px_40px_rgba(0,0,0,0.14)]">
          <div className="flex items-center justify-between">
            <h2 className="font-headline text-lg font-bold text-on-surface">Historique des runs</h2>
            <button
              type="button"
              onClick={() => void loadData()}
              className="text-xs font-semibold text-primary hover:underline"
            >
              Refresh
            </button>
          </div>

          {runs.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-outline-variant/[0.18] px-4 py-10 text-center text-sm text-on-surface-variant">
              Aucun run pour ce pipeline.
              <br />
              <button
                type="button"
                onClick={() => void handleRunPipeline()}
                className="mt-3 rounded-xl bg-primary px-4 py-2 text-xs font-bold text-slate-950 transition hover:brightness-110"
              >
                Lancer le premier run
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              {runs.map((run) => {
                const runClass = statusClasses[run.status] ?? statusClasses.PENDING;
                const isSelected = run.id === selectedRun?.id;
                return (
                  <button
                    key={run.id}
                    type="button"
                    onClick={() => setSelectedRunId(run.id)}
                    className={`w-full rounded-2xl border px-4 py-4 text-left transition ${
                      isSelected
                        ? 'border-primary/35 bg-primary/5'
                        : 'border-outline-variant/[0.14] bg-surface-container hover:border-primary/20'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="font-headline text-lg font-bold text-on-surface">Run #{run.id}</p>
                        <p className="mt-1 text-xs text-outline">{formatDateTime(run.startedAt)}</p>
                      </div>
                      <span
                        className={`rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.2em] ${runClass}`}
                      >
                        {run.status}
                      </span>
                    </div>
                    <p className="mt-3 line-clamp-2 text-sm text-on-surface-variant">
                      {run.summary || 'Aucun résumé disponible.'}
                    </p>
                    <div className="mt-3 flex items-center justify-between text-xs text-outline">
                      <span>Stage: {formatStageName(run.currentStage)}</span>
                      <span>{run.securityScanId ? `Scan #${run.securityScanId}` : 'Sans scan'}</span>
                    </div>
                    <p className="mt-1 text-xs text-outline">Dernier run {formatRelative(run.startedAt)}</p>
                  </button>
                );
              })}
            </div>
          )}
        </aside>

        {/* Right — Stages + Logs */}
        <div className="space-y-5">
          {selectedRun ? (
            <>
              {/* 4 métriques */}
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                {[
                  { label: 'Déclenché par', value: selectedRun.triggeredByLogin || '—' },
                  { label: 'Stage actif', value: formatStageName(selectedRun.currentStage) },
                  { label: 'Scan lié', value: selectedRun.securityScanId ? `#${selectedRun.securityScanId}` : '—' },
                  {
                    label: 'Terminé',
                    value: formatDateTime(selectedRun.finishedAt),
                    sub: selectedRun.approvedByLogin
                      ? `Approved by ${selectedRun.approvedByLogin}`
                      : 'Pas encore approuvé',
                  },
                ].map((item) => (
                  <div
                    key={item.label}
                    className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-4"
                  >
                    <p className="text-[10px] uppercase tracking-[0.24em] text-outline">{item.label}</p>
                    <p className="mt-2 font-headline text-xl font-bold text-on-surface">{item.value}</p>
                    {item.sub && <p className="mt-1 text-xs text-outline">{item.sub}</p>}
                  </div>
                ))}
              </div>

              {/* Grille des stages */}
              {selectedRun.stages.length > 0 ? (
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {selectedRun.stages.map((stage) => {
                    const stageClass = statusClasses[stage.status] ?? statusClasses.PENDING;
                    return (
                      <div
                        key={stage.id}
                        className="rounded-[22px] border border-outline-variant/[0.14] bg-surface-container-low p-4"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-center gap-3">
                            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-surface-container text-primary">
                              <span className="material-symbols-outlined text-[22px]">
                                {stageIcon[stage.stageType] ?? 'alt_route'}
                              </span>
                            </div>
                            <div>
                              <p className="font-headline text-lg font-bold text-on-surface">{stage.title}</p>
                              <p className="text-xs text-outline">Ordre {stage.stageOrder}</p>
                            </div>
                          </div>
                          <span
                            className={`rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.18em] ${stageClass}`}
                          >
                            {stage.status}
                          </span>
                        </div>
                        <p className="mt-4 text-sm leading-relaxed text-on-surface-variant">
                          {stage.details || 'Aucun détail métier pour ce stage.'}
                        </p>
                        <div className="mt-4 flex items-center justify-between text-xs text-outline">
                          <span>{formatDateTime(stage.startedAt)}</span>
                          <span>
                            {stage.relatedScanId
                              ? `Scan #${stage.relatedScanId}`
                              : stage.finishedAt
                                ? 'Terminé'
                                : 'En attente'}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="rounded-3xl border border-dashed border-outline-variant/[0.24] px-6 py-10 text-center text-on-surface-variant">
                  <span className="material-symbols-outlined text-4xl text-outline">hourglass_empty</span>
                  <p className="mt-2 font-headline text-lg text-on-surface">Stages en attente</p>
                  <p className="mt-1 text-sm">Les stages apparaîtront en temps réel via SSE dès le démarrage du run.</p>
                </div>
              )}

              {/* Terminal logs consolidés */}
              <div className="overflow-hidden rounded-[24px] border border-outline-variant/[0.16] bg-[#05070d] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
                <div className="flex items-center justify-between border-b border-white/5 px-5 py-4">
                  <div className="flex items-center gap-3">
                    <span className="material-symbols-outlined text-primary">terminal</span>
                    <div>
                      <h3 className="font-headline text-lg font-bold text-white">Logs consolidés</h3>
                      <p className="text-xs text-slate-400">
                        Run #{selectedRun.id} · {selectedRun.summary || 'Aucun résumé'}
                      </p>
                    </div>
                  </div>
                  <span
                    className={`rounded-full border px-3 py-1 text-[10px] uppercase tracking-[0.22em] ${streamStatusClasses[streamState]}`}
                  >
                    {selectedRun.stages.length} stages · {streamState}
                  </span>
                </div>
                <pre className="max-h-[520px] overflow-auto px-5 py-5 font-mono text-[12px] leading-6 text-slate-200 whitespace-pre-wrap">
                  {aggregatedLogs}
                </pre>
              </div>
            </>
          ) : (
            <div className="flex min-h-[300px] items-center justify-center rounded-3xl border border-dashed border-outline-variant/[0.24] text-center text-on-surface-variant">
              <div>
                <span className="material-symbols-outlined text-5xl text-outline">rocket_launch</span>
                <p className="mt-3 font-headline text-xl text-on-surface">Aucun run sélectionné</p>
                <p className="mt-2 text-sm">Déclenche un run pour voir les stages, le quality gate et les logs.</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PipelineRunInspectorPage;
