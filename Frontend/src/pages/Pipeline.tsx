import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import ConfirmModal from '../components/ConfirmModal';
import {
  approvePipelineRun,
  createPipeline,
  deletePipeline,
  getDockerHubCredential,
  getPipelinePreset,
  getPipelineRunLogsStreamUrl,
  getPipelineRuns,
  getPipelines,
  getRepositories,
  getServerNodes,
  runPipeline,
  saveDockerHubCredential,
  updatePipeline,
  type DockerHubCredentialDto,
  type PipelineDefinitionDto,
  type PipelineDefinitionRequest,
  type PipelineLogEventDto,
  type PipelinePresetDto,
  type PipelineRunDto,
  type RepositoryDto,
  type ServerNodeDto,
} from '../services/api';

type PipelineFormState = {
  name: string;
  description: string;
  repositoryId: string;
  repoUrl: string;
  branch: string;
  runnerServerId: string;
  stagingServerId: string;
  productionServerId: string;
  workspacePath: string;
  buildCommand: string;
  testCommand: string;
  dockerBuildCommand: string;
  containerScanCommand: string;
  stagingDeployCommand: string;
  dastCommand: string;
  productionDeployCommand: string;
  approvalRequired: boolean;
  failOnCritical: boolean;
  failOnSecrets: boolean;
  active: boolean;
};

type DockerHubFormState = {
  username: string;
  token: string;
  hasToken: boolean;
};

type AutoServerRole = 'runner' | 'staging' | 'production';

const emptyPipelineForm = (): PipelineFormState => ({
  name: '',
  description: '',
  repositoryId: '',
  repoUrl: '',
  branch: 'main',
  runnerServerId: '',
  stagingServerId: '',
  productionServerId: '',
  workspacePath: '',
  buildCommand: '',
  testCommand: '',
  dockerBuildCommand: '',
  containerScanCommand: '',
  stagingDeployCommand: '',
  dastCommand: '',
  productionDeployCommand: '',
  approvalRequired: true,
  failOnCritical: true,
  failOnSecrets: true,
  active: true,
});

const emptyDockerHubForm = (): DockerHubFormState => ({
  username: '',
  token: '',
  hasToken: false,
});

const extractApiError = (error: any, fallback: string) =>
  error?.response?.data?.message || error?.response?.data?.error || error?.message || fallback;

const fieldClass =
  'w-full rounded-2xl border border-outline-variant/[0.22] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none transition focus:border-primary/40 focus:ring-2 focus:ring-primary/10';

const textAreaClass = `${fieldClass} min-h-[110px] resize-y font-mono text-[12px] leading-relaxed`;

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

const formatStageName = (value?: string | null) =>
  (value ?? '')
    .split('_')
    .filter(Boolean)
    .map((chunk) => chunk.charAt(0) + chunk.slice(1).toLowerCase())
    .join(' ');

const formatDateTime = (value?: string | null) => {
  if (!value) {
    return 'â€”';
  }
  try {
    return new Date(value).toLocaleString('fr-FR');
  } catch {
    return value;
  }
};

const formatRelative = (value?: string | null) => {
  if (!value) {
    return 'jamais';
  }
  const now = Date.now();
  const diffMinutes = Math.max(0, Math.round((now - new Date(value).getTime()) / 60000));
  if (diffMinutes < 1) return 'Ã  lâ€™instant';
  if (diffMinutes < 60) return `il y a ${diffMinutes} min`;
  const diffHours = Math.round(diffMinutes / 60);
  if (diffHours < 24) return `il y a ${diffHours} h`;
  const diffDays = Math.round(diffHours / 24);
  return `il y a ${diffDays} j`;
};

const toPayload = (form: PipelineFormState): PipelineDefinitionRequest => {
  const normalize = (value: string) => (value.trim() ? value.trim() : undefined);
  const parseId = (value: string) => (value ? Number(value) : undefined);
  const name = form.name.trim();

  return {
    name: name || undefined,
    description: normalize(form.description),
    repositoryId: parseId(form.repositoryId),
    repoUrl: normalize(form.repoUrl),
    branch: normalize(form.branch),
    runnerServerId: parseId(form.runnerServerId),
    stagingServerId: parseId(form.stagingServerId),
    productionServerId: parseId(form.productionServerId),
    workspacePath: normalize(form.workspacePath),
    buildCommand: normalize(form.buildCommand),
    testCommand: normalize(form.testCommand),
    dockerBuildCommand: normalize(form.dockerBuildCommand),
    containerScanCommand: normalize(form.containerScanCommand),
    stagingDeployCommand: normalize(form.stagingDeployCommand),
    dastCommand: normalize(form.dastCommand),
    productionDeployCommand: normalize(form.productionDeployCommand),
    approvalRequired: form.approvalRequired,
    failOnCritical: form.failOnCritical,
    failOnSecrets: form.failOnSecrets,
    active: form.active,
  };
};

const toFormState = (pipeline: PipelineDefinitionDto): PipelineFormState => ({
  name: pipeline.name ?? '',
  description: pipeline.description ?? '',
  repositoryId: pipeline.repositoryId ? String(pipeline.repositoryId) : '',
  repoUrl: pipeline.repoUrl ?? '',
  branch: pipeline.branch ?? 'main',
  runnerServerId: pipeline.runnerServerId ? String(pipeline.runnerServerId) : '',
  stagingServerId: pipeline.stagingServerId ? String(pipeline.stagingServerId) : '',
  productionServerId: pipeline.productionServerId ? String(pipeline.productionServerId) : '',
  workspacePath: pipeline.workspacePath ?? '',
  buildCommand: pipeline.buildCommand ?? '',
  testCommand: pipeline.testCommand ?? '',
  dockerBuildCommand: pipeline.dockerBuildCommand ?? '',
  containerScanCommand: pipeline.containerScanCommand ?? '',
  stagingDeployCommand: pipeline.stagingDeployCommand ?? '',
  dastCommand: pipeline.dastCommand ?? '',
  productionDeployCommand: pipeline.productionDeployCommand ?? '',
  approvalRequired: pipeline.approvalRequired,
  failOnCritical: pipeline.failOnCritical,
  failOnSecrets: pipeline.failOnSecrets,
  active: pipeline.active,
});

const toDockerHubState = (credential?: DockerHubCredentialDto | null): DockerHubFormState => ({
  username: credential?.username ?? '',
  token: '',
  hasToken: Boolean(credential?.hasToken),
});

const appendText = (existing?: string | null, line?: string | null) => {
  if (!line?.trim()) {
    return existing ?? null;
  }
  if (!existing?.trim()) {
    return line;
  }
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

const mergeLastRunIntoPipelines = (pipelines: PipelineDefinitionDto[], run: PipelineRunDto) =>
  pipelines.map((pipeline) => (pipeline.id === run.pipelineId
    ? {
        ...pipeline,
        lastRun: run,
        lastRunAt: run.startedAt ?? pipeline.lastRunAt,
      }
    : pipeline));

const appendLogEventToRuns = (runs: PipelineRunDto[], event: PipelineLogEventDto) =>
  runs.map((run) => {
    if (run.id !== event.runId) {
      return run;
    }

    const stageMatcher = (stageId?: number | null, stageType?: string | null) => (stage: PipelineRunDto['stages'][number]) =>
      (stageId ? stage.id === stageId : false) || (!!stageType && stage.stageType === stageType);

    const nextStages = run.stages.map((stage) => (
      stageMatcher(event.stageId, event.stageType)(stage)
        ? {
            ...stage,
            details: stage.details ?? event.message ?? null,
            logOutput: appendText(stage.logOutput, event.message),
          }
        : stage
    ));

    return {
      ...run,
      summary: event.message ?? run.summary,
      stages: nextStages,
    };
  });

const applyPresetToForm = (
  current: PipelineFormState,
  preset: PipelinePresetDto,
  repositoryId: string,
  fallbackRepoUrl?: string,
): PipelineFormState => ({
  ...current,
  repositoryId,
  name: preset.name || current.name,
  description: preset.description ?? current.description,
  repoUrl: preset.repoUrl ?? fallbackRepoUrl ?? current.repoUrl,
  branch: preset.branch ?? current.branch,
  workspacePath: preset.workspacePath ?? current.workspacePath,
  buildCommand: preset.buildCommand ?? current.buildCommand,
  testCommand: preset.testCommand ?? current.testCommand,
  dockerBuildCommand: preset.dockerBuildCommand ?? current.dockerBuildCommand,
  containerScanCommand: preset.containerScanCommand ?? current.containerScanCommand,
  stagingDeployCommand: preset.stagingDeployCommand ?? current.stagingDeployCommand,
  dastCommand: preset.dastCommand ?? current.dastCommand,
  productionDeployCommand: preset.productionDeployCommand ?? current.productionDeployCommand,
  approvalRequired: preset.approvalRequired,
  failOnCritical: preset.failOnCritical,
  failOnSecrets: preset.failOnSecrets,
  active: preset.active,
});

const getServerSearchText = (server: ServerNodeDto) => [
  server.name,
  server.environment,
  server.nodeType,
  server.templateKey,
  server.owner,
  server.projectName,
  server.description,
  server.notes,
  ...(server.tags ?? []),
].filter(Boolean).join(' ').toLowerCase();

const pickAutoServer = (servers: ServerNodeDto[], role: AutoServerRole): string => {
  const directMatches = servers.filter((server) => {
    const searchable = getServerSearchText(server);
    if (role === 'runner') {
      return server.nodeType === 'SCANNER_NODE'
        || searchable.includes('runner')
        || searchable.includes('build')
        || searchable.includes('ci')
        || searchable.includes('scanner');
    }
    if (role === 'staging') {
      return server.nodeType === 'STAGING'
        || searchable.includes('staging')
        || searchable.includes('stage')
        || searchable.includes('preprod')
        || searchable.includes('uat')
        || searchable.includes('lab');
    }
    return server.nodeType === 'PRODUCTION'
      || searchable.includes('production')
      || searchable.includes('prod')
      || searchable.includes('live');
  });

  if (directMatches.length === 1) {
    return String(directMatches[0].id);
  }
  if (role === 'runner') {
    const runnerCandidates = servers.filter((server) => ['SCANNER_NODE', 'CUSTOM'].includes(server.nodeType));
    if (runnerCandidates.length === 1) {
      return String(runnerCandidates[0].id);
    }
  }
  if (servers.length === 1) {
    return String(servers[0].id);
  }
  return '';
};

const withAutoSelectedServers = (current: PipelineFormState, servers: ServerNodeDto[]): PipelineFormState => {
  const nextRunnerServerId = current.runnerServerId || pickAutoServer(servers, 'runner');
  const nextStagingServerId = current.stagingServerId || pickAutoServer(servers, 'staging');
  const nextProductionServerId = current.productionServerId || pickAutoServer(servers, 'production');

  if (
    nextRunnerServerId === current.runnerServerId
    && nextStagingServerId === current.stagingServerId
    && nextProductionServerId === current.productionServerId
  ) {
    return current;
  }

  return {
    ...current,
    runnerServerId: nextRunnerServerId,
    stagingServerId: nextStagingServerId,
    productionServerId: nextProductionServerId,
  };
};

const Pipeline: React.FC = () => {
  const navigate = useNavigate();
  const [form, setForm] = useState<PipelineFormState>(emptyPipelineForm);
  const [dockerHubForm, setDockerHubForm] = useState<DockerHubFormState>(emptyDockerHubForm);
  const [pipelines, setPipelines] = useState<PipelineDefinitionDto[]>([]);
  const [repositories, setRepositories] = useState<RepositoryDto[]>([]);
  const [servers, setServers] = useState<ServerNodeDto[]>([]);
  const [runs, setRuns] = useState<PipelineRunDto[]>([]);
  const [selectedPipelineId, setSelectedPipelineId] = useState<number | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingDockerHub, setSavingDockerHub] = useState(false);
  const [presetLoading, setPresetLoading] = useState(false);
  const [busyPipelineId, setBusyPipelineId] = useState<number | null>(null);
  const [approvingRunId, setApprovingRunId] = useState<number | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [presetSummary, setPresetSummary] = useState<string | null>(null);
  const [detectedComponents, setDetectedComponents] = useState<string[]>([]);
  const [streamState, setStreamState] = useState<'idle' | 'connecting' | 'live' | 'closed'>('idle');
  const [showAdvancedConfiguration, setShowAdvancedConfiguration] = useState(false);
  const [deleteModal, setDeleteModal] = useState<{ open: boolean; pipeline: PipelineDefinitionDto | null }>({ open: false, pipeline: null });

  const selectedPipeline = pipelines.find((pipeline) => pipeline.id === selectedPipelineId) ?? null;
  const selectedRun = runs.find((run) => run.id === selectedRunId) ?? runs[0] ?? null;

  const totalRuns = pipelines.reduce((count, pipeline) => count + (pipeline.lastRun ? 1 : 0), 0);
  const activeRuns = pipelines.filter((pipeline) => ['RUNNING', 'AWAITING_APPROVAL'].includes(pipeline.lastRun?.status ?? '')).length;
  const blockedRuns = pipelines.filter((pipeline) => ['FAILED', 'BLOCKED'].includes(pipeline.lastRun?.status ?? '')).length;

  const aggregatedLogs = useMemo(() => {
    if (!selectedRun) {
      return 'SÃ©lectionne un run pour consulter les logs consolidÃ©s.';
    }
    const blocks = selectedRun.stages
      .filter((stage) => stage.details || stage.logOutput)
      .map((stage) => {
        const header = `[${formatStageName(stage.stageType)}] ${stage.status}`;
        const body = [stage.details, stage.logOutput].filter(Boolean).join('\n');
        return `${header}\n${body}`.trim();
      });
    return blocks.length ? blocks.join('\n\n') : 'Aucun log dÃ©taillÃ© disponible pour ce run.';
  }, [selectedRun]);

  const refreshCatalog = useCallback(async (preferredPipelineId?: number | null, currentSelectedPipelineId?: number | null) => {
    const [pipelineResult, repositoryResult, serverResult] = await Promise.allSettled([
      getPipelines(),
      getRepositories(),
      getServerNodes(),
    ]);

    if (pipelineResult.status === 'fulfilled') {
      const nextPipelines = pipelineResult.value.data;
      setPipelines(nextPipelines);
      const persistedSelection = currentSelectedPipelineId
        && nextPipelines.some((pipeline) => pipeline.id === currentSelectedPipelineId)
        ? currentSelectedPipelineId
        : null;
      const nextSelection = preferredPipelineId
        ?? persistedSelection
        ?? nextPipelines[0]?.id
        ?? null;
      setSelectedPipelineId(nextSelection);
    } else {
      setError(extractApiError(pipelineResult.reason, 'Impossible de charger les pipelines.'));
    }

    if (repositoryResult.status === 'fulfilled') {
      setRepositories(repositoryResult.value.data.filter((repository) => !String(repository.repoUrl ?? '').startsWith('docker://')));
    }

    if (serverResult.status === 'fulfilled') {
      setServers(serverResult.value.data);
    }
  }, []);

  const refreshRuns = useCallback(async (pipelineId: number, preferredRunId?: number | null, currentSelectedRunId?: number | null) => {
    try {
      const response = await getPipelineRuns(pipelineId);
      setRuns(sortRuns(response.data));
      const persistedSelection = currentSelectedRunId
        && response.data.some((run) => run.id === currentSelectedRunId)
        ? currentSelectedRunId
        : null;
      const nextRunId = preferredRunId
        ?? persistedSelection
        ?? response.data[0]?.id
        ?? null;
      setSelectedRunId(nextRunId);
    } catch (requestError) {
      setError(extractApiError(requestError, 'Impossible de charger les runs du pipeline.'));
    }
  }, []);

  const loadDockerHub = useCallback(async () => {
    try {
      const response = await getDockerHubCredential();
      setDockerHubForm(toDockerHubState(response.data));
    } catch {
      setDockerHubForm(emptyDockerHubForm());
    }
  }, []);

  const applyPreset = useCallback(async (repositoryId: number, successMessage = 'Preset monolithique appliquÃ© automatiquement.') => {
    setPresetLoading(true);
    setError(null);
    try {
      const fallbackRepoUrl = repositories.find((repository) => repository.id === repositoryId)?.repoUrl;
      const response = await getPipelinePreset(repositoryId);
      const preset = response.data;
      setForm((current) => withAutoSelectedServers(
        applyPresetToForm(current, preset, String(repositoryId), fallbackRepoUrl),
        servers,
      ));
      setPresetSummary(preset.summary ?? null);
      setDetectedComponents(preset.detectedComponents ?? []);
      setMessage(successMessage);
    } catch (requestError) {
      setError(extractApiError(requestError, 'Impossible de gÃ©nÃ©rer le preset monolithique.'));
    } finally {
      setPresetLoading(false);
    }
  }, [repositories, servers]);

  useEffect(() => {
    let active = true;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        await Promise.all([refreshCatalog(undefined, null), loadDockerHub()]);
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    void load();
    return () => {
      active = false;
    };
  }, [loadDockerHub, refreshCatalog]);

  useEffect(() => {
    if (!selectedPipelineId) {
      setRuns([]);
      setSelectedRunId(null);
      return;
    }
    void refreshRuns(selectedPipelineId, undefined, selectedRunId);
  }, [refreshRuns, selectedPipelineId, selectedRunId]);

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
          setPipelines((current) => mergeLastRunIntoPipelines(current, payload.run!));
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

  useEffect(() => {
    if (!servers.length || !form.repositoryId) {
      return;
    }
    setForm((current) => withAutoSelectedServers(current, servers));
  }, [form.repositoryId, servers]);

  const handleInputChange = <K extends keyof PipelineFormState>(key: K, value: PipelineFormState[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const handleRepositorySelection = async (repositoryIdValue: string) => {
    setForm((current) => ({
      ...current,
      repositoryId: repositoryIdValue,
      repoUrl: repositoryIdValue
        ? repositories.find((repository) => repository.id === Number(repositoryIdValue))?.repoUrl ?? current.repoUrl
        : current.repoUrl,
    }));
    setPresetSummary(null);
    setDetectedComponents([]);
    if (!repositoryIdValue) {
      return;
    }
    await applyPreset(Number(repositoryIdValue));
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();

    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      const payload = toPayload(form);
      const response = editingId
        ? await updatePipeline(editingId, payload)
        : await createPipeline(payload);
      await refreshCatalog(response.data.id, response.data.id);
      setEditingId(response.data.id);
      setForm(toFormState(response.data));
      setMessage(editingId ? 'Pipeline mis Ã  jour.' : 'Pipeline crÃ©Ã©.');
    } catch (requestError) {
      setError(extractApiError(requestError, 'Impossible de sauvegarder le pipeline.'));
    } finally {
      setSaving(false);
    }
  };

  const handleSaveDockerHub = async () => {
    setSavingDockerHub(true);
    setError(null);
    setMessage(null);
    try {
      const response = await saveDockerHubCredential({
        username: dockerHubForm.username.trim(),
        token: dockerHubForm.token.trim() || undefined,
      });
      setDockerHubForm(toDockerHubState(response.data));
      if (form.repositoryId) {
        await applyPreset(Number(form.repositoryId), 'Credentials Docker Hub enregistrÃ©s et preset mis Ã  jour.');
      } else {
        setMessage(response.data.username ? 'Credentials Docker Hub enregistrÃ©s.' : 'Credentials Docker Hub supprimÃ©s.');
      }
    } catch (requestError) {
      setError(extractApiError(requestError, 'Impossible dâ€™enregistrer les credentials Docker Hub.'));
    } finally {
      setSavingDockerHub(false);
    }
  };

  const handleRunPipeline = async (pipelineId: number) => {
    setBusyPipelineId(pipelineId);
    setError(null);
    setMessage(null);
    try {
      await runPipeline(pipelineId);
      await refreshCatalog(pipelineId, pipelineId);
      setMessage('Run dÃ©clenchÃ©. Clique sur View pour suivre les logs en direct.');
    } catch (requestError) {
      setError(extractApiError(requestError, 'Impossible de dÃ©marrer le pipeline.'));
    } finally {
      setBusyPipelineId(null);
    }
  };

  const handleApproveRun = async (runId: number) => {
    setApprovingRunId(runId);
    setError(null);
    setMessage(null);
    try {
      const response = await approvePipelineRun(runId);
      setRuns((current) => mergeRun(current, response.data));
      setPipelines((current) => mergeLastRunIntoPipelines(current, response.data));
      if (selectedPipelineId) {
        await refreshCatalog(selectedPipelineId, selectedPipelineId);
      }
      setSelectedRunId(response.data.id);
      setMessage('Approbation enregistrÃ©e, reprise du run.');
    } catch (requestError) {
      setError(extractApiError(requestError, 'Impossible dâ€™approuver ce run.'));
    } finally {
      setApprovingRunId(null);
    }
  };

  const handleEditPipeline = (pipeline: PipelineDefinitionDto) => {
    navigate(`/pipeline/new?editId=${pipeline.id}`);
  };

  const handleDeletePipeline = (pipeline: PipelineDefinitionDto) => {
    setDeleteModal({ open: true, pipeline });
  };

  const doDeletePipeline = async (pipeline: PipelineDefinitionDto) => {
    setDeleteModal({ open: false, pipeline: null });
    setBusyPipelineId(pipeline.id);
    setError(null);
    setMessage(null);
    try {
      await deletePipeline(pipeline.id);
      const nextSelection = pipelines.find((entry) => entry.id !== pipeline.id)?.id ?? null;
      if (editingId === pipeline.id) {
        setEditingId(null);
        setForm(emptyPipelineForm());
        setPresetSummary(null);
        setDetectedComponents([]);
        setShowAdvancedConfiguration(false);
      }
      await refreshCatalog(nextSelection, nextSelection);
      if (nextSelection) {
        await refreshRuns(nextSelection, undefined, null);
      } else {
        setRuns([]);
        setSelectedRunId(null);
      }
      setMessage('Pipeline supprimÃ©.');
    } catch (requestError) {
      setError(extractApiError(requestError, 'Impossible de supprimer le pipeline.'));
    } finally {
      setBusyPipelineId(null);
    }
  };

  return (
    <div className="space-y-8">
      <ConfirmModal
        open={deleteModal.open}
        title="Supprimer le pipeline"
        message={`Supprimer le pipeline ${deleteModal.pipeline?.name} ? Cette action est dÃ©finitive.`}
        confirmLabel="Supprimer"
        danger
        onConfirm={() => deleteModal.pipeline && doDeletePipeline(deleteModal.pipeline)}
        onCancel={() => setDeleteModal({ open: false, pipeline: null })}
      />
      <header className="rounded-[28px] border border-outline-variant/[0.16] bg-[radial-gradient(circle_at_top_left,rgba(164,230,255,0.12),transparent_35%),linear-gradient(180deg,rgba(16,18,24,0.94),rgba(10,12,18,0.98))] px-6 py-7 shadow-[0_18px_80px_rgba(0,0,0,0.24)]">
        <div className="flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
          <div className="max-w-3xl space-y-3">
            <div className="inline-flex items-center gap-2 rounded-full border border-tertiary/20 bg-tertiary/10 px-3 py-1 text-[11px] uppercase tracking-[0.28em] text-tertiary">
              <span className="h-2 w-2 rounded-full bg-tertiary shadow-[0_0_12px_rgba(0,252,146,0.6)]"></span>
              Orchestration DevSecOps
            </div>
            <div>
              <h1 className="font-headline text-3xl font-bold tracking-tight text-on-surface md:text-4xl">Pipeline factory pour build, test, scan et dÃ©ploiement</h1>
              <p className="mt-3 max-w-2xl text-sm leading-relaxed text-on-surface-variant">
                SÃ©lectionne un repository connu GitHub ou GitLab, laisse le preset monolithique dÃ©tecter front office, back office et backend, puis branche les runners SSH pour tout exÃ©cuter automatiquement.
              </p>
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-3 xl:min-w-[430px]">
            <div className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container px-4 py-4">
              <p className="text-[10px] uppercase tracking-[0.25em] text-outline">Pipelines</p>
              <p className="mt-2 font-headline text-3xl font-bold text-on-surface">{pipelines.length}</p>
            </div>
            <div className="rounded-2xl border border-primary/20 bg-primary/10 px-4 py-4">
              <p className="text-[10px] uppercase tracking-[0.25em] text-primary/80">Runs actifs</p>
              <p className="mt-2 font-headline text-3xl font-bold text-primary">{activeRuns}</p>
            </div>
            <div className="rounded-2xl border border-error/20 bg-error/10 px-4 py-4">
              <p className="text-[10px] uppercase tracking-[0.25em] text-error/80">Runs KO</p>
              <p className="mt-2 font-headline text-3xl font-bold text-error">{blockedRuns}</p>
              <p className="mt-1 text-[11px] text-error/80">Historique initialisÃ©: {totalRuns}</p>
            </div>
          </div>
        </div>
      </header>

      {(message || error) && (
        <div className={`rounded-2xl border px-4 py-3 text-sm ${error ? 'border-error/40 bg-error/10 text-error' : 'border-primary/30 bg-primary/10 text-primary'}`}>
          {error ?? message}
        </div>
      )}

      <div className="grid gap-6">
        <section className="space-y-6">
          <div className="rounded-[28px] border border-outline-variant/[0.16] bg-surface-container p-6 shadow-[0_18px_60px_rgba(0,0,0,0.16)]">
            <div className="mb-5 flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
              <div>
                <p className="text-[11px] uppercase tracking-[0.26em] text-outline">Catalogue</p>
                <h2 className="mt-2 font-headline text-2xl font-bold text-on-surface">Pipelines enregistrÃ©s</h2>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => navigate('/pipeline/new')}
                  className="inline-flex items-center gap-2 rounded-full bg-primary px-4 py-2 text-xs font-bold text-slate-950 transition hover:brightness-110"
                >
                  <span className="material-symbols-outlined text-[14px]">add</span>
                  Ajouter pipeline
                </button>
                <button
                  type="button"
                  onClick={() => void refreshCatalog(selectedPipelineId, selectedPipelineId)}
                  className="rounded-full border border-outline-variant/[0.18] px-4 py-2 text-xs font-semibold text-outline transition hover:border-primary/30 hover:text-primary"
                >
                  Actualiser
                </button>
              </div>
            </div>

            {loading ? (
              <div className="flex min-h-[220px] items-center justify-center">
                <span className="material-symbols-outlined animate-spin text-4xl text-primary">progress_activity</span>
              </div>
            ) : pipelines.length === 0 ? (
              <div className="rounded-3xl border border-dashed border-outline-variant/[0.24] px-6 py-16 text-center text-on-surface-variant">
                <p className="font-headline text-xl text-on-surface">Aucun pipeline pour le moment</p>
                <p className="mt-2 text-sm">CrÃ©e ton premier pipeline Ã  gauche, sÃ©lectionne un repo connu et laisse le preset prÃ©parer les commandes.</p>
              </div>
            ) : (
              <div className="grid gap-4 xl:grid-cols-2">
                {pipelines.map((pipeline) => {
                  const lastRun = pipeline.lastRun;
                  const runStatusClass = statusClasses[lastRun?.status ?? 'PENDING'] ?? statusClasses.PENDING;
                  const isSelected = pipeline.id === selectedPipelineId;

                  // Security gate state
                  const scanSt = pipeline.securityScanStatus;
                  const critCount = pipeline.criticalCveCount ?? 0;
                  const isLaunchBlocked = pipeline.failOnCritical && (
                    scanSt === 'RUNNING' || scanSt === 'PENDING' ||
                    (scanSt === 'COMPLETED' && critCount > 0)
                  );
                  const launchBlockReason =
                    (scanSt === 'RUNNING' || scanSt === 'PENDING')
                      ? 'Scan de sÃ©curitÃ© en coursâ€¦'
                      : (scanSt === 'COMPLETED' && critCount > 0)
                        ? `${critCount} CVE(s) CRITICAL â€” pipeline bloquÃ©e`
                        : scanSt == null
                          ? 'Aucun scan effectuÃ©'
                          : null;

                  return (
                    <article
                      key={pipeline.id}
                      className={`rounded-[24px] border p-5 transition ${isSelected ? 'border-primary/35 bg-primary/5 shadow-[0_20px_80px_rgba(164,230,255,0.12)]' : 'border-outline-variant/[0.14] bg-surface-container-low hover:border-primary/20'}`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <button type="button" onClick={() => setSelectedPipelineId(pipeline.id)} className="text-left">
                          <div className="inline-flex items-center gap-2 rounded-full border border-outline-variant/[0.18] px-2.5 py-1 text-[10px] uppercase tracking-[0.22em] text-outline">
                            {pipeline.sourceProvider ?? 'GIT'}
                          </div>
                          <h3 className="mt-3 font-headline text-xl font-bold text-on-surface">{pipeline.name}</h3>
                          <p className="mt-2 text-sm text-on-surface-variant line-clamp-2">{pipeline.description || 'Pipeline monolithique conteneurisÃ© prÃªt pour build, test, scan et dÃ©ploiement.'}</p>
                        </button>

                        <span className={`rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-[0.2em] ${runStatusClass}`}>
                          {lastRun?.status ?? 'READY'}
                        </span>
                      </div>

                      {/* Security Scan Badge */}
                      {pipeline.repositoryId && (
                        <div className="mt-3 flex items-center gap-2">
                          <span className="text-[10px] uppercase tracking-[0.18em] text-outline">Scan sÃ©curitÃ© :</span>
                          {!scanSt && (
                            <span className="rounded-full border border-outline/30 bg-surface-container px-2.5 py-0.5 text-[10px] font-semibold text-outline">
                              Non scannÃ©
                            </span>
                          )}
                          {(scanSt === 'RUNNING' || scanSt === 'PENDING') && (
                            <span className="inline-flex items-center gap-1 rounded-full border border-secondary/40 bg-secondary/10 px-2.5 py-0.5 text-[10px] font-semibold text-secondary">
                              <span className="material-symbols-outlined animate-spin text-[12px]">autorenew</span>
                              Scan en coursâ€¦
                            </span>
                          )}
                          {scanSt === 'FAILED' && (
                            <span className="rounded-full border border-error/40 bg-error/10 px-2.5 py-0.5 text-[10px] font-semibold text-error">
                              Scan Ã©chouÃ©
                            </span>
                          )}
                          {scanSt === 'COMPLETED' && critCount === 0 && (
                            <span className="inline-flex items-center gap-1 rounded-full border border-success/40 bg-success/10 px-2.5 py-0.5 text-[10px] font-semibold text-success">
                              <span className="material-symbols-outlined text-[12px]">check_circle</span>
                              Aucun CVE critique
                            </span>
                          )}
                          {scanSt === 'COMPLETED' && critCount > 0 && (
                            <span className="inline-flex items-center gap-1 rounded-full border border-error/50 bg-error/15 px-2.5 py-0.5 text-[10px] font-bold text-error">
                              <span className="material-symbols-outlined text-[12px]">dangerous</span>
                              {critCount} CVE CRITICAL
                            </span>
                          )}
                          {pipeline.scanResultId && (
                            <a
                              href={`/vulnerabilities?scanId=${pipeline.scanResultId}${pipeline.repositoryId ? `&repoId=${pipeline.repositoryId}` : ''}`}
                              className="text-[10px] text-primary underline-offset-2 hover:underline"
                            >
                              Voir rapport
                            </a>
                          )}
                        </div>
                      )}

                      <div className="mt-5 grid gap-3 text-sm text-on-surface-variant md:grid-cols-2">
                        <div className="rounded-2xl bg-surface-container px-3 py-3">
                          <p className="text-[10px] uppercase tracking-[0.22em] text-outline">Source</p>
                          <p className="mt-2 font-mono text-[12px] text-on-surface">{pipeline.repositoryLabel || pipeline.repoUrl || 'Non configurÃ©'}</p>
                          <p className="mt-1 text-xs text-outline">Branch: {pipeline.branch || 'main'}</p>
                        </div>
                        <div className="rounded-2xl bg-surface-container px-3 py-3">
                          <p className="text-[10px] uppercase tracking-[0.22em] text-outline">Infra</p>
                          <p className="mt-2 text-on-surface">Runner: {pipeline.runnerServerName || 'â€”'}</p>
                          <p className="mt-1 text-xs text-outline">Staging: {pipeline.stagingServerName || 'â€”'} Â· Prod: {pipeline.productionServerName || 'â€”'}</p>
                        </div>
                      </div>

                      <div className="mt-5 flex flex-wrap items-center gap-2">
                        <div className="flex flex-col gap-1">
                          <button
                            type="button"
                            onClick={() => void handleRunPipeline(pipeline.id)}
                            disabled={busyPipelineId === pipeline.id || isLaunchBlocked}
                            title={isLaunchBlocked ? launchBlockReason ?? undefined : 'Lancer la pipeline'}
                            className={`rounded-xl px-4 py-2 text-xs font-bold transition ${
                              isLaunchBlocked
                                ? 'cursor-not-allowed border border-error/30 bg-error/10 text-error opacity-80'
                                : 'bg-primary text-slate-950 hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-70'
                            }`}
                          >
                            {busyPipelineId === pipeline.id
                              ? 'Runâ€¦'
                              : isLaunchBlocked
                                ? 'ðŸš« BloquÃ©e'
                                : 'Lancer'}
                          </button>
                          {isLaunchBlocked && launchBlockReason && (
                            <p className="text-[10px] text-error">{launchBlockReason}</p>
                          )}
                        </div>
                        <button type="button" onClick={() => navigate(`/pipeline/new?editId=${pipeline.id}`)} className="rounded-xl border border-outline-variant/[0.18] px-4 py-2 text-xs font-semibold text-on-surface transition hover:border-primary/30 hover:text-primary">Ã‰diter</button>
                        <button
                          type="button"
                          onClick={() => navigate(`/pipeline/${pipeline.id}/inspector`)}
                          className="rounded-xl border border-secondary/30 bg-secondary/10 px-4 py-2 text-xs font-semibold text-secondary transition hover:bg-secondary/20"
                        >
                          <span className="flex items-center gap-1.5">
                            <span className="material-symbols-outlined text-[14px]">visibility</span>
                            View
                          </span>
                        </button>
                        <button type="button" onClick={() => void handleDeletePipeline(pipeline)} className="rounded-xl border border-error/24 px-4 py-2 text-xs font-semibold text-error transition hover:bg-error/10">Supprimer</button>
                        <span className="ml-auto text-xs text-outline">Dernier run {formatRelative(lastRun?.startedAt)}</span>
                      </div>
                    </article>
                  );
                })}
              </div>
            )}
          </div>

          <div className="rounded-[28px] border border-outline-variant/[0.16] bg-surface-container/60 p-5 shadow-[0_8px_30px_rgba(0,0,0,0.10)]">
            <div className="flex items-center gap-3 text-sm text-on-surface-variant">
              <span className="material-symbols-outlined text-[20px] text-outline">info</span>
              <p>Clique sur <span className="font-semibold text-secondary">View</span> sur un pipeline pour ouvrir le Run Inspector : historique, stages, quality gate et logs live via SSE.</p>
            </div>
          </div>

        </section>
      </div>
    </div>
  );
};

export default Pipeline;
