import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  createPipeline,
  getDockerHubCredential,
  getPipeline,
  getPipelinePreset,
  getRepositories,
  getServerNodes,
  saveDockerHubCredential,
  updatePipeline,
  type DockerHubCredentialDto,
  type PipelineDefinitionDto,
  type PipelineDefinitionRequest,
  type PipelinePresetDto,
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
  PENDING: 'border-outline-variant/30 bg-surface-container text-outline',
};

const toPayload = (form: PipelineFormState): PipelineDefinitionRequest => {
  const normalize = (value: string) => (value.trim() ? value.trim() : undefined);
  const parseId = (value: string) => (value ? Number(value) : undefined);
  return {
    name: form.name.trim() || undefined,
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
  server.name, server.environment, server.nodeType, server.templateKey,
  server.owner, server.projectName, server.description, server.notes,
  ...(server.tags ?? []),
].filter(Boolean).join(' ').toLowerCase();

const pickAutoServer = (servers: ServerNodeDto[], role: AutoServerRole): string => {
  const directMatches = servers.filter((server) => {
    const searchable = getServerSearchText(server);
    if (role === 'runner') {
      return server.nodeType === 'SCANNER_NODE' || searchable.includes('runner') || searchable.includes('build') || searchable.includes('ci') || searchable.includes('scanner');
    }
    if (role === 'staging') {
      return server.nodeType === 'STAGING' || searchable.includes('staging') || searchable.includes('stage') || searchable.includes('preprod') || searchable.includes('uat') || searchable.includes('lab');
    }
    return server.nodeType === 'PRODUCTION' || searchable.includes('production') || searchable.includes('prod') || searchable.includes('live');
  });
  if (directMatches.length === 1) return String(directMatches[0].id);
  if (role === 'runner') {
    const runnerCandidates = servers.filter((s) => ['SCANNER_NODE', 'CUSTOM'].includes(s.nodeType));
    if (runnerCandidates.length === 1) return String(runnerCandidates[0].id);
  }
  if (servers.length === 1) return String(servers[0].id);
  return '';
};

const withAutoSelectedServers = (current: PipelineFormState, servers: ServerNodeDto[]): PipelineFormState => {
  const nextRunnerServerId = current.runnerServerId || pickAutoServer(servers, 'runner');
  const nextStagingServerId = current.stagingServerId || pickAutoServer(servers, 'staging');
  const nextProductionServerId = current.productionServerId || pickAutoServer(servers, 'production');
  if (
    nextRunnerServerId === current.runnerServerId &&
    nextStagingServerId === current.stagingServerId &&
    nextProductionServerId === current.productionServerId
  ) return current;
  return { ...current, runnerServerId: nextRunnerServerId, stagingServerId: nextStagingServerId, productionServerId: nextProductionServerId };
};

const PipelineFormPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const editIdParam = searchParams.get('editId');

  const [form, setForm] = useState<PipelineFormState>(emptyPipelineForm());
  const [dockerHubForm, setDockerHubForm] = useState<DockerHubFormState>(emptyDockerHubForm());
  const [repositories, setRepositories] = useState<RepositoryDto[]>([]);
  const [servers, setServers] = useState<ServerNodeDto[]>([]);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingDockerHub, setSavingDockerHub] = useState(false);
  const [presetLoading, setPresetLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [presetSummary, setPresetSummary] = useState<string | null>(null);
  const [detectedComponents, setDetectedComponents] = useState<string[]>([]);
  const [showAdvancedConfiguration, setShowAdvancedConfiguration] = useState(false);

  useEffect(() => {
    let active = true;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const [repoResult, serverResult, dockerResult] = await Promise.allSettled([
          getRepositories(),
          getServerNodes(),
          getDockerHubCredential(),
        ]);

        let loadedServers: ServerNodeDto[] = [];
        if (repoResult.status === 'fulfilled') {
          setRepositories(repoResult.value.data.filter((r) => !String(r.repoUrl ?? '').startsWith('docker://')));
        }
        if (serverResult.status === 'fulfilled') {
          loadedServers = serverResult.value.data;
          setServers(loadedServers);
        }
        if (dockerResult.status === 'fulfilled') {
          setDockerHubForm(toDockerHubState(dockerResult.value.data));
        }

        if (editIdParam) {
          const pipelineRes = await getPipeline(Number(editIdParam));
          if (active) {
            const pipeline = pipelineRes.data;
            setEditingId(pipeline.id);
            setForm(withAutoSelectedServers(toFormState(pipeline), loadedServers));
            setPresetSummary(pipeline.repositoryId ? 'Configuration chargée. Réapplique le preset si tu changes de repository.' : null);
          }
        }
      } catch (err) {
        if (active) setError(extractApiError(err, 'Impossible de charger les données.'));
      } finally {
        if (active) setLoading(false);
      }
    };
    void load();
    return () => { active = false; };
  }, [editIdParam]);

  useEffect(() => {
    if (!servers.length || !form.repositoryId) return;
    setForm((current) => withAutoSelectedServers(current, servers));
  }, [form.repositoryId, servers]);

  const applyPreset = useCallback(async (repositoryId: number, successMessage = 'Preset monolithique appliqué automatiquement.') => {
    setPresetLoading(true);
    setError(null);
    try {
      const fallbackRepoUrl = repositories.find((r) => r.id === repositoryId)?.repoUrl;
      const response = await getPipelinePreset(repositoryId);
      const preset = response.data;
      setForm((current) => withAutoSelectedServers(applyPresetToForm(current, preset, String(repositoryId), fallbackRepoUrl), servers));
      setPresetSummary(preset.summary ?? null);
      setDetectedComponents(preset.detectedComponents ?? []);
      setMessage(successMessage);
    } catch (err) {
      setError(extractApiError(err, 'Impossible de générer le preset monolithique.'));
    } finally {
      setPresetLoading(false);
    }
  }, [repositories, servers]);

  const handleInputChange = <K extends keyof PipelineFormState>(key: K, value: PipelineFormState[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const handleRepositorySelection = async (repositoryIdValue: string) => {
    setForm((current) => ({
      ...current,
      repositoryId: repositoryIdValue,
      repoUrl: repositoryIdValue
        ? repositories.find((r) => r.id === Number(repositoryIdValue))?.repoUrl ?? current.repoUrl
        : current.repoUrl,
    }));
    setPresetSummary(null);
    setDetectedComponents([]);
    if (!repositoryIdValue) return;
    await applyPreset(Number(repositoryIdValue));
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      const payload = toPayload(form);
      if (editingId) {
        await updatePipeline(editingId, payload);
      } else {
        await createPipeline(payload);
      }
      navigate('/pipeline');
    } catch (err) {
      setError(extractApiError(err, 'Impossible de sauvegarder le pipeline.'));
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
        await applyPreset(Number(form.repositoryId), 'Credentials Docker Hub enregistrés et preset mis à jour.');
      } else {
        setMessage(response.data.username ? 'Credentials Docker Hub enregistrés.' : 'Credentials Docker Hub supprimés.');
      }
    } catch (err) {
      setError(extractApiError(err, 'Impossible d\u2019enregistrer les credentials Docker Hub.'));
    } finally {
      setSavingDockerHub(false);
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <span className="material-symbols-outlined animate-spin text-4xl text-primary">progress_activity</span>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <header className="rounded-[28px] border border-outline-variant/[0.16] bg-[radial-gradient(circle_at_top_left,rgba(164,230,255,0.12),transparent_35%),linear-gradient(180deg,rgba(16,18,24,0.94),rgba(10,12,18,0.98))] px-6 py-7 shadow-[0_18px_80px_rgba(0,0,0,0.24)]">
        <div className="flex items-center gap-4">
          <button
            type="button"
            onClick={() => navigate('/pipeline')}
            className="inline-flex items-center gap-2 rounded-full border border-outline-variant/[0.18] px-4 py-2 text-xs font-semibold text-outline transition hover:border-primary/30 hover:text-primary"
          >
            <span className="material-symbols-outlined text-[14px]">arrow_back</span>
            Retour
          </button>
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-tertiary/20 bg-tertiary/10 px-3 py-1 text-[11px] uppercase tracking-[0.28em] text-tertiary">
              <span className="h-2 w-2 rounded-full bg-tertiary shadow-[0_0_12px_rgba(0,252,146,0.6)]"></span>
              Pipeline Designer
            </div>
            <h1 className="mt-3 font-headline text-3xl font-bold tracking-tight text-on-surface">
              {editingId ? 'Modifier le pipeline' : 'Nouveau pipeline'}
            </h1>
            <p className="mt-2 text-sm text-on-surface-variant">
              Choisis le repo connu, applique le preset auto, puis ajuste les serveurs et les commandes si nécessaire.
            </p>
          </div>
        </div>
      </header>

      {(message || error) && (
        <div className={`rounded-2xl border px-4 py-3 text-sm ${error ? 'border-error/40 bg-error/10 text-error' : 'border-primary/30 bg-primary/10 text-primary'}`}>
          {error ?? message}
        </div>
      )}

      {/* Form card */}
      <section className="rounded-[28px] border border-outline-variant/[0.16] bg-surface-container p-6 shadow-[0_18px_60px_rgba(0,0,0,0.16)]">
        <form className="space-y-5" onSubmit={handleSubmit}>
          <div className="space-y-2">
            <label className="text-xs uppercase tracking-[0.24em] text-outline">Nom</label>
            <input className={fieldClass} value={form.name} onChange={(e) => handleInputChange('name', e.target.value)} placeholder="Auto depuis le repo sélectionné" />
            <p className="text-xs text-outline">Optionnel. Laisse vide si tu veux que le backend génère automatiquement le nom du pipeline.</p>
          </div>

          <div className="space-y-2">
            <label className="text-xs uppercase tracking-[0.24em] text-outline">Description</label>
            <textarea className={`${fieldClass} min-h-[92px] resize-none`} value={form.description} onChange={(e) => handleInputChange('description', e.target.value)} placeholder="Pipeline monolithique containerisé pour front office, back office et backend Spring Boot." />
            <p className="text-xs text-outline">Optionnel. Le preset peut aussi générer automatiquement cette description.</p>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.24em] text-outline">Repository connu</label>
              <div className="flex gap-2">
                <select className={fieldClass} value={form.repositoryId} onChange={(e) => void handleRepositorySelection(e.target.value)}>
                  <option value="">Choisir un repo déjà connu</option>
                  {repositories.map((repository) => (
                    <option key={repository.id} value={repository.id}>
                      {repository.repoUrl.replace(/^https?:\/\//, '')}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  disabled={!form.repositoryId || presetLoading}
                  onClick={() => form.repositoryId && void applyPreset(Number(form.repositoryId), 'Preset monolithique réappliqué.')}
                  className="rounded-2xl border border-outline-variant/[0.18] px-4 py-3 text-xs font-semibold text-on-surface transition hover:border-primary/30 hover:text-primary disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {presetLoading ? 'Preset…' : 'Preset'}
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.24em] text-outline">URL Git fallback</label>
              <input className={fieldClass} value={form.repoUrl} onChange={(e) => handleInputChange('repoUrl', e.target.value)} placeholder="https://github.com/org/repo.git" />
            </div>
          </div>

          {(presetSummary || detectedComponents.length > 0) && (
            <div className="rounded-3xl border border-primary/18 bg-primary/5 p-4">
              <div className="flex flex-wrap items-center gap-2">
                {detectedComponents.map((component) => (
                  <span key={component} className="rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] text-primary">
                    {component}
                  </span>
                ))}
              </div>
              {presetSummary && <p className="mt-3 text-sm leading-relaxed text-on-surface-variant">{presetSummary}</p>}
              <p className="mt-3 text-xs text-outline">Build, test, Docker, scan conteneur, déploiement staging, DAST et production seront remplis automatiquement depuis le repo choisi.</p>
            </div>
          )}

          {/* Docker Hub */}
          <div className="rounded-3xl border border-outline-variant/[0.16] bg-surface-container-high p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-[0.24em] text-outline">Docker Hub</p>
                <p className="mt-2 text-sm text-on-surface-variant">Stockage chiffré des credentials pour namespace automatique des tags et push après build.</p>
              </div>
              <span className={`rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] ${dockerHubForm.hasToken ? statusClasses.SUCCESS : statusClasses.PENDING}`}>
                {dockerHubForm.hasToken ? 'Linked' : 'Absent'}
              </span>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <input className={fieldClass} value={dockerHubForm.username} onChange={(e) => setDockerHubForm((c) => ({ ...c, username: e.target.value }))} placeholder="dockerhub-username" />
              <input type="password" className={fieldClass} value={dockerHubForm.token} onChange={(e) => setDockerHubForm((c) => ({ ...c, token: e.target.value }))} placeholder={dockerHubForm.hasToken ? 'Laisser vide pour conserver le token actuel' : 'Docker Hub access token'} />
            </div>
            <div className="mt-3 flex items-center justify-between gap-3 text-xs text-outline">
              <span>{dockerHubForm.hasToken ? 'Le token reste chiffré côté backend.' : 'Enregistré au niveau utilisateur puis réutilisé pour tous les pipelines.'}</span>
              <button
                type="button"
                disabled={savingDockerHub}
                onClick={() => void handleSaveDockerHub()}
                className="rounded-full border border-outline-variant/[0.18] px-4 py-2 font-semibold text-on-surface transition hover:border-primary/30 hover:text-primary disabled:cursor-not-allowed disabled:opacity-60"
              >
                {savingDockerHub ? 'Enregistrement…' : 'Sauvegarder Docker Hub'}
              </button>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.24em] text-outline">Branche</label>
              <input className={fieldClass} value={form.branch} onChange={(e) => handleInputChange('branch', e.target.value)} placeholder="main" />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.24em] text-outline">Workspace distant</label>
              <input className={fieldClass} value={form.workspacePath} onChange={(e) => handleInputChange('workspacePath', e.target.value)} placeholder="/opt/apps/ecommerce" />
            </div>
          </div>

          {/* Servers */}
          <div className="grid gap-4 md:grid-cols-3">
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.24em] text-outline">Runner SSH</label>
              <select className={fieldClass} value={form.runnerServerId} onChange={(e) => handleInputChange('runnerServerId', e.target.value)}>
                <option value="">Aucun runner</option>
                {servers.map((server) => (
                  <option key={server.id} value={server.id}>{server.name} · {server.host}</option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.24em] text-outline">Staging</label>
              <select className={fieldClass} value={form.stagingServerId} onChange={(e) => handleInputChange('stagingServerId', e.target.value)}>
                <option value="">Aucun serveur staging</option>
                {servers.map((server) => (
                  <option key={server.id} value={server.id}>{server.name} · {server.host}</option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.24em] text-outline">Production</label>
              <select className={fieldClass} value={form.productionServerId} onChange={(e) => handleInputChange('productionServerId', e.target.value)}>
                <option value="">Aucun serveur production</option>
                {servers.map((server) => (
                  <option key={server.id} value={server.id}>{server.name} · {server.host}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Advanced */}
          <div className="rounded-3xl border border-outline-variant/[0.16] bg-surface-container-high p-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.24em] text-outline">Mode automatique</p>
                <p className="mt-2 text-sm text-on-surface-variant">Tu sélectionnes le repo, le backend détecte les bonnes commandes et le designer les applique automatiquement. Les champs ci-dessous ne servent qu'en personnalisation avancée.</p>
              </div>
              <button
                type="button"
                onClick={() => setShowAdvancedConfiguration((c) => !c)}
                className="rounded-full border border-outline-variant/[0.18] px-4 py-2 text-xs font-semibold text-on-surface transition hover:border-primary/30 hover:text-primary"
              >
                {showAdvancedConfiguration ? 'Masquer les détails avancés' : 'Personnaliser manuellement'}
              </button>
            </div>
          </div>

          {showAdvancedConfiguration && (
            <>
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-[0.24em] text-outline">Build command</label>
                <textarea className={textAreaClass} value={form.buildCommand} onChange={(e) => handleInputChange('buildCommand', e.target.value)} placeholder={'mvn clean package -DskipTests\ncd Frontend && npm ci && npm run build'} />
              </div>
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-[0.24em] text-outline">Tests command</label>
                <textarea className={textAreaClass} value={form.testCommand} onChange={(e) => handleInputChange('testCommand', e.target.value)} placeholder={'mvn test\ncd Frontend && npm test -- --watch=false'} />
              </div>
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-[0.24em] text-outline">Docker build command</label>
                <textarea className={textAreaClass} value={form.dockerBuildCommand} onChange={(e) => handleInputChange('dockerBuildCommand', e.target.value)} placeholder={'docker build -t vulnix-backend:latest Backend\ndocker build -t vulnix-frontend:latest Frontend'} />
              </div>
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-[0.24em] text-outline">Container scan command</label>
                <textarea className={textAreaClass} value={form.containerScanCommand} onChange={(e) => handleInputChange('containerScanCommand', e.target.value)} placeholder={'trivy image vulnix-backend:latest\ntrivy image vulnix-frontend:latest'} />
              </div>
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-[0.24em] text-outline">Staging deploy command</label>
                <textarea className={textAreaClass} value={form.stagingDeployCommand} onChange={(e) => handleInputChange('stagingDeployCommand', e.target.value)} placeholder={'docker compose pull\ndocker compose up -d'} />
              </div>
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-[0.24em] text-outline">DAST command</label>
                <textarea className={textAreaClass} value={form.dastCommand} onChange={(e) => handleInputChange('dastCommand', e.target.value)} placeholder={'docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://staging.example.com'} />
              </div>
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-[0.24em] text-outline">Production deploy command</label>
                <textarea className={textAreaClass} value={form.productionDeployCommand} onChange={(e) => handleInputChange('productionDeployCommand', e.target.value)} placeholder={'docker compose pull\ndocker compose up -d'} />
              </div>
              <div className="grid gap-3 rounded-3xl border border-outline-variant/[0.16] bg-surface-container-high p-4 text-sm text-on-surface-variant">
                {[
                  { key: 'approvalRequired', label: 'Approbation manuelle avant production' },
                  { key: 'failOnCritical', label: 'Bloquer si CVE critique détectée' },
                  { key: 'failOnSecrets', label: 'Bloquer si secret détecté' },
                  { key: 'active', label: 'Pipeline actif' },
                ].map((item) => (
                  <label key={item.key} className="flex items-center justify-between gap-3 rounded-2xl border border-outline-variant/[0.12] bg-surface-container px-4 py-3">
                    <span>{item.label}</span>
                    <input
                      type="checkbox"
                      checked={Boolean(form[item.key as keyof PipelineFormState])}
                      onChange={(e) => handleInputChange(item.key as keyof PipelineFormState, e.target.checked as never)}
                      className="h-4 w-4 accent-primary"
                    />
                  </label>
                ))}
              </div>
            </>
          )}

          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => navigate('/pipeline')}
              className="rounded-2xl border border-outline-variant/[0.22] px-6 py-3 font-headline text-sm font-semibold text-on-surface-variant transition hover:border-outline/40 hover:text-on-surface"
            >
              Annuler
            </button>
            <button
              type="submit"
              disabled={saving}
              className="flex-1 rounded-2xl bg-primary px-4 py-3 font-headline text-sm font-bold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {saving ? 'Sauvegarde…' : editingId ? 'Mettre à jour le pipeline' : 'Créer le pipeline automatiquement'}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
};

export default PipelineFormPage;
