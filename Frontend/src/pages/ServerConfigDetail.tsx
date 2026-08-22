import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  deployServerNode,
  getLiveServerNode,
  getRepositories,
  getServerDeploys,
  getServerNode,
  scanServerNode,
  setServerAutoDeploy,
  updateServerDeploySettings,
  type DeployFindingDto,
  type DeployRunDto,
  type RepositoryDto,
  type ServerNodeDetailDto,
} from '../services/api';
import {
  extractApiError,
  fieldClass,
  FormField,
  formatDateTime,
  formatNodeType,
  MetricCard,
  severityBadgeClass,
  typeBadgeClass,
  validateDeployFields,
} from './serverConfigShared';

const LIVE_REFRESH_INTERVAL_MS = 30000;
const CONTAINER_HOSTNAME_PATTERN = /^[a-f0-9]{12,64}$/i;

const severityRank = (severity?: string | null) => {
  const value = (severity ?? '').toUpperCase();
  if (value === 'CRITICAL') return 0;
  if (value === 'HIGH') return 1;
  if (value === 'WARNING' || value === 'MEDIUM') return 2;
  return 3;
};

const sortBlockingFindings = (items: DeployFindingDto[]) =>
  [...items].sort((left, right) => {
    const bySeverity = severityRank(left.severity) - severityRank(right.severity);
    if (bySeverity !== 0) return bySeverity;
    return (left.cveId ?? '').localeCompare(right.cveId ?? '');
  });

const findingSeverityClass = (severity?: string | null) => {
  const value = (severity ?? '').toUpperCase();
  if (value === 'CRITICAL') return 'border-error/40 bg-error/15 text-error';
  if (value === 'HIGH') return 'border-amber-400/40 bg-amber-400/10 text-amber-300';
  return 'border-outline-variant/30 bg-surface-container-high text-on-surface-variant';
};

const detectEnvironmentHints = (server: ServerNodeDetailDto): string[] => {
  const hints: string[] = [];
  const hostname = server.hostname?.trim() ?? '';
  const host = server.host.trim().toLowerCase();
  const platformFingerprint = `${server.osName ?? ''} ${server.kernelVersion ?? ''}`.toLowerCase();

  if (CONTAINER_HOSTNAME_PATTERN.test(hostname)) {
    hints.push('Hostname de conteneur Docker detecte');
  }

  if (platformFingerprint.includes('microsoft-standard-wsl') || platformFingerprint.includes('wsl2')) {
    hints.push('Environnement WSL2 detecte');
  }

  if (host === 'localhost' || host === '127.0.0.1') {
    hints.push('Connexion SSH redirigee via localhost');
  }

  return hints;
};

const buildMeasurementScope = (server: ServerNodeDetailDto, environmentHints: string[]): string => {
  if (environmentHints.length === 0) {
    return `Les valeurs affichees viennent du serveur scanne via SSH (${server.host}:${server.port}), pas du PC hote.`;
  }

  return `Les valeurs affichees viennent du serveur scanne via SSH (${server.host}:${server.port}). Cette cible ressemble a un environnement conteneurise ou virtualise, pas au PC hote.`;
};

const ServerConfigDetail: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const serverId = Number(id);
  const [selectedServer, setSelectedServer] = useState<ServerNodeDetailDto | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(true);
  const [refreshingLive, setRefreshingLive] = useState(false);
  const [scanningServer, setScanningServer] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);
  const liveRefreshInFlight = useRef(false);
  const [deployPath, setDeployPath] = useState('');
  const [domain, setDomain] = useState('');
  const [linkedRepositoryId, setLinkedRepositoryId] = useState<number | ''>('');
  const [deployBranch, setDeployBranch] = useState('main');
  const [repositories, setRepositories] = useState<RepositoryDto[]>([]);
  const [deploys, setDeploys] = useState<DeployRunDto[]>([]);
  const [savingDeploy, setSavingDeploy] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [togglingAuto, setTogglingAuto] = useState(false);
  const [blockAlert, setBlockAlert] = useState<DeployRunDto | null>(null);

  const loadServerDetail = useCallback(async () => {
    if (!Number.isFinite(serverId)) {
      setSelectedServer(null);
      setLoadingDetail(false);
      setError('Identifiant de serveur invalide.');
      return;
    }

    setLoadingDetail(true);
    setError(null);
    try {
      const { data } = await getServerNode(serverId);
      setSelectedServer(data);
      setDeployPath(data.deployPath ?? '');
      setDomain(data.domain ?? '');
      setLinkedRepositoryId(data.linkedRepositoryId ?? '');
      setDeployBranch(data.deployBranch ?? 'main');
      setLiveError(null);
    } catch (err: any) {
      setError(extractApiError(err, 'Impossible de charger les détails du serveur.'));
    } finally {
      setLoadingDetail(false);
    }
  }, [serverId]);

  const loadDeploys = useCallback(async () => {
    if (!Number.isFinite(serverId)) return;
    try {
      const { data } = await getServerDeploys(serverId);
      setDeploys(data);
    } catch {
      setDeploys([]);
    }
  }, [serverId]);

  useEffect(() => {
    void getRepositories()
      .then((res) => setRepositories(res.data ?? []))
      .catch(() => setRepositories([]));
    void loadDeploys();
  }, [loadDeploys]);

  const refreshLiveServer = useCallback(async () => {
    if (!Number.isFinite(serverId)) {
      return;
    }

    if (liveRefreshInFlight.current) {
      return;
    }

    liveRefreshInFlight.current = true;
    setRefreshingLive(true);
    try {
      const { data } = await getLiveServerNode(serverId);
      setSelectedServer(data);
      setLiveError(null);
      setError(null);
    } catch (err: any) {
      const liveRefreshError = extractApiError(err, 'Impossible d’actualiser l’état live du serveur.');
      setLiveError(liveRefreshError);
      setError(liveRefreshError);
    } finally {
      liveRefreshInFlight.current = false;
      setRefreshingLive(false);
    }
  }, [serverId]);

  useEffect(() => {
    let intervalId: number | undefined;

    const bootstrap = async () => {
      await loadServerDetail();
      await refreshLiveServer();
      intervalId = window.setInterval(() => {
        void refreshLiveServer();
      }, LIVE_REFRESH_INTERVAL_MS);
    };

    void bootstrap();

    return () => {
      if (intervalId) {
        window.clearInterval(intervalId);
      }
    };
  }, [loadServerDetail, refreshLiveServer]);

  const handleScanServer = async () => {
    if (!Number.isFinite(serverId)) {
      return;
    }

    setScanningServer(true);
    setMessage(null);
    setError(null);
    try {
      const { data } = await scanServerNode(serverId);
      setSelectedServer(data);
      setError(null);
      setMessage(`Scan de configuration terminé pour ${data.name}.`);
    } catch (err: any) {
      setError(extractApiError(err, 'Le scan SSH du serveur a échoué.'));
    } finally {
      setScanningServer(false);
    }
  };

  const handleSaveDeploySettings = async () => {
    const deployErrors = validateDeployFields(deployPath, domain, deployBranch);
    if (deployErrors.length > 0) {
      setError(deployErrors[0]);
      return;
    }
    setSavingDeploy(true);
    setError(null);
    setMessage(null);
    try {
      const { data } = await updateServerDeploySettings(serverId, {
        deployPath: deployPath.trim(),
        domain: domain.trim(),
        linkedRepositoryId: linkedRepositoryId === '' ? null : Number(linkedRepositoryId),
        deployBranch: deployBranch.trim() || 'main',
      });
      setSelectedServer(data);
      setMessage('Paramètres de déploiement enregistrés.');
    } catch (err: any) {
      setError(extractApiError(err, 'Impossible d’enregistrer le déploiement.'));
    } finally {
      setSavingDeploy(false);
    }
  };

  const handleToggleAutoDeploy = async () => {
    if (!selectedServer) return;
    setTogglingAuto(true);
    setError(null);
    setMessage(null);
    try {
      const { data } = await setServerAutoDeploy(serverId, !selectedServer.autoDeployEnabled);
      setSelectedServer(data);
      setMessage(data.autoDeployEnabled
        ? 'Auto-deploy activé : un scan PASS déclenchera git pull + docker compose.'
        : 'Auto-deploy désactivé. Utilise le bouton Déployer.');
    } catch (err: any) {
      setError(extractApiError(err, 'Impossible de changer l’auto-deploy.'));
    } finally {
      setTogglingAuto(false);
    }
  };

  const runDeploy = async (force: boolean) => {
    const deployErrors = validateDeployFields(deployPath, domain, deployBranch);
    if (deployErrors.length > 0) {
      setError(deployErrors[0]);
      return;
    }
    setDeploying(true);
    setError(null);
    setMessage(null);
    if (force) setBlockAlert(null);
    try {
      await updateServerDeploySettings(serverId, {
        deployPath: deployPath.trim(),
        domain: domain.trim(),
        linkedRepositoryId: linkedRepositoryId === '' ? null : Number(linkedRepositoryId),
        deployBranch: deployBranch.trim() || 'main',
      });
      const { data } = await deployServerNode(serverId, force);
      setDeploys((prev) => [data, ...prev.filter((item) => item.id !== data.id)].slice(0, 20));
      setMessage(data.status === 'SUCCESS'
        ? 'Déploiement terminé.'
        : `Déploiement ${data.status.toLowerCase()}.`);
    } catch (err: any) {
      const payload = err?.response?.data as DeployRunDto | undefined;
      if (err?.response?.status === 409 && payload?.blocked) {
        setBlockAlert(payload);
        setDeploys((prev) => [payload, ...prev.filter((item) => item.id !== payload.id)].slice(0, 20));
      } else {
        setError(extractApiError(err, 'Le déploiement a échoué.'));
      }
    } finally {
      setDeploying(false);
    }
  };

  const findings = selectedServer?.findings ?? [];
  const ports = selectedServer?.ports ?? [];
  const services = selectedServer?.services ?? [];
  const environmentHints = selectedServer ? detectEnvironmentHints(selectedServer) : [];
  const measurementScope = selectedServer ? buildMeasurementScope(selectedServer, environmentHints) : null;
  const liveStatusLabel = refreshingLive ? 'Actualisation en cours' : liveError ? 'Live interrompu' : 'Live actif';
  const liveStatusHelper = refreshingLive ? 'Synchronisation en cours...' : liveError ? 'Derniere tentative echouee' : 'Actualisation automatique toutes les 30 secondes';
  const liveStatusClass = liveError
    ? 'border-error/30 bg-error/10 text-error'
    : 'border-tertiary/30 bg-tertiary/10 text-tertiary';
  const liveDotClass = liveError
    ? 'bg-error'
    : refreshingLive
      ? 'bg-tertiary animate-pulse'
      : 'bg-tertiary';

  const host = selectedServer?.host?.toLowerCase() ?? '';
  const isLocalhostTarget = host === 'localhost' || host === '127.0.0.1';
  const errorLower = (liveError ?? error ?? '').toLowerCase();
  const isConnectionRefused = errorLower.includes('connection refused') || errorLower.includes('connexion ssh impossible');
  const showLocalhostDiagnostic = isLocalhostTarget && isConnectionRefused;
  const blockingFindings = sortBlockingFindings(blockAlert?.blocking ?? []);
  const criticalCount = blockingFindings.filter((item) => (item.severity ?? '').toUpperCase() === 'CRITICAL').length;
  const highCount = blockingFindings.filter((item) => (item.severity ?? '').toUpperCase() === 'HIGH').length;

  return (
    <div className="space-y-6">
      {blockAlert && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
          onClick={() => setBlockAlert(null)}
        >
          <div
            className="flex max-h-[min(88vh,640px)] w-full max-w-lg flex-col rounded-2xl border border-outline-variant/30 bg-surface-container p-5 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-start gap-3">
              <span className="material-symbols-outlined text-error">warning</span>
              <div className="min-w-0 flex-1">
                <h3 className="font-headline text-base font-bold text-on-surface">
                  Déploiement bloqué
                </h3>
                <p className="mt-1 text-xs text-on-surface-variant">
                  Des vulnérabilités CRITICAL / HIGH empêchent le pull et docker compose. Aucune commande SSH n’a été exécutée.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setBlockAlert(null)}
                className="rounded-full p-1 text-outline transition hover:text-on-surface"
                aria-label="Fermer"
              >
                <span className="material-symbols-outlined text-lg">close</span>
              </button>
            </div>

            <div className="mt-4 rounded-xl border border-error/40 bg-error/10 px-3 py-2 text-xs space-y-1">
              <p className="font-bold text-error">
                Verdict : {blockAlert.verdict || 'BLOCKING_VULNS'}
                {blockAlert.commitSha ? ` · ${blockAlert.commitSha.slice(0, 8)}` : ''}
              </p>
              <p className="text-on-surface">
                {blockingFindings.length > 0
                  ? `${blockingFindings.length} vulnérabilité(s) bloquante(s) sur le dépôt lié.`
                  : (blockAlert.verdict || 'Scan non prêt ou échoué.')}
              </p>
            </div>

            <div className="mt-3 grid grid-cols-2 gap-2 text-[11px]">
              <div className="rounded-lg bg-surface-container-high px-3 py-2">
                <p className="text-[9px] uppercase tracking-wider text-outline">CRITICAL</p>
                <p className="mt-0.5 font-headline text-sm font-bold text-error">{criticalCount}</p>
              </div>
              <div className="rounded-lg bg-surface-container-high px-3 py-2">
                <p className="text-[9px] uppercase tracking-wider text-outline">HIGH</p>
                <p className="mt-0.5 font-headline text-sm font-bold text-amber-300">{highCount}</p>
              </div>
            </div>

            {blockingFindings.length > 0 && (
              <div className="mt-4 min-h-0 flex-1">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-outline">
                  Vulnérabilités bloquantes · faites défiler
                </p>
                <div className="max-h-56 space-y-1.5 overflow-y-auto rounded-xl border border-outline-variant/20 bg-surface-container-high/60 p-2 pr-1">
                  {blockingFindings.map((item, idx) => (
                    <div
                      key={`all-${item.cveId}-${idx}`}
                      className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-[11px] hover:bg-surface-container"
                    >
                      <span className={`shrink-0 rounded-full border px-1.5 py-0.5 text-[9px] font-bold uppercase ${findingSeverityClass(item.severity)}`}>
                        {item.severity || '?'}
                      </span>
                      <span className="min-w-0 truncate font-mono text-on-surface">{item.cveId || '?'}</span>
                      <span className="ml-auto min-w-0 truncate text-on-surface-variant">
                        {item.packageName}
                        {item.packageVersion ? `@${item.packageVersion}` : ''}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="mt-4 rounded-lg border border-error/30 bg-error/5 px-3 py-2 text-[11px] text-error">
              Continuer déploie quand même (git pull + docker compose). Réservé à une raison métier.
            </div>

            <div className="mt-3 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => setBlockAlert(null)}
                className="rounded-xl px-4 py-2 text-sm text-outline hover:text-on-surface"
              >
                Annuler
              </button>
              <button
                type="button"
                onClick={() => void runDeploy(true)}
                disabled={deploying}
                className="rounded-xl bg-error px-4 py-2 text-sm font-bold text-on-error disabled:opacity-60"
              >
                {deploying ? 'Déploiement…' : 'Continuer quand même'}
              </button>
            </div>
          </div>
        </div>
      )}
      <header className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
        <div className="space-y-2">
          <button
            onClick={() => navigate('/server-config')}
            className="inline-flex items-center gap-2 rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-2 text-sm font-semibold text-on-surface transition-colors hover:border-primary/40 hover:text-primary"
          >
            <span className="material-symbols-outlined text-base">arrow_back</span>
            Retour à la liste
          </button>
          <p className="pt-2 text-xs uppercase tracking-[0.35em] text-outline">Server Detail</p>
          <h1 className="font-headline text-4xl font-bold tracking-tight text-on-surface">
            {selectedServer?.name ?? 'Détail serveur'}
          </h1>
          <p className="max-w-3xl text-sm text-on-surface-variant">
            Vue dediee au serveur selectionne avec inventaire complet, findings, derive de configuration et actualisation live toutes les 30 secondes. Les metriques correspondent a la cible SSH scannee.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className={`inline-flex items-center gap-3 rounded-2xl border px-4 py-3 text-sm ${liveStatusClass}`}>
            <span className={`h-3 w-3 rounded-full ${liveDotClass}`} />
            <div>
              <p className="font-headline text-sm font-semibold">{liveStatusLabel}</p>
              <p className="text-xs opacity-80">{liveStatusHelper}</p>
            </div>
          </div>
          <button
            onClick={() => void refreshLiveServer()}
            disabled={!selectedServer || refreshingLive || scanningServer || loadingDetail}
            className="inline-flex items-center gap-2 rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-5 py-3 text-sm font-headline font-semibold text-on-surface disabled:opacity-60"
          >
            <span className="material-symbols-outlined text-base">sync</span>
            Actualiser
          </button>
          <button
            onClick={handleScanServer}
            disabled={!selectedServer || scanningServer || loadingDetail}
            className="inline-flex items-center gap-2 rounded-2xl bg-primary px-5 py-3 text-sm font-headline font-semibold text-on-primary disabled:opacity-60"
          >
            <span className="material-symbols-outlined text-base">
              {scanningServer ? 'progress_activity' : 'radar'}
            </span>
            {scanningServer ? 'Scan en cours...' : 'Scanner ce serveur'}
          </button>
        </div>
      </header>

      {(message || error) && (
        <div className={`rounded-2xl border px-4 py-3 text-sm ${error ? 'border-error/40 bg-error/10 text-error' : 'border-primary/30 bg-primary/10 text-primary'}`}>
          {error ?? message}
        </div>
      )}

      {selectedServer && (
        <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-5">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <p className="text-xs uppercase tracking-[0.22em] text-outline">Déploiement VPS</p>
              <h2 className="mt-1 font-headline text-xl font-semibold text-on-surface">Git pull + Docker</h2>
              <p className="mt-1 text-sm text-on-surface-variant max-w-2xl">
                Configure le chemin et le dépôt. Nginx reste manuel. CRITICAL / HIGH bloquent, sauf « Continuer quand même ».
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => void handleToggleAutoDeploy()}
                disabled={togglingAuto || deploying || savingDeploy}
                className={`inline-flex items-center gap-2 rounded-2xl border px-4 py-2.5 text-sm font-semibold ${
                  selectedServer.autoDeployEnabled
                    ? 'border-tertiary/40 bg-tertiary/15 text-tertiary'
                    : 'border-outline-variant/30 text-on-surface-variant'
                }`}
              >
                <span className={`h-2.5 w-2.5 rounded-full ${selectedServer.autoDeployEnabled ? 'bg-[#34c759]' : 'bg-outline'}`} />
                Auto-deploy {selectedServer.autoDeployEnabled ? 'ON' : 'OFF'}
              </button>
              <button
                type="button"
                onClick={() => void runDeploy(false)}
                disabled={deploying || savingDeploy}
                className="inline-flex items-center gap-2 rounded-2xl bg-primary px-5 py-2.5 text-sm font-headline font-semibold text-on-primary disabled:opacity-60"
              >
                <span className={`material-symbols-outlined text-base ${deploying ? 'animate-spin' : ''}`}>
                  {deploying ? 'progress_activity' : 'rocket_launch'}
                </span>
                {deploying ? 'Déploiement…' : 'Déployer'}
              </button>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <FormField label="Chemin app" hint="Dossier déjà cloné sur le VPS">
              <input
                value={deployPath}
                onChange={(e) => setDeployPath(e.target.value)}
                placeholder="/var/www/pfe/MEDIANET_PFE-"
                spellCheck={false}
                className={`${fieldClass} font-mono`}
              />
            </FormField>
            <FormField label="Domaine" hint="Lien uniquement, nginx reste manuel">
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="pfe.exemple.com"
                spellCheck={false}
                className={fieldClass}
              />
            </FormField>
            <FormField label="Dépôt Git lié" hint="Le verdict CRITICAL / HIGH de ce dépôt bloque le deploy">
              <select
                value={linkedRepositoryId}
                onChange={(e) => setLinkedRepositoryId(e.target.value ? Number(e.target.value) : '')}
                className={fieldClass}
              >
                <option value="">Aucun dépôt</option>
                {repositories.map((repo) => (
                  <option key={repo.id} value={repo.id}>
                    {repo.repoUrl}
                  </option>
                ))}
              </select>
            </FormField>
            <FormField label="Branche">
              <input
                value={deployBranch}
                onChange={(e) => setDeployBranch(e.target.value)}
                placeholder="main"
                spellCheck={false}
                className={`${fieldClass} font-mono`}
              />
            </FormField>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => void handleSaveDeploySettings()}
              disabled={savingDeploy}
              className="rounded-2xl border border-outline-variant/30 px-4 py-2.5 text-sm font-semibold text-on-surface disabled:opacity-60"
            >
              {savingDeploy ? 'Enregistrement…' : 'Enregistrer le déploiement'}
            </button>
            {selectedServer.domain && (
              <a
                href={`https://${selectedServer.domain}`}
                target="_blank"
                rel="noreferrer"
                className="text-sm text-primary underline"
              >
                https://{selectedServer.domain}
              </a>
            )}
          </div>

          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-outline mb-2">Journal des déploiements</p>
            {deploys.length === 0 ? (
              <p className="text-sm text-on-surface-variant">Aucun déploiement pour l’instant.</p>
            ) : (
              <div className="space-y-2">
                {deploys.map((run) => (
                  <details key={run.id} className="rounded-2xl border border-outline-variant/20 bg-surface-container-high px-4 py-3">
                    <summary className="cursor-pointer text-sm text-on-surface">
                      <span className="font-semibold">{run.status}</span>
                      {' · '}
                      {run.triggerType}
                      {run.commitSha ? ` · ${run.commitSha.slice(0, 8)}` : ''}
                      {run.startedAt ? ` · ${formatDateTime(run.startedAt)}` : ''}
                    </summary>
                    <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap text-[11px] text-on-surface-variant">
                      {run.log || '—'}
                    </pre>
                  </details>
                ))}
              </div>
            )}
          </div>
        </section>
      )}

      {showLocalhostDiagnostic && (
        <section className="rounded-3xl border border-error/30 bg-error/5 p-5">
          <div className="flex items-start gap-3">
            <span className="material-symbols-outlined text-error">lan</span>
            <div className="space-y-4">
              <div>
                <p className="text-xs uppercase tracking-[0.22em] text-error">Diagnostic SSH — localhost</p>
                <p className="mt-2 text-sm font-semibold text-on-surface">
                  Pourquoi la connexion est refusée sur localhost ?
                </p>
                <p className="mt-1 text-sm text-on-surface-variant">
                  Le backend essaie d'ouvrir une vraie connexion SSH vers{' '}
                  <code className="rounded bg-surface-container px-1.5 py-0.5 text-xs font-mono text-on-surface">
                    {selectedServer?.host}:{selectedServer?.port}
                  </code>
                  . Si aucun serveur SSH n'écoute sur ce port de votre machine, la connexion est immédiatement refusée — même si l'application tourne en local.
                </p>
              </div>

              <div className="space-y-3 text-sm">
                <p className="text-xs uppercase tracking-[0.18em] text-outline">Solutions</p>

                <div className="rounded-2xl border border-outline-variant/[0.18] bg-surface-container p-4">
                  <p className="font-semibold text-on-surface">Option 1 — Activer OpenSSH Server sur Windows</p>
                  <ol className="mt-2 list-decimal space-y-1 pl-5 text-on-surface-variant">
                    <li>Paramètres → Système → Fonctionnalités facultatives → Ajouter une fonctionnalité</li>
                    <li>Chercher <strong>OpenSSH Server</strong> et l'installer</li>
                    <li>Dans PowerShell (admin) : <code className="rounded bg-surface-container-low px-1 text-xs font-mono">Start-Service sshd ; Set-Service sshd -StartupType Automatic</code></li>
                    <li>Configurer ce serveur avec <strong>host = 127.0.0.1</strong>, <strong>port = 22</strong>, utilisateur Windows</li>
                  </ol>
                </div>

                <div className="rounded-2xl border border-outline-variant/[0.18] bg-surface-container p-4">
                  <p className="font-semibold text-on-surface">Option 2 — Cibler une VM (VirtualBox / VMware / Hyper-V)</p>
                  <ol className="mt-2 list-decimal space-y-1 pl-5 text-on-surface-variant">
                    <li>Démarrer la VM Linux et vérifier que SSH est actif : <code className="rounded bg-surface-container-low px-1 text-xs font-mono">sudo systemctl start ssh</code></li>
                    <li>Trouver l'IP de la VM : <code className="rounded bg-surface-container-low px-1 text-xs font-mono">ip addr show</code> (souvent 192.168.x.x ou 10.x.x.x)</li>
                    <li>Modifier ce serveur dans l'app et remplacer <strong>localhost</strong> par l'IP réelle de la VM</li>
                    <li><em>Alternative NAT</em> : configurer un forwarding de port hôte → invité (ex: 127.0.0.1:{selectedServer?.port} → :22) dans les paramètres réseau de la VM</li>
                  </ol>
                </div>

                <div className="rounded-2xl border border-outline-variant/[0.18] bg-surface-container p-4">
                  <p className="font-semibold text-on-surface">Option 3 — WSL2 avec SSH</p>
                  <ol className="mt-2 list-decimal space-y-1 pl-5 text-on-surface-variant">
                    <li>Dans WSL2 : <code className="rounded bg-surface-container-low px-1 text-xs font-mono">sudo apt install openssh-server && sudo service ssh start</code></li>
                    <li>WSL2 utilise un port aléatoire ; trouver l'IP WSL : <code className="rounded bg-surface-container-low px-1 text-xs font-mono">wsl hostname -I</code></li>
                    <li>Configurer ce serveur avec cette IP et port 22</li>
                  </ol>
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {loadingDetail ? (
        <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-12 text-center text-sm text-outline">
          Chargement du serveur...
        </div>
      ) : !selectedServer ? (
        <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-12 text-center text-sm text-on-surface-variant">
          Impossible d’afficher ce serveur. Reviens à la liste puis réessaie.
        </div>
      ) : (
        <>
          <section className="rounded-3xl border border-secondary/25 bg-secondary/10 p-5 text-sm text-on-surface">
            <div className="flex items-start gap-3">
              <span className="material-symbols-outlined text-secondary">info</span>
              <div className="space-y-3">
                <div>
                  <p className="text-xs uppercase tracking-[0.22em] text-secondary">Portee des mesures</p>
                  <p className="mt-2 text-on-surface-variant">{measurementScope}</p>
                </div>
                {environmentHints.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {environmentHints.map((hint) => (
                      <span key={hint} className="rounded-full border border-secondary/25 bg-surface-container px-3 py-1 text-xs font-medium text-secondary">
                        {hint}
                      </span>
                    ))}
                  </div>
                ) : null}
              </div>
            </div>
          </section>

          <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container-low p-6">
            <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded-full border px-3 py-1 text-[10px] font-semibold uppercase ${typeBadgeClass[selectedServer.nodeType] || typeBadgeClass.CUSTOM}`}>
                    {formatNodeType(selectedServer.nodeType)}
                  </span>
                  <span className={`rounded-full border px-3 py-1 text-[10px] font-semibold uppercase ${selectedServer.latestStatus === 'FAILED' ? 'border-error/30 bg-error/10 text-error' : 'border-tertiary/30 bg-tertiary/10 text-tertiary'}`}>
                    {selectedServer.latestStatus ?? 'NOT SCANNED'}
                  </span>
                </div>
                <h2 className="mt-4 font-headline text-3xl font-bold text-on-surface">{selectedServer.name}</h2>
                <p className="mt-2 text-sm text-on-surface-variant">
                  {selectedServer.host}:{selectedServer.port} · utilisateur SSH {selectedServer.username} · dernière synchronisation {formatDateTime(selectedServer.lastScannedAt)}
                </p>
                {selectedServer.description ? (
                  <p className="mt-3 max-w-3xl text-sm text-on-surface-variant">{selectedServer.description}</p>
                ) : null}
              </div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="rounded-2xl border border-error/20 bg-error/10 px-4 py-4">
                  <p className="text-[10px] uppercase tracking-[0.18em] text-error">Critical</p>
                  <p className="mt-2 font-headline text-2xl font-bold text-error">{selectedServer.criticalCount}</p>
                </div>
                <div className="rounded-2xl border border-secondary/20 bg-secondary/10 px-4 py-4">
                  <p className="text-[10px] uppercase tracking-[0.18em] text-secondary">Warning</p>
                  <p className="mt-2 font-headline text-2xl font-bold text-secondary">{selectedServer.warningCount}</p>
                </div>
                <div className="rounded-2xl border border-primary/20 bg-primary/10 px-4 py-4">
                  <p className="text-[10px] uppercase tracking-[0.18em] text-primary">Info</p>
                  <p className="mt-2 font-headline text-2xl font-bold text-primary">{selectedServer.infoCount}</p>
                </div>
              </div>
            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <MetricCard icon="memory" label="OS / Kernel" value={selectedServer.osName || '—'} helper={selectedServer.kernelVersion || 'Version du kernel non collectée'} />
              <MetricCard icon="speed" label="CPU de la cible" value={selectedServer.cpuSummary || '—'} helper={selectedServer.hostname || 'Hostname non remonté'} />
              <MetricCard icon="developer_board" label="Memoire de la cible" value={selectedServer.memorySummary || '—'} helper={selectedServer.dockerSummary || 'Docker non détecté'} />
              <MetricCard icon="hard_drive_2" label="Disque racine / Securite" value={selectedServer.diskSummary || '—'} helper={`FS / distant · Pare-feu: ${selectedServer.firewallStatus || '—'} · SSH root: ${selectedServer.sshRootLogin || '—'}`} />
            </div>
          </section>

          <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
            <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="text-xs uppercase tracking-[0.22em] text-outline">Findings</p>
                  <h3 className="mt-2 font-headline text-2xl font-semibold text-on-surface">Alertes & recommandations</h3>
                </div>
                <span className="rounded-full border border-outline-variant/[0.2] px-3 py-1 text-xs text-on-surface-variant">
                  {findings.length} findings
                </span>
              </div>

              <div className="mt-5 space-y-3">
                {findings.length === 0 ? (
                  <div className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-5 text-sm text-on-surface-variant">
                    Aucune alerte remontée pour le dernier snapshot. Lance un scan pour alimenter cette vue.
                  </div>
                ) : findings.map((finding) => (
                  <div key={finding.id} className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low p-4">
                    <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase ${severityBadgeClass[finding.severity] || severityBadgeClass.INFO}`}>
                            {finding.severity}
                          </span>
                          <span className="text-xs uppercase tracking-[0.18em] text-outline">{finding.category}</span>
                        </div>
                        <h4 className="mt-3 font-headline text-lg font-semibold text-on-surface">{finding.title}</h4>
                        <p className="mt-2 text-sm text-on-surface-variant">{finding.description}</p>
                      </div>
                      {finding.detectedValue ? (
                        <div className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container px-3 py-2 text-xs text-on-surface-variant">
                          {finding.detectedValue}
                        </div>
                      ) : null}
                    </div>
                    <div className="mt-3 rounded-2xl bg-primary/5 px-4 py-3 text-sm text-primary">
                      {finding.recommendation}
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <div className="space-y-6">
              <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6">
                <p className="text-xs uppercase tracking-[0.22em] text-outline">Drift Detection</p>
                <h3 className="mt-2 font-headline text-2xl font-semibold text-on-surface">Dérive de configuration</h3>
                <div className="mt-5 flex flex-wrap gap-2">
                  {(selectedServer.driftChanges.length ? selectedServer.driftChanges : ['Aucune donnée de dérive']).map((change) => (
                    <span key={change} className="rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
                      {change}
                    </span>
                  ))}
                </div>

                <div className="mt-6 space-y-3">
                  {selectedServer.recentSnapshots.map((snapshot) => (
                    <div key={snapshot.id} className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-3">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <p className="text-sm font-medium text-on-surface">Snapshot #{snapshot.id}</p>
                          <p className="mt-1 text-xs text-outline">{formatDateTime(snapshot.collectedAt)}</p>
                        </div>
                        <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase ${snapshot.status === 'FAILED' ? 'border-error/30 bg-error/10 text-error' : 'border-tertiary/30 bg-tertiary/10 text-tertiary'}`}>
                          {snapshot.status}
                        </span>
                      </div>
                      <p className="mt-3 text-sm text-on-surface-variant">{snapshot.summary}</p>
                    </div>
                  ))}
                </div>
              </section>

              <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6">
                <p className="text-xs uppercase tracking-[0.22em] text-outline">Exposure & TLS</p>
                <h3 className="mt-2 font-headline text-2xl font-semibold text-on-surface">Résumé opérationnel</h3>
                <div className="mt-5 space-y-3 text-sm text-on-surface-variant">
                  <div className="rounded-2xl bg-surface-container-low px-4 py-3">
                    <span className="text-outline">Certificats:</span> {selectedServer.certificateSummary || '—'}
                  </div>
                  <div className="rounded-2xl bg-surface-container-low px-4 py-3">
                    <span className="text-outline">Docker:</span> {selectedServer.dockerSummary || '—'}
                  </div>
                  <div className="rounded-2xl bg-surface-container-low px-4 py-3">
                    <span className="text-outline">Synthèse:</span> {selectedServer.summary || '—'}
                  </div>
                </div>
              </section>
            </div>
          </div>

          <div className="grid gap-6 xl:grid-cols-2">
            <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-[0.22em] text-outline">Ports</p>
                  <h3 className="mt-2 font-headline text-2xl font-semibold text-on-surface">Ports ouverts</h3>
                </div>
                <span className="rounded-full border border-outline-variant/[0.2] px-3 py-1 text-xs text-on-surface-variant">
                  {ports.length}
                </span>
              </div>

              <div className="mt-5 space-y-3">
                {ports.length === 0 ? (
                  <div className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-5 text-sm text-on-surface-variant">
                    Aucun port remonté. Le scan SSH n’a pas encore collecté `ss -tulpen` sur ce nœud.
                  </div>
                ) : ports.map((port) => (
                  <div key={`${port.portNumber}-${port.protocol}-${port.bindAddress}`} className="flex items-center justify-between gap-4 rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-headline text-lg font-semibold text-on-surface">{port.portNumber}</span>
                        <span className="rounded-full border border-outline-variant/[0.2] px-2 py-0.5 text-[10px] uppercase text-outline">{port.protocol}</span>
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase ${port.exposureLevel === 'PUBLIC' ? 'border-error/30 bg-error/10 text-error' : port.exposureLevel === 'INTERNAL' ? 'border-secondary/30 bg-secondary/10 text-secondary' : 'border-tertiary/30 bg-tertiary/10 text-tertiary'}`}>
                          {port.exposureLevel}
                        </span>
                      </div>
                      <p className="mt-1 text-sm text-on-surface-variant">{port.bindAddress} · {port.processName || port.serviceName || 'unknown process'}</p>
                    </div>
                    <span className="text-xs uppercase tracking-[0.18em] text-outline">{port.state}</span>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-[0.22em] text-outline">Services</p>
                  <h3 className="mt-2 font-headline text-2xl font-semibold text-on-surface">Services systemd</h3>
                </div>
                <span className="rounded-full border border-outline-variant/[0.2] px-3 py-1 text-xs text-on-surface-variant">
                  {services.length}
                </span>
              </div>

              <div className="mt-5 space-y-3">
                {services.length === 0 ? (
                  <div className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-5 text-sm text-on-surface-variant">
                    Aucun service systemd remonté pour ce snapshot.
                  </div>
                ) : services.map((service) => (
                  <div key={service.serviceName} className="flex items-center justify-between gap-4 rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-4">
                    <div>
                      <p className="font-medium text-on-surface">{service.serviceName}</p>
                      <p className="mt-1 text-sm text-on-surface-variant">{service.state} · {service.subState} · enabled={service.enabledStatus}</p>
                    </div>
                    <span className={`rounded-full border px-2.5 py-1 text-[10px] uppercase ${service.state === 'active' ? 'border-tertiary/30 bg-tertiary/10 text-tertiary' : 'border-secondary/30 bg-secondary/10 text-secondary'}`}>
                      {service.state}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          </div>

          <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-[0.22em] text-outline">Live Journal</p>
                <h3 className="mt-2 font-headline text-2xl font-semibold text-on-surface">Journal système récent</h3>
              </div>
              <span className="rounded-full border border-outline-variant/[0.2] px-3 py-1 text-xs text-on-surface-variant">
                {selectedServer.latestStatus ?? 'N/A'}
              </span>
            </div>
            <div className="mt-5 rounded-3xl border border-primary/10 bg-black/35 p-4 font-mono text-[12px] leading-relaxed text-tertiary/80">
              <pre className="whitespace-pre-wrap">{selectedServer.journalExcerpt || 'Aucun journal disponible pour ce serveur.'}</pre>
            </div>
          </section>
        </>
      )}
    </div>
  );
};

export default ServerConfigDetail;