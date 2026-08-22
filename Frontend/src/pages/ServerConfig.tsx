import React, { useCallback, useEffect, useState } from 'react';
import ConfirmModal from '../components/ConfirmModal';
import { useNavigate } from 'react-router-dom';
import {
  createServerNode,
  deleteServerNode,
  getLiveServerNode,
  getPortRecommendations,
  getRepositories,
  getServerNode,
  getServerNodes,
  scanServerNode,
  updateServerNode,
  type PortExposureDto,
  type PortRecommendationDto,
  type RepositoryDto,
  type ServerNodeDetailDto,
  type ServerNodeDto,
  type ServerNodeRequest,
  type ServiceStatusDto,
} from '../services/api';
import {
  applyServerTemplate,
  deployStrategyOptions,
  emptyServerForm,
  environmentOptions,
  extractApiError,
  fieldClass,
  FormField,
  FormSection,
  formatDateTime,
  formatNodeType,
  nodeTypeOptions,
  parseTagsInput,
  serverTemplateOptions,
  stringifyTags,
  validateServerForm,
} from './serverConfigShared';

type InventoryLiveState = 'UNKNOWN' | 'CHECKING' | 'ONLINE' | 'OFFLINE';

type InventoryLiveSnapshot = {
  latestStatus?: string | null;
  lastScannedAt?: string | null;
  criticalCount?: number;
  warningCount?: number;
  infoCount?: number;
  osName?: string | null;
  checkedAt?: string | null;
  liveState: InventoryLiveState;
  liveError?: string | null;
};

type InventoryServerCard = ServerNodeDto & InventoryLiveSnapshot;

const liveStatusPresentation: Record<InventoryLiveState, { label: string; className: string; dotClass: string }> = {
  UNKNOWN: {
    label: 'État inconnu',
    className: 'border-outline-variant/[0.2] bg-surface-container text-on-surface-variant',
    dotClass: 'bg-outline',
  },
  CHECKING: {
    label: 'Vérification',
    className: 'border-primary/30 bg-primary/10 text-primary',
    dotClass: 'bg-primary animate-pulse',
  },
  ONLINE: {
    label: 'Live OK',
    className: 'border-tertiary/30 bg-tertiary/10 text-tertiary',
    dotClass: 'bg-tertiary',
  },
  OFFLINE: {
    label: 'Live KO',
    className: 'border-error/30 bg-error/10 text-error',
    dotClass: 'bg-error',
  },
};

const ServerConfig: React.FC = () => {
  const navigate = useNavigate();
  const [servers, setServers] = useState<ServerNodeDto[]>([]);
  const [liveSnapshots, setLiveSnapshots] = useState<Record<number, InventoryLiveSnapshot>>({});
  const [loadingList, setLoadingList] = useState(true);
  const [refreshingInventory, setRefreshingInventory] = useState(false);
  const [savingServer, setSavingServer] = useState(false);
  const [deletingServerId, setDeletingServerId] = useState<number | null>(null);
  const [loadingEditorId, setLoadingEditorId] = useState<number | null>(null);
  const [showServerForm, setShowServerForm] = useState(false);
  const [editingServerId, setEditingServerId] = useState<number | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [formErrors, setFormErrors] = useState<string[]>([]);
  const [deleteModal, setDeleteModal] = useState<{ open: boolean; server: ServerNodeDto | null }>({ open: false, server: null });
  const [form, setForm] = useState<ServerNodeRequest>(emptyServerForm);
  const [searchQuery, setSearchQuery] = useState('');
  const [environmentFilter, setEnvironmentFilter] = useState('ALL');
  const [nodeTypeFilter, setNodeTypeFilter] = useState('ALL');
  const [liveFilter, setLiveFilter] = useState('ALL');
  const [osFilter, setOsFilter] = useState('ALL');
  const [repositories, setRepositories] = useState<RepositoryDto[]>([]);

  type ScanModalState = {
    open: boolean;
    serverId: number | null;
    serverName: string;
    loading: boolean;
    result: ServerNodeDetailDto | null;
    error: string | null;
    portRecs: Map<number, PortRecommendationDto> | null;
    loadingRecs: boolean;
    recsError: string | null;
  };
  const [scanModal, setScanModal] = useState<ScanModalState>({
    open: false,
    serverId: null,
    serverName: '',
    loading: false,
    result: null,
    error: null,
    portRecs: null,
    loadingRecs: false,
    recsError: null,
  });

  const handleOpenScanModal = async (server: InventoryServerCard) => {
    setScanModal({ open: true, serverId: server.id, serverName: server.name, loading: true, result: null, error: null, portRecs: null, loadingRecs: false, recsError: null });
    try {
      const { data } = await scanServerNode(server.id);
      setScanModal((prev) => ({ ...prev, loading: false, result: data }));
    } catch (err: any) {
      setScanModal((prev) => ({ ...prev, loading: false, error: extractApiError(err, 'Le scan du serveur a échoué.') }));
    }
  };

  const handleFetchPortRecommendations = async () => {
    if (!scanModal.serverId) return;
    setScanModal((prev) => ({ ...prev, loadingRecs: true, recsError: null, portRecs: null }));
    try {
      const { data } = await getPortRecommendations(scanModal.serverId);
      const map = new Map<number, PortRecommendationDto>();
      data.forEach((rec) => map.set(rec.portNumber, rec));
      setScanModal((prev) => ({ ...prev, loadingRecs: false, portRecs: map }));
    } catch (err: any) {
      setScanModal((prev) => ({
        ...prev,
        loadingRecs: false,
        recsError: extractApiError(err, 'Impossible d’obtenir les recommandations IA.'),
      }));
    }
  };

  const refreshLiveCards = useCallback(async (inventory: ServerNodeDto[]) => {
    if (inventory.length === 0) {
      setLiveSnapshots({});
      return;
    }

    setRefreshingInventory(true);
    setLiveSnapshots((current) => {
      const next = { ...current };
      inventory.forEach((server) => {
        next[server.id] = {
          ...current[server.id],
          liveState: 'CHECKING',
          liveError: null,
        };
      });
      return next;
    });

    const settled = await Promise.allSettled(
      inventory.map(async (server) => {
        const { data } = await getLiveServerNode(server.id);
        return {
          id: server.id,
          snapshot: {
            latestStatus: data.latestStatus,
            lastScannedAt: data.lastScannedAt,
            criticalCount: data.criticalCount,
            warningCount: data.warningCount,
            infoCount: data.infoCount,
            osName: data.osName,
            checkedAt: new Date().toISOString(),
            liveState: data.latestStatus === 'FAILED' ? 'OFFLINE' as InventoryLiveState : 'ONLINE' as InventoryLiveState,
            liveError: null,
          },
        };
      }),
    );

    setLiveSnapshots((current) => {
      const next = { ...current };
      settled.forEach((result, index) => {
        const serverId = inventory[index].id;
        if (result.status === 'fulfilled') {
          next[serverId] = result.value.snapshot;
          return;
        }

        next[serverId] = {
          ...current[serverId],
          checkedAt: new Date().toISOString(),
          liveState: 'OFFLINE',
          liveError: extractApiError(result.reason, 'Le test live du serveur a échoué.'),
        };
      });
      return next;
    });

    setRefreshingInventory(false);
  }, []);

  const loadServers = useCallback(async () => {
    setLoadingList(true);
    setError(null);
    try {
      const { data } = await getServerNodes();
      setServers(data);
      void refreshLiveCards(data);
    } catch (err: any) {
      setError(extractApiError(err, 'Impossible de charger les serveurs.'));
    } finally {
      setLoadingList(false);
    }
  }, [refreshLiveCards]);

  useEffect(() => {
    void loadServers();
  }, [loadServers]);

  useEffect(() => {
    void getRepositories()
      .then((res) => setRepositories(res.data ?? []))
      .catch(() => setRepositories([]));
  }, []);

  const resetServerForm = () => {
    setEditingServerId(null);
    setForm(emptyServerForm);
    setFormErrors([]);
    setShowServerForm(false);
  };

  const handleOpenCreateForm = () => {
    setMessage(null);
    setError(null);
    setFormErrors([]);
    if (showServerForm && editingServerId === null) {
      resetServerForm();
      return;
    }
    setEditingServerId(null);
    setForm(emptyServerForm);
    setShowServerForm(true);
  };

  const handleEditServer = async (serverId: number) => {
    setLoadingEditorId(serverId);
    setMessage(null);
    setError(null);
    setFormErrors([]);
    try {
      const { data } = await getServerNode(serverId);
      setEditingServerId(serverId);
      setForm({
        name: data.name,
        host: data.host,
        port: data.port,
        username: data.username,
        nodeType: data.nodeType,
        authMethod: data.authMethod as ServerNodeRequest['authMethod'],
        environment: data.environment ?? 'LAB',
        templateKey: data.templateKey ?? 'CUSTOM',
        owner: data.owner ?? '',
        clientName: data.clientName ?? '',
        projectName: data.projectName ?? '',
        runbookUrl: data.runbookUrl ?? '',
        tags: data.tags ?? [],
        notes: data.notes ?? '',
        password: '',
        privateKey: '',
        privateKeyPassphrase: '',
        description: data.description ?? '',
        deployPath: data.deployPath ?? '',
        domain: data.domain ?? '',
        linkedRepositoryId: data.linkedRepositoryId ?? null,
        deployBranch: data.deployBranch ?? 'main',
        deployStrategy: data.deployStrategy ?? 'DOCKER_COMPOSE',
      });
      setShowServerForm(true);
    } catch (err: any) {
      setError(extractApiError(err, 'Impossible de charger ce serveur pour édition.'));
    } finally {
      setLoadingEditorId(null);
    }
  };

  const handleSubmitServer = async (event: React.FormEvent) => {
    event.preventDefault();
    const isEditing = editingServerId !== null;
    const validationErrors = validateServerForm(form, isEditing);
    if (validationErrors.length > 0) {
      setFormErrors(validationErrors);
      return;
    }

    setSavingServer(true);
    setMessage(null);
    setError(null);
    setFormErrors([]);
    try {
      const payload: ServerNodeRequest = {
        ...form,
        name: form.name.trim(),
        host: form.host.trim(),
        port: Number(form.port) || 22,
        username: form.username.trim(),
        environment: form.environment?.trim(),
        templateKey: form.templateKey?.trim(),
        owner: form.owner?.trim(),
        clientName: form.clientName?.trim(),
        projectName: form.projectName?.trim(),
        runbookUrl: form.runbookUrl?.trim(),
        notes: form.notes?.trim(),
        description: form.description?.trim(),
        tags: (form.tags ?? []).map((tag) => tag.trim()).filter(Boolean),
        deployPath: form.deployPath?.trim() || '',
        domain: form.domain?.trim() || '',
        deployBranch: form.deployBranch?.trim() || 'main',
        deployStrategy: form.deployStrategy || 'DOCKER_COMPOSE',
        linkedRepositoryId: form.linkedRepositoryId ?? null,
      };

      const { data } = isEditing && editingServerId
        ? await updateServerNode(editingServerId, payload)
        : await createServerNode(payload);

      resetServerForm();
      setMessage(isEditing ? `Serveur ${data.name} mis à jour.` : `Serveur ${data.name} ajouté.`);
      await loadServers();
    } catch (err: any) {
      setError(extractApiError(err, isEditing
        ? 'Impossible de modifier le serveur.'
        : 'Impossible d’ajouter le serveur.'));
    } finally {
      setSavingServer(false);
    }
  };

  const handleDeleteServer = (server: ServerNodeDto) => {
    setDeleteModal({ open: true, server });
  };

  const doDeleteServer = async (server: ServerNodeDto) => {
    setDeleteModal({ open: false, server: null });
    setDeletingServerId(server.id);
    setMessage(null);
    setError(null);
    try {
      await deleteServerNode(server.id);
      if (editingServerId === server.id) {
        resetServerForm();
      }
      setMessage(`Serveur ${server.name} supprimé.`);
      await loadServers();
    } catch (err: any) {
      setError(extractApiError(err, 'Impossible de supprimer le serveur.'));
    } finally {
      setDeletingServerId(null);
    }
  };

  const updateForm = <K extends keyof ServerNodeRequest>(key: K, value: ServerNodeRequest[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const handleTemplateChange = (templateKey: string) => {
    setForm((current) => applyServerTemplate(current, templateKey));
    setFormErrors([]);
  };

  const serverCards: InventoryServerCard[] = servers.map((server) => {
    const live = liveSnapshots[server.id];
    return {
      ...server,
      latestStatus: live?.latestStatus ?? server.latestStatus,
      lastScannedAt: live?.lastScannedAt ?? server.lastScannedAt,
      criticalCount: live?.criticalCount ?? server.criticalCount,
      warningCount: live?.warningCount ?? server.warningCount,
      infoCount: live?.infoCount ?? server.infoCount,
      osName: live?.osName ?? server.osName,
      checkedAt: live?.checkedAt ?? null,
      liveState: live?.liveState ?? 'UNKNOWN',
      liveError: live?.liveError ?? null,
    };
  });

  const osOptions = Array.from(new Set(serverCards.map((server) => server.osName).filter(Boolean))) as string[];

  const filteredServers = serverCards.filter((server) => {
    const searchable = [
      server.name,
      server.host,
      server.username,
      server.nodeType,
      server.environment,
      server.owner,
      server.clientName,
      server.projectName,
      server.description,
      server.notes,
      server.osName,
      server.domain,
      server.deployPath,
      server.deployBranch,
      ...(server.tags ?? []),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();

    const matchesSearch = !searchQuery.trim() || searchable.includes(searchQuery.trim().toLowerCase());
    const matchesEnvironment = environmentFilter === 'ALL' || server.environment === environmentFilter;
    const matchesNodeType = nodeTypeFilter === 'ALL' || server.nodeType === nodeTypeFilter;
    const matchesLive = liveFilter === 'ALL' || server.liveState === liveFilter;
    const matchesOs = osFilter === 'ALL' || server.osName === osFilter;

    return matchesSearch && matchesEnvironment && matchesNodeType && matchesLive && matchesOs;
  });

  return (
    <div className="space-y-6">
      {scanModal.open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-16 backdrop-blur-sm">
          <div className="w-full max-w-3xl rounded-3xl border border-outline-variant/[0.2] bg-surface-container shadow-2xl">
            {/* Header */}
            <div className="flex items-center justify-between gap-4 border-b border-outline-variant/[0.14] px-6 py-5">
              <div>
                <p className="text-[11px] uppercase tracking-[0.26em] text-outline">Scan de ports</p>
                <h2 className="mt-1 font-headline text-xl font-bold text-on-surface">{scanModal.serverName}</h2>
              </div>
              <button
                onClick={() => setScanModal((prev) => ({ ...prev, open: false }))}
                className="rounded-full border border-outline-variant/[0.2] p-2 text-on-surface-variant transition hover:border-primary/40 hover:text-primary"
              >
                <span className="material-symbols-outlined text-[18px]">close</span>
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Loading */}
              {scanModal.loading && (
                <div className="flex flex-col items-center gap-4 py-10 text-on-surface-variant">
                  <span className="material-symbols-outlined animate-spin text-4xl text-primary">progress_activity</span>
                  <p className="text-sm">Connexion SSH et scan en cours…</p>
                </div>
              )}

              {/* Error */}
              {!scanModal.loading && scanModal.error && (
                <div className="rounded-2xl border border-error/40 bg-error/10 px-4 py-4 text-sm text-error">
                  <p className="font-semibold">Échec du scan</p>
                  <p className="mt-1">{scanModal.error}</p>
                </div>
              )}

              {/* Result */}
              {!scanModal.loading && scanModal.result && (
                <>
                  {/* System info */}
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                    <div className="rounded-2xl bg-surface-container-low px-4 py-3">
                      <p className="text-[10px] uppercase tracking-[0.18em] text-outline">OS</p>
                      <p className="mt-1 text-sm font-semibold text-on-surface">{scanModal.result.osName || '—'}</p>
                    </div>
                    <div className="rounded-2xl bg-surface-container-low px-4 py-3">
                      <p className="text-[10px] uppercase tracking-[0.18em] text-outline">Pare-feu</p>
                      <p className="mt-1 text-sm font-semibold text-on-surface">{scanModal.result.firewallStatus || '—'}</p>
                    </div>
                    <div className="rounded-2xl bg-surface-container-low px-4 py-3">
                      <p className="text-[10px] uppercase tracking-[0.18em] text-outline">Ports ouverts</p>
                      <p className="mt-1 font-headline text-xl font-bold text-tertiary">{(scanModal.result.ports ?? []).length}</p>
                    </div>
                    <div className="rounded-2xl bg-surface-container-low px-4 py-3">
                      <p className="text-[10px] uppercase tracking-[0.18em] text-outline">SSH Root</p>
                      <p className="mt-1 text-sm font-semibold text-on-surface">{scanModal.result.sshRootLogin || '—'}</p>
                    </div>
                  </div>

                  {/* Ports */}
                  <div>
                    <div className="mb-3 flex items-center justify-between">
                      <h3 className="font-headline text-base font-semibold text-on-surface">Ports exposés</h3>
                      <div className="flex items-center gap-2">
                        <span className="rounded-full border border-outline-variant/[0.2] px-3 py-1 text-xs text-on-surface-variant">
                          {(scanModal.result.ports ?? []).length} port(s)
                        </span>
                        {(scanModal.result.ports ?? []).length > 0 && (
                          <button
                            id="btn-port-ai-recs"
                            onClick={() => void handleFetchPortRecommendations()}
                            disabled={scanModal.loadingRecs}
                            className="inline-flex items-center gap-1.5 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-semibold text-primary transition hover:bg-primary/20 disabled:opacity-60"
                          >
                            {scanModal.loadingRecs ? (
                              <>
                                <span className="material-symbols-outlined animate-spin text-sm">progress_activity</span>
                                Analyse IA...
                              </>
                            ) : (
                              <>
                                <span className="material-symbols-outlined text-sm">auto_awesome</span>
                                {scanModal.portRecs ? 'Actualiser les recommandations' : 'Recommandations IA'}
                              </>
                            )}
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Erreur recommandations */}
                    {scanModal.recsError && (
                      <div className="mb-3 rounded-2xl border border-error/40 bg-error/10 px-3 py-2 text-xs text-error">
                        {scanModal.recsError}
                      </div>
                    )}

                    {(scanModal.result.ports ?? []).length === 0 ? (
                      <div className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-5 text-sm text-on-surface-variant">
                        Aucun port remonтé. Le scan SSH n'a pas pu lister les ports de ce nœud.
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {(scanModal.result.ports ?? []).map((port: PortExposureDto) => {
                          const rec = scanModal.portRecs?.get(port.portNumber);
                          const sevClass = rec
                            ? rec.severity === 'CRITICAL'
                              ? 'border-error/40 bg-error/5'
                              : rec.severity === 'WARNING'
                              ? 'border-[#f97316]/30 bg-[#f97316]/5'
                              : 'border-tertiary/20 bg-tertiary/5'
                            : 'border-outline-variant/[0.14] bg-surface-container-low';

                          return (
                            <div
                              key={`${port.portNumber}-${port.protocol}-${port.bindAddress}`}
                              className={`rounded-2xl border px-4 py-3 transition-all ${sevClass}`}
                            >
                              {/* Port header row */}
                              <div className="flex items-center justify-between gap-4">
                                <div className="flex items-center gap-3">
                                  <span className="font-headline text-lg font-bold text-on-surface w-12">{port.portNumber}</span>
                                  <span className="rounded-full border border-outline-variant/[0.2] px-2 py-0.5 text-[10px] uppercase text-outline">{port.protocol}</span>
                                  <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase font-semibold ${
                                    port.exposureLevel === 'PUBLIC'
                                      ? 'border-error/30 bg-error/10 text-error'
                                      : port.exposureLevel === 'INTERNAL'
                                      ? 'border-secondary/30 bg-secondary/10 text-secondary'
                                      : 'border-tertiary/30 bg-tertiary/10 text-tertiary'
                                  }`}>
                                    {port.exposureLevel}
                                  </span>
                                  <span className="text-sm text-on-surface-variant">{port.processName || port.serviceName || 'unknown'}</span>
                                </div>
                                <div className="flex items-center gap-3">
                                  {rec && (
                                    <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase font-bold ${
                                      rec.severity === 'CRITICAL'
                                        ? 'border-error/50 bg-error/15 text-error'
                                        : rec.severity === 'WARNING'
                                        ? 'border-[#f97316]/40 bg-[#f97316]/10 text-[#f97316]'
                                        : 'border-tertiary/30 bg-tertiary/10 text-tertiary'
                                    }`}>
                                      {rec.severity === 'CRITICAL' ? '⚠ CRITIQUE' : rec.severity === 'WARNING' ? '⚠ AVERTISSEMENT' : 'ℹ INFO'}
                                    </span>
                                  )}
                                  <span className="text-xs text-outline">{port.bindAddress}</span>
                                  <span className="text-xs uppercase tracking-[0.18em] text-outline">{port.state}</span>
                                </div>
                              </div>

                              {/* AI recommendation block */}
                              {scanModal.portRecs && (
                                <div className="mt-3 space-y-2 border-t border-outline-variant/[0.15] pt-3">
                                  {rec ? (
                                    <>
                                      {/* Risk reason */}
                                      <p className="text-xs text-on-surface-variant leading-relaxed">
                                        <span className="font-semibold text-on-surface">⛔ Risque :</span>{' '}
                                        {rec.riskReason}
                                      </p>

                                      {/* Disable command */}
                                      {rec.disableCommand && !rec.disableCommand.startsWith('#') && (
                                        <div>
                                          <p className="mb-1 text-[10px] uppercase tracking-[0.18em] text-outline">Commande de désactivation</p>
                                          <div className="group relative flex items-start gap-2 rounded-xl bg-surface-container px-3 py-2">
                                            <code className="flex-1 break-all font-mono text-[11px] text-on-surface">{rec.disableCommand}</code>
                                            <button
                                              id={`btn-copy-port-${port.portNumber}`}
                                              onClick={() => void navigator.clipboard.writeText(rec.disableCommand)}
                                              title="Copier la commande"
                                              className="shrink-0 rounded-lg p-1 text-outline transition hover:bg-primary/10 hover:text-primary"
                                            >
                                              <span className="material-symbols-outlined text-[15px]">content_copy</span>
                                            </button>
                                          </div>
                                        </div>
                                      )}

                                      {/* Port normal (INFO with comment command) */}
                                      {rec.disableCommand?.startsWith('#') && (
                                        <p className="text-[11px] italic text-outline">{rec.disableCommand}</p>
                                      )}
                                    </>
                                  ) : (
                                    <p className="text-xs text-on-surface-variant leading-relaxed">
                                      <span className="font-semibold text-on-surface">⛔ Risque :</span> Analyse IA indisponible. Vérifiez manuellement si ce port est nécessaire.
                                    </p>
                                  )}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* Services */}
                  {(scanModal.result.services ?? []).length > 0 && (
                    <div>
                      <div className="mb-3 flex items-center justify-between">
                        <h3 className="font-headline text-base font-semibold text-on-surface">Services systemd</h3>
                        <span className="rounded-full border border-outline-variant/[0.2] px-3 py-1 text-xs text-on-surface-variant">
                          {(scanModal.result.services ?? []).length} service(s)
                        </span>
                      </div>
                      <div className="space-y-2">
                        {(scanModal.result.services ?? []).map((svc: ServiceStatusDto) => (
                          <div
                            key={svc.serviceName}
                            className="flex items-center justify-between gap-4 rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-3"
                          >
                            <p className="text-sm font-medium text-on-surface">{svc.serviceName}</p>
                            <div className="flex items-center gap-2">
                              <span className={`rounded-full border px-2.5 py-1 text-[10px] uppercase ${
                                svc.state === 'active'
                                  ? 'border-tertiary/30 bg-tertiary/10 text-tertiary'
                                  : 'border-secondary/30 bg-secondary/10 text-secondary'
                              }`}>{svc.state}</span>
                              <span className="text-xs text-outline">{svc.enabledStatus}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      <ConfirmModal
        open={deleteModal.open}
        title="Supprimer le serveur"
        message={`Supprimer le serveur ${deleteModal.server?.name} ? Cette action est définitive.`}
        confirmLabel="Supprimer"
        danger
        onConfirm={() => deleteModal.server && doDeleteServer(deleteModal.server)}
        onCancel={() => setDeleteModal({ open: false, server: null })}
      />
      <header className="space-y-5">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-[0.35em] text-outline">Server Config</p>
            <h1 className="font-headline text-4xl font-bold tracking-tight text-on-surface">Serveurs</h1>
            <p className="max-w-2xl text-sm leading-relaxed text-on-surface-variant">
              Inventaire SSH et centre de déploiement. Configurez le VPS une fois, puis poussez votre code :
              Vulnix scanne, et déploie seulement si le verdict CRITICAL / HIGH passe.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => void refreshLiveCards(servers)}
              disabled={refreshingInventory || loadingList || servers.length === 0}
              className="inline-flex items-center gap-2 rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-5 py-3 text-sm font-semibold text-on-surface transition hover:border-primary/40 hover:text-primary disabled:opacity-60"
            >
              <span className="material-symbols-outlined text-base">sync</span>
              {refreshingInventory ? 'Actualisation…' : 'Actualiser'}
            </button>
            <button
              onClick={handleOpenCreateForm}
              className="inline-flex items-center gap-2 rounded-2xl bg-primary px-5 py-3 text-sm font-headline font-semibold text-on-primary transition hover:opacity-90"
            >
              <span className="material-symbols-outlined text-base">
                {showServerForm && editingServerId === null ? 'close' : 'add'}
              </span>
              {showServerForm && editingServerId === null ? 'Fermer' : 'Ajouter un serveur'}
            </button>
          </div>
        </div>

        {servers.length > 0 ? (
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {[
              { label: 'Serveurs', value: servers.length, icon: 'dns' },
              { label: 'En ligne', value: serverCards.filter((s) => s.liveState === 'ONLINE').length, icon: 'wifi' },
              { label: 'Hors ligne', value: serverCards.filter((s) => s.liveState === 'OFFLINE').length, icon: 'wifi_off' },
              { label: 'Auto-deploy', value: servers.filter((s) => s.autoDeployEnabled).length, icon: 'rocket_launch' },
            ].map((stat) => (
              <div key={stat.label} className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container px-4 py-4">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[11px] uppercase tracking-[0.18em] text-outline">{stat.label}</p>
                  <span className="material-symbols-outlined text-base text-primary">{stat.icon}</span>
                </div>
                <p className="mt-2 font-headline text-2xl font-semibold text-on-surface">{stat.value}</p>
              </div>
            ))}
          </div>
        ) : null}
      </header>

      {(message || error) && (
        <div className={`rounded-2xl border px-4 py-3 text-sm ${error ? 'border-error/40 bg-error/10 text-error' : 'border-primary/30 bg-primary/10 text-primary'}`}>
          {error ?? message}
        </div>
      )}

      {showServerForm && (
        <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container-low p-6">
          <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="font-headline text-xl font-semibold text-on-surface">
                {editingServerId ? 'Modifier le serveur' : 'Nouveau serveur'}
              </h2>
              <p className="mt-1 text-sm text-on-surface-variant">
                Identité, connexion SSH, puis déploiement. Les identifiants restent chiffrés et ne sont jamais renvoyés au navigateur.
              </p>
            </div>
            <span className="rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-semibold text-primary">
              SSH chiffré · commandes figées
            </span>
          </div>

          {formErrors.length > 0 && (
            <div className="mb-5 rounded-2xl border border-error/40 bg-error/10 px-4 py-4 text-sm text-error">
              <p className="font-semibold">Le formulaire doit être corrigé avant l’enregistrement.</p>
              <ul className="mt-2 list-disc space-y-1 pl-5">
                {formErrors.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          )}

          <form onSubmit={handleSubmitServer} autoComplete="off" className="space-y-4">
            <FormSection
              step="1"
              title="Identité"
              hint={serverTemplateOptions.find((option) => option.value === (form.templateKey ?? 'CUSTOM'))?.helper}
            >
              <div className="grid gap-4 md:grid-cols-2">
                <FormField label="Nom">
                  <input value={form.name} onChange={(e) => updateForm('name', e.target.value)} placeholder="VPS client · PFE" className={fieldClass} />
                </FormField>
                <FormField label="Type">
                  <select value={form.nodeType} onChange={(e) => updateForm('nodeType', e.target.value)} className={fieldClass}>
                    {nodeTypeOptions.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </FormField>
                <FormField label="Template">
                  <select value={form.templateKey ?? 'CUSTOM'} onChange={(e) => handleTemplateChange(e.target.value)} className={fieldClass}>
                    {serverTemplateOptions.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </FormField>
                <FormField label="Environnement">
                  <select value={form.environment ?? 'LAB'} onChange={(e) => updateForm('environment', e.target.value)} className={fieldClass}>
                    {environmentOptions.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </FormField>
              </div>
            </FormSection>

            <FormSection step="2" title="Connexion SSH" hint="Mot de passe et clé privée sont chiffrés côté serveur. Laissez vide à l’édition pour conserver l’existant.">
              <div className="grid gap-4 md:grid-cols-2">
                <FormField label="Hôte">
                  <input value={form.host} onChange={(e) => updateForm('host', e.target.value)} placeholder="IP ou hostname" spellCheck={false} className={fieldClass} />
                </FormField>
                <FormField label="Port">
                  <input type="number" min={1} max={65535} value={form.port} onChange={(e) => updateForm('port', Number(e.target.value) || 22)} className={fieldClass} />
                </FormField>
                <FormField label="Utilisateur">
                  <input value={form.username} onChange={(e) => updateForm('username', e.target.value)} placeholder="root ou ubuntu" spellCheck={false} className={fieldClass} />
                </FormField>
                <FormField label="Authentification">
                  <select value={form.authMethod} onChange={(e) => updateForm('authMethod', e.target.value as ServerNodeRequest['authMethod'])} className={fieldClass}>
                    <option value="PASSWORD">Mot de passe</option>
                    <option value="PRIVATE_KEY">Clé privée</option>
                  </select>
                </FormField>
                {form.authMethod === 'PASSWORD' ? (
                  <FormField label="Mot de passe SSH" className="md:col-span-2" hint={editingServerId ? 'Laisser vide pour conserver le mot de passe actuel.' : undefined}>
                    <input
                      type="password"
                      autoComplete="new-password"
                      value={form.password ?? ''}
                      onChange={(e) => updateForm('password', e.target.value)}
                      placeholder={editingServerId ? 'Nouveau mot de passe (optionnel)' : 'Mot de passe SSH'}
                      className={fieldClass}
                    />
                  </FormField>
                ) : (
                  <>
                    <FormField label="Clé privée" className="md:col-span-2">
                      <textarea
                        value={form.privateKey ?? ''}
                        onChange={(e) => updateForm('privateKey', e.target.value)}
                        placeholder={editingServerId ? 'Nouvelle clé (laisser vide pour conserver)' : '-----BEGIN OPENSSH PRIVATE KEY-----'}
                        rows={5}
                        spellCheck={false}
                        className={`${fieldClass} font-mono text-xs`}
                      />
                    </FormField>
                    <FormField label="Passphrase" className="md:col-span-2">
                      <input
                        type="password"
                        autoComplete="new-password"
                        value={form.privateKeyPassphrase ?? ''}
                        onChange={(e) => updateForm('privateKeyPassphrase', e.target.value)}
                        placeholder="Optionnel"
                        className={fieldClass}
                      />
                    </FormField>
                  </>
                )}
              </div>
            </FormSection>

            <FormSection step="3" title="Déploiement" hint="Optionnel à la création. Requis ensuite pour Déployer / Auto-deploy. Chemin et branche sont filtrés (pas de caractères shell).">
              <div className="grid gap-4 md:grid-cols-2">
                <FormField label="Chemin app" hint="Ex. /var/www/pfe/MEDIANET_PFE-">
                  <input value={form.deployPath ?? ''} onChange={(e) => updateForm('deployPath', e.target.value)} placeholder="/var/www/app" spellCheck={false} className={`${fieldClass} font-mono`} />
                </FormField>
                <FormField label="Domaine" hint="Info + lien, pas de génération nginx.">
                  <input value={form.domain ?? ''} onChange={(e) => updateForm('domain', e.target.value)} placeholder="pfe.exemple.com" spellCheck={false} className={fieldClass} />
                </FormField>
                <FormField label="Dépôt Git lié" hint="Le verdict CRITICAL / HIGH de ce dépôt bloque le déploiement.">
                  <select
                    value={form.linkedRepositoryId ?? ''}
                    onChange={(e) => updateForm('linkedRepositoryId', e.target.value ? Number(e.target.value) : null)}
                    className={fieldClass}
                  >
                    <option value="">Aucun dépôt</option>
                    {repositories.map((repo) => (
                      <option key={repo.id} value={repo.id}>{repo.repoUrl}</option>
                    ))}
                  </select>
                </FormField>
                <FormField label="Branche">
                  <input value={form.deployBranch ?? 'main'} onChange={(e) => updateForm('deployBranch', e.target.value)} placeholder="main" spellCheck={false} className={`${fieldClass} font-mono`} />
                </FormField>
                <FormField
                  label="Stratégie"
                  className="md:col-span-2"
                  hint={deployStrategyOptions.find((option) => option.value === (form.deployStrategy ?? 'DOCKER_COMPOSE'))?.helper}
                >
                  <select
                    value={form.deployStrategy ?? 'DOCKER_COMPOSE'}
                    onChange={(e) => updateForm('deployStrategy', e.target.value)}
                    className={fieldClass}
                  >
                    {deployStrategyOptions.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </FormField>
              </div>
            </FormSection>

            <FormSection title="Contexte (optionnel)" hint="Client, projet et notes d’exploitation. Invisible pour le moteur SSH.">
              <div className="grid gap-4 md:grid-cols-2">
                <FormField label="Responsable">
                  <input value={form.owner ?? ''} onChange={(e) => updateForm('owner', e.target.value)} placeholder="Owner" className={fieldClass} />
                </FormField>
                <FormField label="Client">
                  <input value={form.clientName ?? ''} onChange={(e) => updateForm('clientName', e.target.value)} placeholder="Client / entité" className={fieldClass} />
                </FormField>
                <FormField label="Projet">
                  <input value={form.projectName ?? ''} onChange={(e) => updateForm('projectName', e.target.value)} placeholder="Application" className={fieldClass} />
                </FormField>
                <FormField label="Runbook">
                  <input value={form.runbookUrl ?? ''} onChange={(e) => updateForm('runbookUrl', e.target.value)} placeholder="https://…" className={fieldClass} />
                </FormField>
                <FormField label="Tags" className="md:col-span-2">
                  <input value={stringifyTags(form.tags)} onChange={(e) => updateForm('tags', parseTagsInput(e.target.value))} placeholder="docker, pfe, client-a" className={fieldClass} />
                </FormField>
                <FormField label="Description" className="md:col-span-2">
                  <textarea value={form.description ?? ''} onChange={(e) => updateForm('description', e.target.value)} rows={2} placeholder="Rôle du serveur" className={fieldClass} />
                </FormField>
                <FormField label="Notes" className="md:col-span-2">
                  <textarea value={form.notes ?? ''} onChange={(e) => updateForm('notes', e.target.value)} rows={3} placeholder="Consignes d’exploitation" className={fieldClass} />
                </FormField>
              </div>
            </FormSection>

            <div className="flex items-center justify-end gap-3">
              <button type="button" onClick={resetServerForm} className="rounded-2xl border border-outline-variant/[0.2] px-4 py-3 text-sm font-semibold text-on-surface">
                Annuler
              </button>
              <button type="submit" disabled={savingServer} className="rounded-2xl bg-primary px-5 py-3 text-sm font-headline font-semibold text-on-primary disabled:opacity-60">
                {savingServer
                  ? (editingServerId ? 'Mise à jour…' : 'Enregistrement…')
                  : (editingServerId ? 'Enregistrer les modifications' : 'Créer le serveur')}
              </button>
            </div>
          </form>
        </section>
      )}

      <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container-low p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.22em] text-outline">Inventaire</p>
            <h2 className="mt-2 font-headline text-2xl font-semibold text-on-surface">Tous les serveurs</h2>
          </div>
          {servers.length > 0 ? (
            <span className="w-fit rounded-full border border-outline-variant/[0.2] px-3 py-1 text-xs text-on-surface-variant">
              {filteredServers.length} / {servers.length}
            </span>
          ) : null}
        </div>

        {servers.length > 0 ? (
          <div className="mt-5 grid gap-3 lg:grid-cols-[minmax(0,1.4fr)_repeat(3,minmax(0,1fr))]">
            <div className="relative">
              <span className="material-symbols-outlined pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-base text-outline">search</span>
              <input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Nom, hôte, domaine, chemin, tags…"
                className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container py-3 pl-11 pr-4 text-sm text-on-surface outline-none focus:border-primary/40"
              />
            </div>
            <select value={environmentFilter} onChange={(e) => setEnvironmentFilter(e.target.value)} className={fieldClass}>
              <option value="ALL">Tous les environnements</option>
              {environmentOptions.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            <select value={liveFilter} onChange={(e) => setLiveFilter(e.target.value)} className={fieldClass}>
              <option value="ALL">Tous les états</option>
              <option value="ONLINE">En ligne</option>
              <option value="OFFLINE">Hors ligne</option>
              <option value="CHECKING">Vérification</option>
              <option value="UNKNOWN">Inconnu</option>
            </select>
            <select value={nodeTypeFilter} onChange={(e) => setNodeTypeFilter(e.target.value)} className={fieldClass}>
              <option value="ALL">Tous les types</option>
              {nodeTypeOptions.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </div>
        ) : null}

        {osOptions.length > 0 ? (
          <div className="mt-3">
            <select value={osFilter} onChange={(e) => setOsFilter(e.target.value)} className={`${fieldClass} max-w-xs`}>
              <option value="ALL">Tous les OS</option>
              {osOptions.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
          </div>
        ) : null}

        <div className="mt-6">
          {loadingList ? (
            <div className="rounded-3xl border border-outline-variant/[0.14] bg-surface-container p-10 text-center text-sm text-outline">
              Chargement des serveurs…
            </div>
          ) : servers.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-outline-variant/[0.2] bg-surface-container px-6 py-12 text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10">
                <span className="material-symbols-outlined text-3xl text-primary">dns</span>
              </div>
              <h3 className="mt-5 font-headline text-xl font-semibold text-on-surface">Aucun serveur pour l’instant</h3>
              <p className="mx-auto mt-2 max-w-md text-sm text-on-surface-variant">
                Ajoutez le VPS une fois. Ensuite : lier le dépôt, activer l’auto-deploy, et Vulnix fera le pull + docker compose après un scan PASS.
              </p>
              <ol className="mx-auto mt-6 grid max-w-2xl gap-3 text-left sm:grid-cols-3">
                {[
                  { n: '1', t: 'Ajouter le serveur', d: 'Hôte, SSH, chemin app' },
                  { n: '2', t: 'Lier le dépôt', d: 'Le scan CRITICAL / HIGH bloque' },
                  { n: '3', t: 'Déployer', d: 'Manuel ou auto après push' },
                ].map((step) => (
                  <li key={step.n} className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-3">
                    <p className="text-xs font-bold text-primary">{step.n}</p>
                    <p className="mt-1 text-sm font-semibold text-on-surface">{step.t}</p>
                    <p className="mt-1 text-xs text-on-surface-variant">{step.d}</p>
                  </li>
                ))}
              </ol>
              <button
                onClick={handleOpenCreateForm}
                className="mt-7 inline-flex items-center gap-2 rounded-2xl bg-primary px-5 py-3 text-sm font-headline font-semibold text-on-primary"
              >
                <span className="material-symbols-outlined text-base">add</span>
                Ajouter le premier serveur
              </button>
            </div>
          ) : filteredServers.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-outline-variant/[0.18] bg-surface-container p-10 text-center text-sm text-on-surface-variant">
              Aucun serveur ne correspond aux filtres.
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
              {filteredServers.map((server) => {
                const isDeleting = deletingServerId === server.id;
                const isLoadingEditor = loadingEditorId === server.id;
                const liveMeta = liveStatusPresentation[server.liveState];
                const environmentLabel = environmentOptions.find((option) => option.value === server.environment)?.label
                  ?? server.environment
                  ?? 'Non classé';
                const linkedRepo = repositories.find((repo) => repo.id === server.linkedRepositoryId);

                return (
                  <article
                    key={server.id}
                    className="flex flex-col rounded-3xl border border-outline-variant/[0.16] bg-surface-container p-5 transition hover:border-primary/30"
                  >
                    <button onClick={() => navigate(`/server-config/${server.id}`)} className="w-full flex-1 text-left">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase ${liveMeta.className}`}>
                          <span className={`h-2 w-2 rounded-full ${liveMeta.dotClass}`} />
                          {liveMeta.label}
                        </span>
                        <span className="rounded-full border border-outline-variant/[0.2] px-2.5 py-1 text-[10px] font-semibold uppercase text-on-surface-variant">
                          {environmentLabel}
                        </span>
                        {server.autoDeployEnabled ? (
                          <span className="rounded-full border border-tertiary/30 bg-tertiary/10 px-2.5 py-1 text-[10px] font-semibold uppercase text-tertiary">
                            Auto-deploy
                          </span>
                        ) : null}
                      </div>
                      <h3 className="mt-3 font-headline text-xl font-semibold text-on-surface">{server.name}</h3>
                      <p className="mt-1 font-mono text-sm text-on-surface-variant">{server.host}:{server.port}</p>
                      <p className="mt-1 text-xs text-outline">{server.username} · {formatNodeType(server.nodeType)}</p>

                      <div className="mt-4 rounded-2xl border border-outline-variant/[0.12] bg-surface-container-low px-4 py-3">
                        {server.domain ? (
                          <p className="truncate text-sm text-primary">{server.domain}</p>
                        ) : (
                          <p className="text-sm text-outline">Aucun domaine</p>
                        )}
                        <p className="mt-1 truncate font-mono text-xs text-on-surface-variant">
                          {server.deployPath || 'Chemin de déploiement non défini'}
                        </p>
                        <p className="mt-1 truncate text-xs text-outline">
                          {linkedRepo ? linkedRepo.repoUrl : 'Aucun dépôt lié'}
                          {server.deployBranch ? ` · ${server.deployBranch}` : ''}
                          {' · '}
                          {server.deployStrategy === 'STATIC_NGINX' ? 'Site nginx' : 'Docker Compose'}
                        </p>
                      </div>

                      {(server.criticalCount > 0 || server.warningCount > 0) ? (
                        <p className="mt-3 text-xs text-on-surface-variant">
                          <span className="text-error">{server.criticalCount} critique</span>
                          {' · '}
                          <span className="text-secondary">{server.warningCount} warning</span>
                          {server.osName ? ` · ${server.osName}` : ''}
                        </p>
                      ) : (
                        <p className="mt-3 text-xs text-outline">
                          {server.osName || 'OS non détecté'}
                          {server.lastScannedAt ? ` · ${formatDateTime(server.lastScannedAt)}` : ''}
                        </p>
                      )}
                    </button>

                    <div className="mt-4 grid grid-cols-2 gap-2">
                      <button
                        onClick={() => navigate(`/server-config/${server.id}`)}
                        className="inline-flex items-center justify-center gap-1.5 rounded-2xl bg-primary px-3 py-2.5 text-sm font-semibold text-on-primary"
                      >
                        <span className="material-symbols-outlined text-base">deployed_code</span>
                        Ouvrir
                      </button>
                      <button
                        onClick={() => void handleOpenScanModal(server)}
                        disabled={isDeleting || isLoadingEditor}
                        className="inline-flex items-center justify-center gap-1.5 rounded-2xl border border-outline-variant/[0.2] px-3 py-2.5 text-sm font-semibold text-on-surface disabled:opacity-60"
                      >
                        <span className="material-symbols-outlined text-base">radar</span>
                        Scanner
                      </button>
                      <button
                        onClick={() => void handleEditServer(server.id)}
                        disabled={isLoadingEditor || isDeleting}
                        className="inline-flex items-center justify-center gap-1.5 rounded-2xl border border-outline-variant/[0.2] px-3 py-2.5 text-sm font-semibold text-on-surface disabled:opacity-60"
                      >
                        <span className="material-symbols-outlined text-base">edit</span>
                        {isLoadingEditor ? '…' : 'Éditer'}
                      </button>
                      <button
                        onClick={() => void handleDeleteServer(server)}
                        disabled={isDeleting || isLoadingEditor}
                        className="inline-flex items-center justify-center gap-1.5 rounded-2xl border border-error/25 bg-error/10 px-3 py-2.5 text-sm font-semibold text-error disabled:opacity-60"
                      >
                        <span className="material-symbols-outlined text-base">delete</span>
                        {isDeleting ? '…' : 'Supprimer'}
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </div>
      </section>
    </div>
  );
};

export default ServerConfig;
