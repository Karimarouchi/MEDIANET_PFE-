import React, { useCallback, useEffect, useState } from 'react';
import ConfirmModal from '../components/ConfirmModal';
import { useNavigate } from 'react-router-dom';
import {
  createServerNode,
  deleteServerNode,
  getLiveServerNode,
  getServerNode,
  getServerNodes,
  scanServerNode,
  updateServerNode,
  type PortExposureDto,
  type ServerNodeDetailDto,
  type ServerNodeDto,
  type ServerNodeRequest,
  type ServiceStatusDto,
} from '../services/api';
import {
  applyServerTemplate,
  emptyServerForm,
  environmentOptions,
  extractApiError,
  formatDateTime,
  formatNodeType,
  nodeTypeOptions,
  parseTagsInput,
  serverTemplateOptions,
  stringifyTags,
  typeBadgeClass,
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

  type ScanModalState = {
    open: boolean;
    serverId: number | null;
    serverName: string;
    loading: boolean;
    result: ServerNodeDetailDto | null;
    error: string | null;
  };
  const [scanModal, setScanModal] = useState<ScanModalState>({
    open: false,
    serverId: null,
    serverName: '',
    loading: false,
    result: null,
    error: null,
  });

  const handleOpenScanModal = async (server: InventoryServerCard) => {
    setScanModal({ open: true, serverId: server.id, serverName: server.name, loading: true, result: null, error: null });
    try {
      const { data } = await scanServerNode(server.id);
      setScanModal((prev) => ({ ...prev, loading: false, result: data }));
    } catch (err: any) {
      setScanModal((prev) => ({ ...prev, loading: false, error: extractApiError(err, 'Le scan du serveur a échoué.') }));
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
                      <span className="rounded-full border border-outline-variant/[0.2] px-3 py-1 text-xs text-on-surface-variant">
                        {(scanModal.result.ports ?? []).length} port(s)
                      </span>
                    </div>
                    {(scanModal.result.ports ?? []).length === 0 ? (
                      <div className="rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-5 text-sm text-on-surface-variant">
                        Aucun port remonté. Le scan SSH n'a pas pu lister les ports de ce nœud.
                      </div>
                    ) : (
                      <div className="space-y-2">
                        {(scanModal.result.ports ?? []).map((port: PortExposureDto) => (
                          <div
                            key={`${port.portNumber}-${port.protocol}-${port.bindAddress}`}
                            className="flex items-center justify-between gap-4 rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-3"
                          >
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
                              <span className="text-xs text-outline">{port.bindAddress}</span>
                              <span className="text-xs uppercase tracking-[0.18em] text-outline">{port.state}</span>
                            </div>
                          </div>
                        ))}
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
      <header className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
        <div className="space-y-2">
          <p className="text-xs uppercase tracking-[0.35em] text-outline">Server Config</p>
          <h1 className="font-headline text-4xl font-bold tracking-tight text-on-surface">Serveurs</h1>
          <p className="max-w-3xl text-sm text-on-surface-variant">
            Console d’inventaire des serveurs avec recherche, filtres, templates de création, validation forte et enrichissement live des cartes.
          </p>
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => void refreshLiveCards(servers)}
            disabled={refreshingInventory || loadingList || servers.length === 0}
            className="inline-flex items-center gap-2 rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-5 py-3 text-sm font-headline font-semibold text-on-surface transition-colors hover:border-primary/40 hover:text-primary disabled:opacity-60"
          >
            <span className="material-symbols-outlined text-base">sync</span>
            {refreshingInventory ? 'Actualisation...' : 'Actualiser les cartes'}
          </button>
          <button
            onClick={handleOpenCreateForm}
            className="inline-flex items-center gap-2 rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-5 py-3 text-sm font-headline font-semibold text-on-surface transition-colors hover:border-primary/40 hover:text-primary"
          >
            <span className="material-symbols-outlined text-base">add_circle</span>
            {showServerForm && editingServerId === null ? 'Fermer' : 'Ajouter un serveur'}
          </button>
        </div>
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
                {editingServerId ? 'Modifier le serveur Linux' : 'Ajouter un serveur Linux'}
              </h2>
              <p className="mt-1 text-sm text-on-surface-variant">
                Templates de déploiement, métadonnées d’exploitation et validation forte avant sauvegarde.
              </p>
            </div>
            <span className="rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-semibold text-primary">
              SSH agentless + validation métier
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

          <form onSubmit={handleSubmitServer} className="grid gap-4 lg:grid-cols-2">
            <div className="lg:col-span-2 grid gap-4 xl:grid-cols-[1fr_1fr_auto]">
              <div>
                <label className="mb-2 block text-xs uppercase tracking-[0.2em] text-outline">Template</label>
                <select
                  value={form.templateKey ?? 'CUSTOM'}
                  onChange={(e) => handleTemplateChange(e.target.value)}
                  className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
                >
                  {serverTemplateOptions.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-2 block text-xs uppercase tracking-[0.2em] text-outline">Environnement</label>
                <select
                  value={form.environment ?? 'LAB'}
                  onChange={(e) => updateForm('environment', e.target.value)}
                  className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
                >
                  {environmentOptions.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </div>
              <div className="rounded-2xl border border-outline-variant/[0.18] bg-surface-container px-4 py-3 text-sm text-on-surface-variant">
                {serverTemplateOptions.find((option) => option.value === (form.templateKey ?? 'CUSTOM'))?.helper}
              </div>
            </div>

            <input
              value={form.name}
              onChange={(e) => updateForm('name', e.target.value)}
              placeholder="Nom du serveur"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
            />
            <input
              value={form.host}
              onChange={(e) => updateForm('host', e.target.value)}
              placeholder="IP ou hostname"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
            />
            <input
              type="number"
              min={1}
              max={65535}
              value={form.port}
              onChange={(e) => updateForm('port', Number(e.target.value) || 22)}
              placeholder="Port SSH"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
            />
            <input
              value={form.username}
              onChange={(e) => updateForm('username', e.target.value)}
              placeholder="Utilisateur SSH"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
            />
            <select
              value={form.nodeType}
              onChange={(e) => updateForm('nodeType', e.target.value)}
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
            >
              {nodeTypeOptions.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            <select
              value={form.authMethod}
              onChange={(e) => updateForm('authMethod', e.target.value as ServerNodeRequest['authMethod'])}
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
            >
              <option value="PASSWORD">Mot de passe</option>
              <option value="PRIVATE_KEY">Clé privée</option>
            </select>

            <input
              value={form.owner ?? ''}
              onChange={(e) => updateForm('owner', e.target.value)}
              placeholder="Owner / responsable"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
            />
            <input
              value={form.clientName ?? ''}
              onChange={(e) => updateForm('clientName', e.target.value)}
              placeholder="Client / entité"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
            />
            <input
              value={form.projectName ?? ''}
              onChange={(e) => updateForm('projectName', e.target.value)}
              placeholder="Projet / application"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
            />
            <input
              value={form.runbookUrl ?? ''}
              onChange={(e) => updateForm('runbookUrl', e.target.value)}
              placeholder="URL du runbook"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
            />

            {form.authMethod === 'PASSWORD' ? (
              <input
                type="password"
                value={form.password ?? ''}
                onChange={(e) => updateForm('password', e.target.value)}
                placeholder={editingServerId ? 'Nouveau mot de passe SSH (laisser vide pour conserver)' : 'Mot de passe SSH'}
                className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none lg:col-span-2"
              />
            ) : (
              <>
                <textarea
                  value={form.privateKey ?? ''}
                  onChange={(e) => updateForm('privateKey', e.target.value)}
                  placeholder={editingServerId ? 'Nouvelle clé privée (laisser vide pour conserver)' : '-----BEGIN OPENSSH PRIVATE KEY-----'}
                  rows={6}
                  className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none lg:col-span-2"
                />
                <input
                  type="password"
                  value={form.privateKeyPassphrase ?? ''}
                  onChange={(e) => updateForm('privateKeyPassphrase', e.target.value)}
                  placeholder="Passphrase de la clé (optionnel)"
                  className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none lg:col-span-2"
                />
              </>
            )}

            <input
              value={stringifyTags(form.tags)}
              onChange={(e) => updateForm('tags', parseTagsInput(e.target.value))}
              placeholder="Tags (séparés par des virgules)"
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none lg:col-span-2"
            />

            <textarea
              value={form.description ?? ''}
              onChange={(e) => updateForm('description', e.target.value)}
              placeholder="Description opérationnelle"
              rows={3}
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none lg:col-span-2"
            />

            <textarea
              value={form.notes ?? ''}
              onChange={(e) => updateForm('notes', e.target.value)}
              placeholder="Notes d’exploitation / consignes"
              rows={4}
              className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none lg:col-span-2"
            />

            <div className="flex items-center justify-end gap-3 lg:col-span-2">
              <button
                type="button"
                onClick={resetServerForm}
                className="rounded-2xl border border-outline-variant/[0.2] px-4 py-3 text-sm font-semibold text-on-surface"
              >
                Annuler
              </button>
              <button
                type="submit"
                disabled={savingServer}
                className="rounded-2xl bg-primary px-5 py-3 text-sm font-headline font-semibold text-on-primary disabled:opacity-60"
              >
                {savingServer
                  ? (editingServerId ? 'Mise à jour...' : 'Enregistrement...')
                  : (editingServerId ? 'Mettre à jour le serveur' : 'Enregistrer le serveur')}
              </button>
            </div>
          </form>
        </section>
      )}

      <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container-low p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.22em] text-outline">Inventory</p>
            <h2 className="mt-2 font-headline text-2xl font-semibold text-on-surface">Tous les serveurs</h2>
            <p className="mt-2 text-sm text-on-surface-variant">
              Recherche, filtres opérationnels et cartes enrichies avec statut live, criticité et OS détecté.
            </p>
          </div>
          <span className="w-fit rounded-full border border-outline-variant/[0.2] px-3 py-1 text-xs text-on-surface-variant">
            {filteredServers.length} / {servers.length} serveur(s)
          </span>
        </div>

        <div className="mt-6 grid gap-3 xl:grid-cols-[1.3fr_repeat(4,minmax(0,1fr))]">
          <input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Rechercher par nom, host, user, tags, client, projet..."
            className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
          />
          <select
            value={environmentFilter}
            onChange={(e) => setEnvironmentFilter(e.target.value)}
            className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
          >
            <option value="ALL">Tous les environnements</option>
            {environmentOptions.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
          <select
            value={nodeTypeFilter}
            onChange={(e) => setNodeTypeFilter(e.target.value)}
            className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
          >
            <option value="ALL">Tous les types</option>
            {nodeTypeOptions.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
          <select
            value={liveFilter}
            onChange={(e) => setLiveFilter(e.target.value)}
            className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
          >
            <option value="ALL">Tous les états live</option>
            <option value="ONLINE">Live OK</option>
            <option value="OFFLINE">Live KO</option>
            <option value="CHECKING">Vérification</option>
            <option value="UNKNOWN">Inconnu</option>
          </select>
          <select
            value={osFilter}
            onChange={(e) => setOsFilter(e.target.value)}
            className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none"
          >
            <option value="ALL">Tous les OS</option>
            {osOptions.map((option) => (
              <option key={option} value={option}>{option}</option>
            ))}
          </select>
        </div>

        <div className="mt-6">
          {loadingList ? (
            <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-10 text-center text-sm text-outline">
              Chargement des serveurs...
            </div>
          ) : servers.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-outline-variant/[0.18] bg-surface-container p-10 text-center text-sm text-on-surface-variant">
              Aucun serveur enregistré. Ajoute le premier serveur pour constituer l’inventaire.
            </div>
          ) : filteredServers.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-outline-variant/[0.18] bg-surface-container p-10 text-center text-sm text-on-surface-variant">
              Aucun serveur ne correspond aux filtres actifs.
            </div>
          ) : (
            <div className="grid gap-5 md:grid-cols-2 2xl:grid-cols-3">
              {filteredServers.map((server) => {
                const isDeleting = deletingServerId === server.id;
                const isLoadingEditor = loadingEditorId === server.id;
                const liveMeta = liveStatusPresentation[server.liveState];
                const environmentLabel = environmentOptions.find((option) => option.value === server.environment)?.label
                  ?? server.environment
                  ?? 'Non classé';

                return (
                  <article
                    key={server.id}
                    className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-5 transition-colors hover:border-primary/30 hover:bg-surface-container-high"
                  >
                    <button
                      onClick={() => navigate(`/server-config/${server.id}`)}
                      className="w-full text-left"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase ${typeBadgeClass[server.nodeType] || typeBadgeClass.CUSTOM}`}>
                              {formatNodeType(server.nodeType)}
                            </span>
                            <span className="rounded-full border border-outline-variant/[0.2] bg-surface-container-low px-2.5 py-1 text-[10px] font-semibold uppercase text-on-surface-variant">
                              {environmentLabel}
                            </span>
                            <span className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase ${liveMeta.className}`}>
                              <span className={`h-2.5 w-2.5 rounded-full ${liveMeta.dotClass}`} />
                              {liveMeta.label}
                            </span>
                          </div>
                          <h3 className="mt-4 font-headline text-xl font-semibold text-on-surface">{server.name}</h3>
                          <p className="mt-2 text-sm text-on-surface-variant">{server.host}:{server.port} · {server.username}</p>
                          {(server.clientName || server.projectName || server.owner) ? (
                            <p className="mt-2 text-xs text-outline">
                              {[server.clientName, server.projectName, server.owner].filter(Boolean).join(' · ')}
                            </p>
                          ) : null}
                        </div>
                      </div>

                      {server.tags.length > 0 ? (
                        <div className="mt-4 flex flex-wrap gap-2">
                          {server.tags.map((tag) => (
                            <span key={tag} className="rounded-full border border-primary/20 bg-primary/10 px-2.5 py-1 text-[11px] font-medium text-primary">
                              {tag}
                            </span>
                          ))}
                        </div>
                      ) : null}

                      {server.description ? (
                        <p className="mt-4 line-clamp-2 text-sm text-on-surface-variant">{server.description}</p>
                      ) : server.notes ? (
                        <p className="mt-4 line-clamp-2 text-sm text-on-surface-variant">{server.notes}</p>
                      ) : (
                        <p className="mt-4 text-sm text-outline">Aucune description opérationnelle.</p>
                      )}

                      <div className="mt-5 grid grid-cols-3 gap-2 text-center">
                        <div className="rounded-2xl bg-surface-container-low px-2 py-3">
                          <p className="text-[10px] uppercase tracking-[0.18em] text-outline">Critical</p>
                          <p className="mt-1 font-headline text-base text-error">{server.criticalCount}</p>
                        </div>
                        <div className="rounded-2xl bg-surface-container-low px-2 py-3">
                          <p className="text-[10px] uppercase tracking-[0.18em] text-outline">Warning</p>
                          <p className="mt-1 font-headline text-base text-secondary">{server.warningCount}</p>
                        </div>
                        <div className="rounded-2xl bg-surface-container-low px-2 py-3">
                          <p className="text-[10px] uppercase tracking-[0.18em] text-outline">Info</p>
                          <p className="mt-1 font-headline text-base text-primary">{server.infoCount}</p>
                        </div>
                      </div>

                      <div className="mt-5 rounded-2xl border border-outline-variant/[0.14] bg-surface-container-low px-4 py-4">
                        <p className="text-[10px] uppercase tracking-[0.18em] text-outline">OS</p>
                        <p className="mt-2 font-headline text-lg font-semibold text-on-surface">{server.osName || 'OS non détecté'}</p>
                        <p className="mt-2 text-xs text-on-surface-variant">
                          {server.liveError
                            ? server.liveError
                            : server.checkedAt
                              ? `Vérifié ${formatDateTime(server.checkedAt)}`
                              : `Dernière synchro ${formatDateTime(server.lastScannedAt)}`}
                        </p>
                      </div>

                      <div className="mt-5 flex items-center justify-between gap-3 text-xs text-outline">
                        <span>{server.latestStatus ?? 'Not scanned'}</span>
                        <span>{formatDateTime(server.lastScannedAt)}</span>
                      </div>
                    </button>

                    <div className="mt-5 flex flex-wrap gap-2">
                      <button
                        onClick={() => navigate(`/server-config/${server.id}`)}
                        className="inline-flex items-center gap-2 rounded-2xl bg-primary px-4 py-2.5 text-sm font-semibold text-on-primary"
                      >
                        <span className="material-symbols-outlined text-base">open_in_new</span>
                        Ouvrir
                      </button>
                      <button
                        onClick={(e) => { e.stopPropagation(); void handleOpenScanModal(server); }}
                        disabled={isDeleting || isLoadingEditor}
                        className="inline-flex items-center gap-2 rounded-2xl border border-tertiary/30 bg-tertiary/10 px-4 py-2.5 text-sm font-semibold text-tertiary disabled:opacity-60"
                      >
                        <span className="material-symbols-outlined text-base">radar</span>
                        Scanner
                      </button>
                      <button
                        onClick={() => void handleEditServer(server.id)}
                        disabled={isLoadingEditor || isDeleting}
                        className="inline-flex items-center gap-2 rounded-2xl border border-outline-variant/[0.2] px-4 py-2.5 text-sm font-semibold text-on-surface disabled:opacity-60"
                      >
                        <span className="material-symbols-outlined text-base">edit</span>
                        {isLoadingEditor ? 'Chargement...' : 'Éditer'}
                      </button>
                      <button
                        onClick={() => void handleDeleteServer(server)}
                        disabled={isDeleting || isLoadingEditor}
                        className="inline-flex items-center gap-2 rounded-2xl border border-error/25 bg-error/10 px-4 py-2.5 text-sm font-semibold text-error disabled:opacity-60"
                      >
                        <span className="material-symbols-outlined text-base">delete</span>
                        {isDeleting ? 'Suppression...' : 'Supprimer'}
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
