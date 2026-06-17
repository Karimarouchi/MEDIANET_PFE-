import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { hasAnyPermission } from '../constants/access';
import {
  assignEmployeeToClient,
  assignRepositoryToClient,
  getAllScans,
  getClient,
  getRepositories,
  getUsers,
  removeRepositoryFromClient,
  updateClient,
  type ClientDto,
  type RepositoryDto,
  type ScanResultDto,
  type UserDto,
} from '../services/api';

const ClientDetail: React.FC = () => {
  const { id } = useParams();
  const { user } = useAuth();
  const [client, setClient] = useState<ClientDto | null>(null);
  const [users, setUsers] = useState<UserDto[]>([]);
  const [repositories, setRepositories] = useState<RepositoryDto[]>([]);
  const [scans, setScans] = useState<ScanResultDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [employeeId, setEmployeeId] = useState('');
  const [repositoryId, setRepositoryId] = useState('');
  const [form, setForm] = useState({ name: '', company: '', email: '' });

  const employees = useMemo(() => users.filter((entry) => entry.systemRole === 'EMPLOYEE' && !entry.suspended), [users]);
  const canManageProject = user?.systemRole === 'ADMIN' && hasAnyPermission(user.permissions, ['ADMIN_PROJECTS']);
  const canViewProject = hasAnyPermission(user?.permissions, ['REPOSITORIES', 'ADMIN_PROJECTS']);
  const projectScans = useMemo(() => {
    if (!client) return [];
    return scans
      .filter((entry) => (entry.clientIds ?? []).includes(client.id))
      .sort((a, b) => new Date(b.startedAt ?? '').getTime() - new Date(a.startedAt ?? '').getTime());
  }, [client, scans]);
  const latestScan = projectScans[0];

  const loadData = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const requests = [getClient(Number(id)), getRepositories(), getAllScans()] as const;
      const [clientRes, repositoriesRes, scansRes] = await Promise.all(requests);
      const usersRes = canManageProject ? await getUsers() : null;
      setClient(clientRes.data);
      setUsers(usersRes?.data ?? []);
      setRepositories(repositoriesRes.data);
      setScans(scansRes.data);
      setForm({
        name: clientRes.data.name ?? '',
        company: clientRes.data.company ?? '',
        email: clientRes.data.email ?? '',
      });
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Impossible de charger la fiche client.');
    } finally {
      setLoading(false);
    }
  }, [canManageProject, id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (!canViewProject) {
    return (
      <div className="max-w-3xl mx-auto rounded-3xl border border-error/30 bg-error/10 p-8 text-error">
        <h1 className="font-headline text-2xl font-bold">Accès refusé</h1>
        <p className="mt-3 text-sm">Ce dossier projet n’est pas accessible avec votre rôle.</p>
      </div>
    );
  }

  const handleUpdate = async () => {
    if (!client) return;
    setMessage(null);
    setError(null);
    try {
      const res = await updateClient(client.id, form);
      setClient(res.data);
      setMessage('Informations client mises à jour.');
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Mise à jour impossible.');
    }
  };

  const handleAssignEmployee = async () => {
    if (!client || !employeeId) return;
    setMessage(null);
    setError(null);
    try {
      const res = await assignEmployeeToClient(client.id, Number(employeeId));
      setClient(res.data);
      setEmployeeId('');
      setMessage('Employé assigné.');
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Affectation employé impossible.');
    }
  };

  const handleAssignRepository = async () => {
    if (!client || !repositoryId) return;
    setMessage(null);
    setError(null);
    try {
      const res = await assignRepositoryToClient(client.id, Number(repositoryId));
      setClient(res.data);
      setRepositoryId('');
      setMessage('Dépôt assigné.');
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Affectation dépôt impossible.');
    }
  };

  const handleRemoveRepository = async (repoId: number) => {
    if (!client) return;
    setMessage(null);
    setError(null);
    try {
      await removeRepositoryFromClient(client.id, repoId);
      await loadData();
      setMessage('Dépôt retiré du client.');
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Suppression du dépôt impossible.');
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <header className="space-y-3">
        <Link to={canManageProject ? '/admin/projects' : '/repositories'} className="inline-flex items-center gap-2 text-sm text-outline hover:text-primary transition-colors">
          <span className="material-symbols-outlined text-base">arrow_back</span>
          {canManageProject ? 'Retour aux projets' : 'Retour aux dépôts'}
        </Link>
        <p className="text-xs uppercase tracking-[0.35em] text-outline">Project Workspace</p>
        <h1 className="font-headline text-3xl font-bold text-on-surface">{client?.name || 'Projet client'}</h1>
        <p className="text-sm text-on-surface-variant max-w-3xl">
          Ce dossier regroupe un projet client, ses repos liés et les rapports qui doivent remonter ensemble dans Repositories, Scans et Vulnerabilities.
        </p>
      </header>

      {(message || error) && (
        <div className={`rounded-2xl border px-4 py-3 text-sm ${error ? 'border-error/40 bg-error/10 text-error' : 'border-primary/30 bg-primary/10 text-primary'}`}>
          {error || message}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-24">
          <span className="material-symbols-outlined text-primary text-5xl animate-spin">progress_activity</span>
        </div>
      ) : client ? (
        <>
          <section className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
            <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
              <h2 className="font-headline text-xl font-semibold text-on-surface">Informations du dossier projet</h2>
              <div className="grid gap-3 sm:grid-cols-2">
                <input value={form.name} onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))} placeholder="Nom du projet ou du client" className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm" />
                <input value={form.company} onChange={(e) => setForm((prev) => ({ ...prev, company: e.target.value }))} placeholder="Société ou programme" className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm" />
                <input value={form.email} onChange={(e) => setForm((prev) => ({ ...prev, email: e.target.value }))} placeholder="Contact projet (optionnel)" className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm sm:col-span-2" />
              </div>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-sm">
                <div className="rounded-2xl bg-surface-container-high px-4 py-3">
                  <p className="text-[11px] uppercase tracking-[0.2em] text-outline">Contact</p>
                  <p className="mt-2 text-on-surface">{client.email || 'Non renseigné'}</p>
                </div>
                <div className="rounded-2xl bg-surface-container-high px-4 py-3">
                  <p className="text-[11px] uppercase tracking-[0.2em] text-outline">Créé par</p>
                  <p className="mt-2 text-on-surface">{client.createdByLogin || 'N/A'}</p>
                </div>
                <div className="rounded-2xl bg-surface-container-high px-4 py-3">
                  <p className="text-[11px] uppercase tracking-[0.2em] text-outline">Repos liés</p>
                  <p className="mt-2 text-on-surface">{client.repositoryIds.length}</p>
                </div>
                <div className="rounded-2xl bg-surface-container-high px-4 py-3">
                  <p className="text-[11px] uppercase tracking-[0.2em] text-outline">Rapports liés</p>
                  <p className="mt-2 text-on-surface">{projectScans.length}</p>
                </div>
              </div>
              <button onClick={handleUpdate} className="rounded-2xl bg-primary px-4 py-3 text-sm font-headline font-semibold text-on-primary">Enregistrer</button>
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
                <h2 className="font-headline text-xl font-semibold text-on-surface">Collaborateurs affectés</h2>
                <p className="text-sm text-on-surface-variant">Les collaborateurs liés voient ce dossier projet et les repos rattachés dans l’application.</p>
                {canManageProject ? (
                  <>
                    <select value={employeeId} onChange={(e) => setEmployeeId(e.target.value)} className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm">
                      <option value="">Choisir un collaborateur</option>
                      {employees.map((entry) => (
                        <option key={entry.id} value={entry.id}>{entry.login}</option>
                      ))}
                    </select>
                    <button onClick={handleAssignEmployee} className="rounded-2xl border border-outline-variant/[0.2] px-4 py-3 text-sm font-headline font-semibold text-on-surface">Affecter le collaborateur</button>
                  </>
                ) : (
                  <div className="rounded-2xl bg-surface-container-high px-4 py-3 text-sm text-on-surface-variant">
                    Consultation seule sur les affectations de collaborateurs.
                  </div>
                )}
                <div className="space-y-2">
                  {client.employeeLogins.length ? client.employeeLogins.map((entry) => (
                    <div key={entry} className="rounded-xl bg-surface-container-high px-3 py-2 text-sm text-on-surface">{entry}</div>
                  )) : <p className="text-sm text-outline">Aucun collaborateur affecté.</p>}
                </div>
              </div>

              <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
                <h2 className="font-headline text-xl font-semibold text-on-surface">Repos liés au projet</h2>
                <p className="text-sm text-on-surface-variant">Ces repos remontent ensuite dans Repositories, Scans et Vulnerabilities avec le badge du dossier projet.</p>
                <select value={repositoryId} onChange={(e) => setRepositoryId(e.target.value)} className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm">
                  <option value="">Choisir un repo</option>
                  {repositories.map((entry) => (
                    <option key={entry.id} value={entry.id}>{entry.repoUrl}</option>
                  ))}
                </select>
                <button onClick={handleAssignRepository} className="rounded-2xl border border-outline-variant/[0.2] px-4 py-3 text-sm font-headline font-semibold text-on-surface">Lier le repo</button>
                <div className="space-y-2">
                  {client.repositoryUrls.length ? client.repositoryUrls.map((entry, index) => (
                    <div key={`${entry}-${index}`} className="flex items-center justify-between gap-3 rounded-xl bg-surface-container-high px-3 py-2 text-sm text-on-surface">
                      <span className="truncate">{entry}</span>
                      <button onClick={() => handleRemoveRepository(client.repositoryIds[index])} className="text-xs text-error">Retirer</button>
                    </div>
                  )) : <p className="text-sm text-outline">Aucun repo lié.</p>}
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h2 className="font-headline text-xl font-semibold text-on-surface">Rapports liés au projet</h2>
                <p className="mt-2 text-sm text-on-surface-variant">Tous les scans des repos liés à ce dossier projet sont visibles ici.</p>
              </div>
              <span className="rounded-full bg-surface-container-high px-3 py-1 text-[11px] font-headline text-on-surface">{projectScans.length} rapport(s)</span>
            </div>

            {projectScans.length ? (
              <div className="space-y-3">
                {projectScans.map((scan) => {
                  const reportHref = scan.scanMode === 'ssl-only'
                    ? `/ssl-analysis?scanId=${scan.id}`
                    : `/vulnerabilities?scanId=${scan.id}&repoId=${scan.repoId}`;
                  return (
                    <div key={scan.id} className="rounded-2xl bg-surface-container-high p-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                      <div>
                        <p className="font-headline text-sm font-semibold text-on-surface">{scan.repoUrl}</p>
                        <p className="text-xs text-outline mt-1">Scan #{scan.id} · {scan.status} · {scan.startedAt ? new Date(scan.startedAt).toLocaleString() : '—'}</p>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="rounded-full bg-surface-container px-3 py-1 text-[11px] text-on-surface">{scan.cveCount} CVE</span>
                        <Link to={reportHref} className="inline-flex items-center gap-2 rounded-xl border border-outline-variant/[0.2] px-3 py-2 text-xs font-headline font-semibold text-on-surface hover:border-primary/40 hover:text-primary transition-colors">
                          <span className="material-symbols-outlined text-sm">open_in_new</span>
                          Ouvrir le rapport
                        </Link>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="rounded-2xl bg-surface-container-high px-4 py-5 text-sm text-on-surface-variant">
                Aucun rapport n’est encore lié à ce dossier projet. Les scans apparaîtront ici dès qu’un repo lié sera scanné.
              </div>
            )}

            {latestScan ? (
              <div className="rounded-2xl border border-primary/20 bg-primary/5 px-4 py-4 text-sm text-on-surface-variant">
                Dernier rapport: <span className="font-semibold text-on-surface">Scan #{latestScan.id}</span> sur <span className="font-semibold text-on-surface">{latestScan.repoUrl}</span>.
              </div>
            ) : null}
          </section>
        </>
      ) : null}
    </div>
  );
};

export default ClientDetail;