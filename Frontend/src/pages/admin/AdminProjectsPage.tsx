import React from 'react';
import { Link, useOutletContext } from 'react-router-dom';
import { type AdminPanelContextValue } from '../AdminPanel';

const AdminProjectsPage: React.FC = () => {
  const {
    clients,
    repositories,
    loading,
    clientForm,
    setClientForm,
    employees,
    employeeSelections,
    repoSelections,
    setEmployeeSelections,
    setRepoSelections,
    handleCreateClient,
    handleAssignEmployee,
    handleAssignRepository,
    handleRemoveRepository,
  } = useOutletContext<AdminPanelContextValue>();

  return (
    <div className="grid gap-6 xl:grid-cols-[0.92fr_1.08fr]">
      <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
        <div>
          <h2 className="font-headline text-xl font-semibold text-on-surface">Créer un projet client</h2>
          <p className="mt-2 text-sm text-on-surface-variant">Un projet client regroupe les repos GitHub ou GitLab qui doivent remonter sous le même dossier.</p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <input value={clientForm.name} onChange={(e) => setClientForm((prev) => ({ ...prev, name: e.target.value }))} placeholder="Nom du projet ou du client" className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm" />
          <input value={clientForm.company} onChange={(e) => setClientForm((prev) => ({ ...prev, company: e.target.value }))} placeholder="Société ou programme" className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm" />
          <input value={clientForm.email} onChange={(e) => setClientForm((prev) => ({ ...prev, email: e.target.value }))} placeholder="Contact projet (optionnel)" className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm sm:col-span-2" />
        </div>

        <div className="rounded-2xl bg-surface-container-high px-4 py-4 text-sm text-on-surface-variant">
          Ce dossier projet ne correspond pas à un compte utilisateur. Il sert à centraliser les repos et les rapports liés au même client ou au même projet.
        </div>

        <button onClick={handleCreateClient} className="rounded-2xl border border-outline-variant/[0.2] px-4 py-3 text-sm font-headline font-semibold text-on-surface">Créer le projet client</button>
      </section>

      <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-headline text-xl font-semibold text-on-surface">Dossiers projets</h2>
            <p className="mt-2 text-sm text-on-surface-variant">Chaque carte centralise les repos liés et l’accès à la fiche projet.</p>
          </div>
          <span className="text-xs text-outline">{clients.length} dossiers</span>
        </div>

        {loading ? (
          <p className="text-sm text-outline">Chargement…</p>
        ) : (
          <div className="grid gap-4 max-h-[40rem] overflow-y-auto pr-2">
            {clients.map((client) => (
              <article key={client.id} className="rounded-2xl bg-surface-container-high p-5 space-y-4">
                <div>
                  <h3 className="font-headline text-lg font-semibold text-on-surface">{client.name}</h3>
                  <p className="text-xs text-outline">{client.company || 'Programme non renseigné'} · {client.repositoryIds.length} repo(s) lié(s)</p>
                </div>

                <Link
                  to={`/admin/clients/${client.id}`}
                  className="inline-flex items-center gap-2 rounded-xl border border-outline-variant/[0.2] px-3 py-2 text-xs font-headline font-semibold text-on-surface hover:border-primary/40 hover:text-primary transition-colors"
                >
                  <span className="material-symbols-outlined text-sm">open_in_new</span>
                  Ouvrir le dossier projet
                </Link>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <p className="text-[11px] uppercase tracking-[0.2em] text-outline">Collaborateurs</p>
                    <p className="mt-2 text-sm text-on-surface">{client.employeeLogins.length ? client.employeeLogins.join(', ') : 'Aucun collaborateur affecté'}</p>
                  </div>
                  <div>
                    <p className="text-[11px] uppercase tracking-[0.2em] text-outline">Repos liés</p>
                    <div className="mt-2 space-y-2 text-sm text-on-surface">
                      {client.repositoryUrls.length ? client.repositoryUrls.map((repoUrl, index) => (
                        <div key={`${client.id}-${repoUrl}-${index}`} className="flex items-center justify-between gap-3 rounded-xl bg-surface-container px-3 py-2">
                          <span className="truncate">{repoUrl}</span>
                          <button onClick={() => handleRemoveRepository(client.id, client.repositoryIds[index])} className="text-xs text-error">Retirer</button>
                        </div>
                      )) : <p className="text-outline">Aucun repo lié</p>}
                    </div>
                  </div>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <select value={employeeSelections[client.id] ?? ''} onChange={(e) => setEmployeeSelections((prev) => ({ ...prev, [client.id]: e.target.value }))} className="w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container px-3 py-2 text-sm">
                      <option value="">Choisir un collaborateur</option>
                      {employees.map((entry) => (
                        <option key={entry.id} value={entry.id}>{entry.login}</option>
                      ))}
                    </select>
                    <button onClick={() => handleAssignEmployee(client.id)} className="w-full rounded-xl border border-outline-variant/[0.2] px-3 py-2 text-sm font-headline font-semibold text-on-surface">Assigner collaborateur</button>
                  </div>

                  <div className="space-y-2">
                    <select value={repoSelections[client.id] ?? ''} onChange={(e) => setRepoSelections((prev) => ({ ...prev, [client.id]: e.target.value }))} className="w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container px-3 py-2 text-sm">
                      <option value="">Choisir un repo</option>
                      {repositories.map((repo) => (
                        <option key={repo.id} value={repo.id}>{repo.repoUrl}</option>
                      ))}
                    </select>
                    <button onClick={() => handleAssignRepository(client.id)} className="w-full rounded-xl border border-outline-variant/[0.2] px-3 py-2 text-sm font-headline font-semibold text-on-surface">Lier le repo</button>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};

export default AdminProjectsPage;