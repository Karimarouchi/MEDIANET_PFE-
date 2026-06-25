import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useOutletContext } from "react-router-dom";
import { type AdminPanelContextValue } from "../AdminPanel";

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
    message,
    error,
  } = useOutletContext<AdminPanelContextValue>();

  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);

  const handleCreate = async () => {
    setCreating(true);
    await handleCreateClient();
    setCreating(false);
    setCreateOpen(false);
  };

  // Short display label — handles git https://, docker://, ssl://, etc.
  const shortUrl = (url: string): string => {
    if (!url || !url.trim()) return "(sans URL)";
    try {
      const parsed = new URL(url);
      // Standard https/http git repo — extract owner/repo from path
      const path = parsed.pathname
        .replace(/^\//, "")
        .replace(/\.git$/, "")
        .trim();
      if (path) return path;
      // docker:// or other protocols where path is empty — use hostname
      if (parsed.hostname)
        return `${parsed.protocol.replace(":", "")}://${parsed.hostname}`;
      return url;
    } catch {
      // Not a standard URL — strip .git and return as is
      return url.replace(/\.git$/, "").trim() || url;
    }
  };

  // Only show real Git repos in the assign-repo select (exclude docker/ssl/dast synthetic URLs)
  const gitRepos = repositories.filter(
    (r) =>
      r.repoUrl &&
      !r.repoUrl.startsWith("docker://") &&
      !r.repoUrl.startsWith("ssl://") &&
      !r.repoUrl.startsWith("dast://"),
  );

  return (
    <div className="space-y-6">
      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="font-headline text-2xl font-bold text-on-surface">
            Dossiers projets
          </h2>
          <p className="mt-1 text-sm text-on-surface-variant max-w-xl">
            Chaque carte centralise les repos liés et l'accès à la fiche projet.
          </p>
        </div>
        <button
          onClick={() => setCreateOpen(true)}
          className="flex-shrink-0 flex items-center gap-2 rounded-2xl bg-primary px-5 py-3 font-headline text-sm font-semibold text-on-primary hover:opacity-90 active:scale-95 transition-all shadow-lg shadow-primary/20"
        >
          <span className="material-symbols-outlined text-base">add</span>
          Créer un projet
        </button>
      </div>

      {/* ── Global messages ───────────────────────────────────────────────── */}
      {(message || error) && (
        <div
          className={`rounded-2xl border px-4 py-3 text-sm ${
            error
              ? "border-error/30 bg-error/10 text-error"
              : "border-primary/30 bg-primary/10 text-primary"
          }`}
        >
          {message || error}
        </div>
      )}

      {/* ── Loading ───────────────────────────────────────────────────────── */}
      {loading && (
        <div className="flex items-center justify-center py-20">
          <span className="material-symbols-outlined text-4xl text-primary animate-spin">
            progress_activity
          </span>
        </div>
      )}

      {/* ── Empty state ───────────────────────────────────────────────────── */}
      {!loading && clients.length === 0 && (
        <div className="flex flex-col items-center justify-center py-24 text-outline-variant space-y-4">
          <span className="material-symbols-outlined text-6xl">
            folder_special
          </span>
          <p className="text-lg font-headline">Aucun projet</p>
          <p className="text-sm">
            Cliquez sur "Créer un projet" pour commencer.
          </p>
        </div>
      )}

      {/* ── Cards grid ────────────────────────────────────────────────────── */}
      {!loading && clients.length > 0 && (
        <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
          {clients.map((client) => (
            <article
              key={client.id}
              className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container flex flex-col overflow-hidden"
            >
              {/* Card header */}
              <div className="px-5 pt-5 pb-4 border-b border-outline-variant/[0.1]">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0">
                      <span className="material-symbols-outlined text-primary text-base">
                        folder_special
                      </span>
                    </div>
                    <div className="min-w-0">
                      <h3 className="font-headline font-bold text-on-surface truncate">
                        {client.name}
                      </h3>
                      <p className="text-[11px] text-outline truncate">
                        {client.company || "Société non renseignée"}
                      </p>
                    </div>
                  </div>
                  <Link
                    to={`/admin/clients/${client.id}`}
                    title="Ouvrir la fiche projet"
                    className="flex-shrink-0 flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold border border-outline-variant/[0.2] text-outline hover:text-primary hover:border-primary/40 transition-colors"
                  >
                    <span className="material-symbols-outlined text-[13px]">
                      open_in_new
                    </span>
                    Fiche
                  </Link>
                </div>

                {/* Stats row */}
                <div className="flex items-center gap-4 mt-3">
                  <span className="flex items-center gap-1 text-[11px] text-outline">
                    <span className="material-symbols-outlined text-[13px]">
                      code_blocks
                    </span>
                    {client.repositoryIds.length} repo(s)
                  </span>
                  <span className="flex items-center gap-1 text-[11px] text-outline">
                    <span className="material-symbols-outlined text-[13px]">
                      group
                    </span>
                    {client.employeeLogins.length} collaborateur(s)
                  </span>
                </div>
              </div>

              {/* Card body */}
              <div className="flex-1 px-5 py-4 space-y-4">
                {/* Collaborators */}
                <div>
                  <p className="text-[10px] uppercase tracking-widest text-outline mb-2">
                    Collaborateurs
                  </p>
                  {client.employeeLogins.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {client.employeeLogins.map((login) => (
                        <span
                          key={login}
                          className="px-2 py-0.5 rounded-full bg-secondary/10 text-secondary text-[11px] font-medium"
                        >
                          {login}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] text-outline italic">
                      Aucun collaborateur affecté
                    </p>
                  )}
                </div>

                {/* Repos linked */}
                <div>
                  <p className="text-[10px] uppercase tracking-widest text-outline mb-2">
                    Repos liés
                  </p>
                  {client.repositoryUrls.length > 0 ? (
                    <div className="space-y-1.5 max-h-32 overflow-y-auto pr-1 custom-scrollbar">
                      {client.repositoryUrls.map((repoUrl, idx) => (
                        <div
                          key={`${client.id}-${repoUrl}-${idx}`}
                          className="flex items-center justify-between gap-2 rounded-lg bg-surface-container-low border border-outline-variant/[0.12] px-3 py-1.5"
                        >
                          <span
                            className="text-[11px] text-on-surface-variant truncate"
                            title={repoUrl}
                          >
                            {shortUrl(repoUrl)}
                          </span>
                          <button
                            onClick={() =>
                              handleRemoveRepository(
                                client.id,
                                client.repositoryIds[idx],
                              )
                            }
                            className="flex-shrink-0 text-[10px] font-semibold text-error/70 hover:text-error transition-colors px-1"
                          >
                            Retirer
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] text-outline italic">
                      Aucun repo lié
                    </p>
                  )}
                </div>
              </div>

              {/* Card footer — actions */}
              <div className="px-5 pb-5 space-y-2 border-t border-outline-variant/[0.1] pt-4">
                {/* Assign employee */}
                <div className="flex gap-2">
                  <select
                    value={employeeSelections[client.id] ?? ""}
                    onChange={(e) =>
                      setEmployeeSelections((prev) => ({
                        ...prev,
                        [client.id]: e.target.value,
                      }))
                    }
                    className="flex-1 min-w-0 rounded-xl border border-outline-variant/[0.2] bg-surface-container-low px-3 py-2 text-xs text-on-surface appearance-none [color-scheme:dark]"
                  >
                    <option value="">Choisir un collaborateur</option>
                    {employees.map((e) => (
                      <option key={e.id} value={e.id}>
                        {e.login}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={() => handleAssignEmployee(client.id)}
                    disabled={!employeeSelections[client.id]}
                    className="flex-shrink-0 flex items-center gap-1 px-3 py-2 rounded-xl border border-outline-variant/[0.2] text-xs font-semibold text-on-surface hover:border-secondary/50 hover:text-secondary disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    <span className="material-symbols-outlined text-[13px]">
                      person_add
                    </span>
                    Assigner
                  </button>
                </div>

                {/* Assign repo */}
                <div className="flex gap-2">
                  <select
                    value={repoSelections[client.id] ?? ""}
                    onChange={(e) =>
                      setRepoSelections((prev) => ({
                        ...prev,
                        [client.id]: e.target.value,
                      }))
                    }
                    className="flex-1 min-w-0 rounded-xl border border-outline-variant/[0.2] bg-surface-container-low px-3 py-2 text-xs text-on-surface appearance-none [color-scheme:dark]"
                  >
                    <option value="">Choisir un repo</option>
                    {gitRepos.map((r) => (
                      <option key={r.id} value={r.id}>
                        {shortUrl(r.repoUrl)}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={() => handleAssignRepository(client.id)}
                    disabled={!repoSelections[client.id]}
                    className="flex-shrink-0 flex items-center gap-1 px-3 py-2 rounded-xl border border-outline-variant/[0.2] text-xs font-semibold text-on-surface hover:border-primary/50 hover:text-primary disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    <span className="material-symbols-outlined text-[13px]">
                      link
                    </span>
                    Lier
                  </button>
                </div>
              </div>
            </article>
          ))}
        </div>
      )}

      {/* ══════════════════ MODAL CRÉER UN PROJET ══════════════════ */}
      {createOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          onClick={() => setCreateOpen(false)}
        >
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
          <div
            className="relative z-10 w-full max-w-md bg-surface-container rounded-2xl border border-outline-variant/[0.2] shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal header */}
            <div className="flex items-center justify-between px-6 py-4 bg-surface-container-highest/50 border-b border-outline-variant/[0.1]">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
                  <span className="material-symbols-outlined text-primary text-base">
                    folder_special
                  </span>
                </div>
                <h2 className="font-headline font-bold text-on-surface">
                  Créer un projet
                </h2>
              </div>
              <button
                onClick={() => setCreateOpen(false)}
                className="text-outline hover:text-on-surface transition-colors"
              >
                <span className="material-symbols-outlined text-lg">close</span>
              </button>
            </div>

            {/* Modal body */}
            <div className="p-6 space-y-4">
              <div className="space-y-3">
                <div>
                  <label className="block text-[10px] uppercase tracking-widest text-outline mb-1.5">
                    Nom du projet <span className="text-error">*</span>
                  </label>
                  <input
                    value={clientForm.name}
                    onChange={(e) =>
                      setClientForm((prev) => ({
                        ...prev,
                        name: e.target.value,
                      }))
                    }
                    placeholder="ex: RH-Application, Medianet-Store…"
                    className="w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface placeholder:text-outline focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30"
                  />
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-widest text-outline mb-1.5">
                    Société / Programme
                  </label>
                  <input
                    value={clientForm.company}
                    onChange={(e) =>
                      setClientForm((prev) => ({
                        ...prev,
                        company: e.target.value,
                      }))
                    }
                    placeholder="ex: Antigone Agency, Hostinger…"
                    className="w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface placeholder:text-outline focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30"
                  />
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-widest text-outline mb-1.5">
                    Email de contact{" "}
                    <span className="text-outline/50 normal-case tracking-normal">
                      (optionnel)
                    </span>
                  </label>
                  <input
                    value={clientForm.email}
                    onChange={(e) =>
                      setClientForm((prev) => ({
                        ...prev,
                        email: e.target.value,
                      }))
                    }
                    placeholder="contact@client.com"
                    type="email"
                    className="w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface placeholder:text-outline focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30"
                  />
                </div>
              </div>

              <p className="text-[11px] text-outline leading-relaxed">
                Ce dossier projet centralise les repos GitHub/GitLab et les
                rapports de sécurité liés au même client. Il ne correspond pas à
                un compte utilisateur.
              </p>
            </div>

            {/* Modal footer */}
            <div className="flex gap-3 px-6 pb-6">
              <button
                onClick={() => setCreateOpen(false)}
                className="flex-1 rounded-xl border border-outline-variant/[0.2] px-4 py-2.5 text-sm font-headline font-semibold text-on-surface-variant hover:text-on-surface hover:border-outline-variant/50 transition-colors"
              >
                Annuler
              </button>
              <button
                onClick={handleCreate}
                disabled={creating || !clientForm.name.trim()}
                className="flex-1 flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-headline font-semibold text-on-primary hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                <span className="material-symbols-outlined text-base">
                  {creating ? "progress_activity" : "add_circle"}
                </span>
                {creating ? "Création…" : "Créer le projet"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminProjectsPage;
