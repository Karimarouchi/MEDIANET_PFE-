import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useOutletContext } from "react-router-dom";
import { type AdminPanelContextValue } from "../AdminPanel";
import { getServerNodes, type ServerNodeDto } from "../../services/api";
import type { NewProjectLinks } from "../AdminPanel";
import DeadlineBadge from "../../components/DeadlineBadge";

const todayIso = () => new Date().toISOString().slice(0, 10);

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
    handleSetDeadline,
    message,
    error,
  } = useOutletContext<AdminPanelContextValue>();

  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);

  // repos / servers picked in the creation form (attached right after the project is created)
  const [pickedRepoIds, setPickedRepoIds] = useState<number[]>([]);
  const [pickedServerIds, setPickedServerIds] = useState<number[]>([]);
  const [newServers, setNewServers] = useState<NewProjectLinks["newServers"]>([]);
  const [draftServer, setDraftServer] = useState({ name: "", host: "", environment: "TEST" as "TEST" | "PROD" });
  const [serverOptions, setServerOptions] = useState<ServerNodeDto[]>([]);

  useEffect(() => {
    if (!createOpen) return;
    getServerNodes()
      .then((res) => setServerOptions(res.data))
      .catch(() => setServerOptions([]));
  }, [createOpen]);

  const toggle = (list: number[], id: number) =>
    list.includes(id) ? list.filter((x) => x !== id) : [...list, id];

  const addDraftServer = () => {
    const name = draftServer.name.trim();
    const host = draftServer.host.trim();
    if (!name || !host) return;
    setNewServers((prev) => [...prev, { name, host, environment: draftServer.environment }]);
    setDraftServer({ name: "", host: "", environment: draftServer.environment });
  };

  const handleCreate = async () => {
    setCreating(true);
    await handleCreateClient({ repositoryIds: pickedRepoIds, serverIds: pickedServerIds, newServers });
    setCreating(false);
    setCreateOpen(false);
    setPickedRepoIds([]);
    setPickedServerIds([]);
    setNewServers([]);
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
                      <p className="text-[11px] text-outline truncate flex flex-col">
                        <span>{client.company || "Société non renseignée"}</span>
                        {client.domainName && <span className="text-primary">{client.domainName}</span>}
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

                {/* Deadline du projet : compte à rebours, modifiable */}
                <div className="mt-3">
                  <DeadlineBadge
                    deadline={client.releaseDeadline}
                    label={client.releaseLabel}
                    onChange={(d) => handleSetDeadline(client, d)}
                  />
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
            className="relative z-10 w-full max-w-lg max-h-[90vh] flex flex-col bg-surface-container rounded-2xl border border-outline-variant/[0.2] shadow-2xl overflow-hidden"
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
            <div className="p-6 space-y-4 overflow-y-auto">
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
                <div className="rounded-xl border border-primary/30 bg-primary/5 p-3">
                  <label className="block text-[10px] uppercase tracking-widest text-outline mb-1.5">
                    Deadline du projet (date de fin) <span className="text-error">*</span>
                  </label>
                  <input
                    type="date"
                    min={todayIso()}
                    value={clientForm.releaseDeadline}
                    onChange={(e) =>
                      setClientForm((prev) => ({
                        ...prev,
                        releaseDeadline: e.target.value,
                      }))
                    }
                    className="w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30 [color-scheme:dark]"
                  />
                  <p className="text-[11px] text-outline mt-1.5 leading-relaxed">
                    Date à laquelle le projet doit être livré. Le modèle d'estimation compare le temps restant au temps
                    nécessaire pour corriger les vulnérabilités bloquantes, et annonce le risque de retard.
                  </p>
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
                    Nom de domaine{" "}
                    <span className="text-outline/50 normal-case tracking-normal">
                      (optionnel)
                    </span>
                  </label>
                  <input
                    value={clientForm.domainName}
                    onChange={(e) =>
                      setClientForm((prev) => ({
                        ...prev,
                        domainName: e.target.value,
                      }))
                    }
                    placeholder="ex: courtlinker.com"
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
                <div>
                  <label className="block text-[10px] uppercase tracking-widest text-outline mb-1.5">
                    Libellé de release{" "}
                    <span className="text-outline/50 normal-case tracking-normal">
                      (optionnel)
                    </span>
                  </label>
                  <input
                    value={clientForm.releaseLabel}
                    onChange={(e) =>
                      setClientForm((prev) => ({
                        ...prev,
                        releaseLabel: e.target.value,
                      }))
                    }
                    placeholder="ex: MEP boutique, Go-live 15 oct…"
                    className="w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface placeholder:text-outline focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30"
                  />
                </div>
              </div>

              {/* Repos du projet */}
              <div>
                <label className="block text-[10px] uppercase tracking-widest text-outline mb-1.5">
                  Repos du projet{" "}
                  <span className="text-outline/50 normal-case tracking-normal">(optionnel, {pickedRepoIds.length} choisi(s))</span>
                </label>
                <div className="max-h-36 overflow-y-auto rounded-xl border border-outline-variant/[0.2] bg-surface-container-high divide-y divide-outline-variant/[0.1]">
                  {gitRepos.length === 0 && <p className="px-3 py-2 text-xs text-outline italic">Aucun repo disponible</p>}
                  {gitRepos.map((r) => (
                    <label key={r.id} className="flex items-center gap-2 px-3 py-2 text-xs text-on-surface cursor-pointer hover:bg-primary/5">
                      <input
                        type="checkbox"
                        checked={pickedRepoIds.includes(r.id)}
                        onChange={() => setPickedRepoIds((p) => toggle(p, r.id))}
                      />
                      <span className="truncate" title={r.repoUrl}>{shortUrl(r.repoUrl)}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Serveurs / VPS */}
              <div>
                <label className="block text-[10px] uppercase tracking-widest text-outline mb-1.5">
                  Serveurs / VPS{" "}
                  <span className="text-outline/50 normal-case tracking-normal">(optionnel, plusieurs possibles)</span>
                </label>
                {serverOptions.length > 0 && (
                  <div className="max-h-32 overflow-y-auto rounded-xl border border-outline-variant/[0.2] bg-surface-container-high divide-y divide-outline-variant/[0.1] mb-2">
                    {serverOptions.map((sv) => (
                      <label key={sv.id} className="flex items-center gap-2 px-3 py-2 text-xs text-on-surface cursor-pointer hover:bg-primary/5">
                        <input
                          type="checkbox"
                          checked={pickedServerIds.includes(sv.id)}
                          onChange={() => setPickedServerIds((p) => toggle(p, sv.id))}
                        />
                        <span className="truncate">{sv.name}</span>
                        <span className="text-outline">{sv.host}</span>
                        {sv.environment && <span className="ml-auto text-[10px] text-outline">{sv.environment}</span>}
                      </label>
                    ))}
                  </div>
                )}
                {newServers.map((sv, i) => (
                  <div key={`${sv.name}-${i}`} className="flex items-center gap-2 px-3 py-1.5 mb-1 rounded-lg bg-primary/5 border border-primary/20 text-xs text-on-surface">
                    <span className="material-symbols-outlined text-[14px] text-primary">dns</span>
                    <span className="truncate">{sv.name}</span>
                    <span className="text-outline">{sv.host}</span>
                    <span className="text-[10px] text-outline">{sv.environment}</span>
                    <button
                      type="button"
                      onClick={() => setNewServers((p) => p.filter((_, j) => j !== i))}
                      className="ml-auto text-error/70 hover:text-error text-[10px] font-semibold"
                    >
                      Retirer
                    </button>
                  </div>
                ))}
                <div className="flex gap-2">
                  <input
                    value={draftServer.name}
                    onChange={(e) => setDraftServer((d) => ({ ...d, name: e.target.value }))}
                    placeholder="Nom (ex: vps-test)"
                    className="w-1/3 min-w-0 rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-3 py-2 text-xs text-on-surface placeholder:text-outline"
                  />
                  <input
                    value={draftServer.host}
                    onChange={(e) => setDraftServer((d) => ({ ...d, host: e.target.value }))}
                    placeholder="IP ou domaine"
                    className="flex-1 min-w-0 rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-3 py-2 text-xs text-on-surface placeholder:text-outline"
                  />
                  <select
                    value={draftServer.environment}
                    onChange={(e) => setDraftServer((d) => ({ ...d, environment: e.target.value as "TEST" | "PROD" }))}
                    className="rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-2 py-2 text-xs text-on-surface [color-scheme:dark]"
                  >
                    <option value="TEST">Test</option>
                    <option value="PROD">Production</option>
                  </select>
                  <button
                    type="button"
                    onClick={addDraftServer}
                    disabled={!draftServer.name.trim() || !draftServer.host.trim()}
                    className="px-3 rounded-xl border border-outline-variant/[0.2] text-xs font-semibold text-on-surface hover:border-primary/50 disabled:opacity-40"
                  >
                    Ajouter
                  </button>
                </div>
                <p className="text-[10px] text-outline mt-1">
                  Un serveur ajouté ici est léger (sans accès SSH) : il sert à la cartographie d'attaque. Pour scanner sa
                  configuration, complétez-le ensuite dans Server Config.
                </p>
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
                disabled={creating || !clientForm.name.trim() || !clientForm.releaseDeadline}
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
