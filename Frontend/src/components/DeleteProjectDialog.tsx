import React, { useEffect, useState } from "react";
import { deleteProject, getProjectDeletionPreview, type ProjectDeletionPreview } from "../services/api";

function apiMessage(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string; error?: string } } };
  return e?.response?.data?.message || e?.response?.data?.error || fallback;
}

const plural = (n: number, one: string, many: string) => `${n} ${n > 1 ? many : one}`;

/** Lines of the "what will be removed" list. Exported for the tests. */
export function deletionLines(p: ProjectDeletionPreview): { deleted: string[]; kept: string[] } {
  const deleted: string[] = [];
  const kept: string[] = [];
  if (p.repositoriesDeleted.length) {
    deleted.push(`${plural(p.repositoriesDeleted.length, "dépôt", "dépôts")} (${p.repositoriesDeleted.join(", ")}) et `
      + `${plural(p.scans, "scan", "scans")} avec leurs vulnérabilités, secrets et fichiers de résultats`);
  }
  if (p.serversDeleted.length) {
    deleted.push(`${plural(p.serversDeleted.length, "serveur", "serveurs")} (${p.serversDeleted.join(", ")}), `
      + `${plural(p.deployments, "déploiement", "déploiements")} et leur historique`);
  }
  if (p.ciRepositories) {
    deleted.push(`la CI de ${plural(p.ciRepositories, "dépôt", "dépôts")} : désactivée dans Woodpecker, jetons supprimés`);
  }
  deleted.push("les membres, le domaine, l'alerte SSL, la date de livraison et les notifications du projet");
  if (p.repositoriesDetached.length) {
    kept.push(`${plural(p.repositoriesDetached.length, "dépôt partagé", "dépôts partagés")} avec un autre projet, seulement détaché${p.repositoriesDetached.length > 1 ? "s" : ""} : ${p.repositoriesDetached.join(", ")}`);
  }
  if (p.serversDetached.length) {
    kept.push(`${plural(p.serversDetached.length, "serveur partagé", "serveurs partagés")}, seulement détaché${p.serversDetached.length > 1 ? "s" : ""} : ${p.serversDetached.join(", ")}`);
  }
  kept.push("rien n'est modifié sur les serveurs eux-mêmes ni sur GitHub");
  return { deleted, kept };
}

/**
 * Deletes a project after showing everything that goes with it. The button only works once the exact project
 * name is typed, and stays off while a scan or a deployment of the project is running.
 */
const DeleteProjectDialog: React.FC<{ projectId: number; open: boolean; onClose: () => void; onDeleted: () => void }> = ({
  projectId, open, onClose, onDeleted,
}) => {
  const [preview, setPreview] = useState<ProjectDeletionPreview | null>(null);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setPreview(null);
    setTyped("");
    setError(null);
    getProjectDeletionPreview(projectId)
      .then((r) => setPreview(r.data))
      .catch((e) => setError(apiMessage(e, "Impossible de préparer la suppression.")));
  }, [open, projectId]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape" && !busy) onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, busy, onClose]);

  if (!open) return null;

  const matches = !!preview && typed.trim() === preview.projectName.trim();
  const blocked = !!preview && preview.blockers.length > 0;
  const lines = preview ? deletionLines(preview) : null;

  const confirm = async () => {
    if (!preview || !matches || blocked) return;
    setBusy(true);
    setError(null);
    try {
      await deleteProject(projectId, typed);
      onDeleted();
    } catch (e) {
      setError(apiMessage(e, "La suppression a échoué : rien n'a été supprimé."));
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 backdrop-blur-sm px-4"
      onClick={() => !busy && onClose()}>
      <div role="dialog" aria-modal="true" aria-labelledby="delete-project-title"
        className="w-full max-w-lg rounded-2xl border border-error/30 bg-surface-container p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3 mb-4">
          <span className="material-symbols-outlined text-error text-2xl" aria-hidden="true">warning</span>
          <h3 id="delete-project-title" className="font-headline text-lg font-bold text-on-surface">
            Supprimer le projet{preview ? ` « ${preview.projectName} »` : ""}
          </h3>
        </div>

        {!preview && !error && <p className="text-sm text-on-surface-variant">Calcul de ce qui sera supprimé…</p>}

        {lines && (
          <div className="space-y-4 text-sm">
            <div>
              <p className="font-semibold text-error mb-1">Sera supprimé définitivement :</p>
              <ul className="list-disc pl-5 space-y-1 text-on-surface">
                {lines.deleted.map((l) => <li key={l}>{l}</li>)}
              </ul>
            </div>
            <div>
              <p className="font-semibold text-on-surface-variant mb-1">Est conservé :</p>
              <ul className="list-disc pl-5 space-y-1 text-on-surface-variant">
                {lines.kept.map((l) => <li key={l}>{l}</li>)}
              </ul>
            </div>
            {blocked && (
              <div className="rounded-xl border border-tertiary/40 bg-tertiary/10 px-3 py-2 text-tertiary">
                {preview!.blockers.map((b) => <p key={b}>{b}</p>)}
              </div>
            )}
            <label className="block">
              <span className="text-on-surface-variant">
                Pour confirmer, tapez le nom du projet : <b className="text-on-surface">{preview!.projectName}</b>
              </span>
              <input value={typed} onChange={(e) => setTyped(e.target.value)} disabled={busy || blocked}
                aria-label="Nom du projet à supprimer" autoFocus
                className="mt-2 w-full rounded-xl border border-outline-variant/30 bg-surface px-3 py-2 text-on-surface outline-none focus:border-error/60" />
            </label>
          </div>
        )}

        {error && <p className="mt-4 text-sm text-error" role="alert">{error}</p>}

        <div className="mt-6 flex justify-end gap-3">
          <button type="button" onClick={onClose} disabled={busy}
            className="px-4 py-2 rounded-xl text-sm font-medium text-on-surface-variant border border-outline-variant/30 hover:bg-surface-container-highest disabled:opacity-50">
            Annuler
          </button>
          <button type="button" onClick={confirm} disabled={!matches || blocked || busy}
            className="px-4 py-2 rounded-xl text-sm font-bold bg-error/20 text-error border border-error/30 hover:bg-error/30 disabled:opacity-40 disabled:cursor-not-allowed">
            {busy ? "Suppression…" : "Supprimer définitivement"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default DeleteProjectDialog;
