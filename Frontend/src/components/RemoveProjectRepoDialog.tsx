import React, { useEffect, useState } from "react";
import { getRepoRemovalPreview, removeRepositoryFromClient, type RepoRemovalPreview } from "../services/api";

function apiMessage(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string; error?: string } } };
  return e?.response?.data?.message || e?.response?.data?.error || fallback;
}

/**
 * Removes one repository from a project. By default it is only detached (its scans stay in Vulnix); when no other
 * project uses it, an administrator may tick "also delete it with its scans".
 */
const RemoveProjectRepoDialog: React.FC<{
  projectId: number; repositoryId: number | null; onClose: () => void; onRemoved: () => void;
}> = ({ projectId, repositoryId, onClose, onRemoved }) => {
  const [preview, setPreview] = useState<RepoRemovalPreview | null>(null);
  const [alsoDelete, setAlsoDelete] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (repositoryId == null) return;
    setPreview(null);
    setAlsoDelete(false);
    setError(null);
    getRepoRemovalPreview(projectId, repositoryId)
      .then((r) => setPreview(r.data))
      .catch((e) => setError(apiMessage(e, "Impossible de préparer le retrait.")));
  }, [projectId, repositoryId]);

  useEffect(() => {
    if (repositoryId == null) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape" && !busy) onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [repositoryId, busy, onClose]);

  if (repositoryId == null) return null;
  const blocked = alsoDelete && !!preview && preview.blockers.length > 0;

  const confirm = async () => {
    if (!preview || blocked) return;
    setBusy(true);
    setError(null);
    try {
      await removeRepositoryFromClient(projectId, repositoryId, alsoDelete);
      onRemoved();
    } catch (e) {
      setError(apiMessage(e, "Le retrait a échoué : rien n'a changé."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 backdrop-blur-sm px-4"
      onClick={() => !busy && onClose()}>
      <div role="dialog" aria-modal="true" aria-labelledby="remove-repo-title"
        className="w-full max-w-md rounded-2xl border border-outline-variant/30 bg-surface-container p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}>
        <h3 id="remove-repo-title" className="font-headline text-lg font-bold text-on-surface mb-3">
          Retirer {preview ? `« ${preview.repository} »` : "le dépôt"} du projet
        </h3>
        {!preview && !error && <p className="text-sm text-on-surface-variant">Chargement…</p>}
        {preview && (
          <div className="space-y-3 text-sm text-on-surface-variant">
            <p>
              Le dépôt n'apparaîtra plus dans ce projet.
              {preview.ciEnabled && " Sa CI, activée par ce projet, sera désactivée dans Woodpecker."}
              {" "}Ses déploiements sur les serveurs ne sont pas modifiés.
            </p>
            {preview.shared && (
              <p>Il est aussi utilisé par un autre projet : il y reste, avec ses {preview.scans} scan(s).</p>
            )}
            {!preview.shared && !preview.canDelete && (
              <p>Ses {preview.scans} scan(s) restent dans Vulnix (page Repositories) : il pourra être relié à nouveau.</p>
            )}
            {preview.canDelete && (
              <label className="flex items-start gap-2 rounded-xl border border-error/25 bg-error/5 p-3 cursor-pointer">
                <input type="checkbox" className="mt-0.5" checked={alsoDelete} onChange={(e) => setAlsoDelete(e.target.checked)} disabled={busy} />
                <span>
                  <span className="font-semibold text-error">Supprimer aussi le dépôt et ses {preview.scans} scan(s)</span>
                  <span className="block text-xs">Vulnérabilités, secrets et fichiers de résultats compris. Sinon il reste dans Vulnix et pourra être relié à nouveau.</span>
                </span>
              </label>
            )}
            {blocked && <p className="text-tertiary">{preview.blockers[0]}</p>}
          </div>
        )}
        {error && <p className="mt-3 text-sm text-error" role="alert">{error}</p>}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" onClick={onClose} disabled={busy}
            className="px-4 py-2 rounded-xl text-sm font-medium text-on-surface-variant border border-outline-variant/30 hover:bg-surface-container-highest disabled:opacity-50">
            Annuler
          </button>
          <button type="button" onClick={confirm} disabled={!preview || blocked || busy}
            className="px-4 py-2 rounded-xl text-sm font-bold bg-error/20 text-error border border-error/30 hover:bg-error/30 disabled:opacity-40">
            {busy ? "…" : alsoDelete ? "Retirer et supprimer" : "Retirer du projet"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default RemoveProjectRepoDialog;
