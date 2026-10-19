import React, { useEffect, useState } from "react";
import CommitPicker from "./CommitPicker";
import { deployChosenCommit, type CdTarget, type CommitInfo } from "../services/api";

function apiMessage(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string; error?: string } } };
  return e?.response?.data?.message || e?.response?.data?.error || fallback;
}

/**
 * Puts a chosen (older) commit in production on one server. Same deploy as the CD: backup when configured, exact
 * commit, health check, automatic rollback. When it passes, the version is pinned and green pipelines stop deploying
 * there until "Reprendre". Confirmation: type the first 7 characters of the commit.
 */
const DeployCommitDialog: React.FC<{
  projectId: number; repositoryId: number; target: CdTarget | null; onClose: () => void; onStarted: () => void;
}> = ({ projectId, repositoryId, target, onClose, onStarted }) => {
  const [commit, setCommit] = useState<CommitInfo | null>(null);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setCommit(null);
    setTyped("");
    setError(null);
  }, [target?.deploymentId]);

  if (!target) return null;
  const expected = commit ? commit.sha.slice(0, 7) : "";
  const confirmed = !!commit && typed.trim().toLowerCase() === expected.toLowerCase();
  const isCurrent = !!commit && target.inProduction?.commitSha === commit.sha;

  const deploy = async () => {
    if (!commit || !confirmed) return;
    setBusy(true);
    setError(null);
    try {
      await deployChosenCommit(target.deploymentId, commit.sha);
      onStarted();
    } catch (e) {
      setError(apiMessage(e, "Le déploiement n'a pas pu démarrer : rien n'a changé sur le serveur."));
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 backdrop-blur-sm px-4" onClick={() => !busy && onClose()}>
      <div role="dialog" aria-modal="true" aria-labelledby="deploy-commit-title"
        className="w-full max-w-lg rounded-2xl border border-amber-500/30 bg-surface-container p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}>
        <h3 id="deploy-commit-title" className="font-headline text-lg font-bold text-on-surface mb-1">
          Mettre une autre version en production
        </h3>
        <p className="mb-4 text-xs text-on-surface-variant">
          Serveur <b className="text-on-surface">{target.serverName}</b> · {target.host}:{target.path}
          {target.inProduction?.commitSha && <> · en production : <span className="font-mono">{target.inProduction.commitSha.slice(0, 8)}</span></>}
        </p>

        <CommitPicker projectId={projectId} repositoryId={repositoryId} selected={commit} onPick={(c) => { setCommit(c); setTyped(""); }} />

        {commit && (
          <div className="mt-4 space-y-2 text-xs text-on-surface-variant">
            <ul className="list-disc pl-5 space-y-0.5">
              {target.backupEnabled && <li>La base est sauvegardée avant ({target.backupService}).</li>}
              <li>Le serveur passe sur le commit <span className="font-mono text-on-surface">{commit.sha.slice(0, 12)}</span>, puis est contrôlé ; en cas d'échec, la version actuelle est remise automatiquement.</li>
              <li>Si tout va bien, cette version est <b className="text-on-surface">épinglée</b> : les prochains pipelines verts ne la remplaceront plus jusqu'à « Reprendre le déploiement automatique ».</li>
              <li>Le schéma de la base n'est pas ramené en arrière : si la dernière version l'a modifié, vérifiez que l'ancienne le supporte.</li>
            </ul>
            {isCurrent && <p className="text-amber-300">Ce commit est déjà celui en production.</p>}
            <label className="block pt-1">
              Pour confirmer, tapez <b className="font-mono text-on-surface">{expected}</b>
              <input value={typed} onChange={(e) => setTyped(e.target.value)} disabled={busy} aria-label="Confirmation du commit"
                className="mt-1 w-full rounded-xl border border-outline-variant/30 bg-surface px-3 py-2 font-mono text-on-surface outline-none focus:border-amber-500/60" />
            </label>
          </div>
        )}
        {error && <p className="mt-3 text-sm text-error" role="alert">{error}</p>}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" onClick={onClose} disabled={busy}
            className="px-4 py-2 rounded-xl text-sm font-medium text-on-surface-variant border border-outline-variant/30 hover:bg-surface-container-highest disabled:opacity-50">
            Annuler
          </button>
          <button type="button" onClick={deploy} disabled={!confirmed || busy}
            className="px-4 py-2 rounded-xl text-sm font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30 disabled:opacity-40">
            {busy ? "Démarrage…" : commit ? `Déployer ${commit.shortSha}` : "Déployer"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default DeployCommitDialog;
