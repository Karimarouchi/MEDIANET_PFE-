import React, { useEffect, useState } from "react";
import CommitPicker from "./CommitPicker";
import type { CommitInfo } from "../services/api";

/** "What to scan": the latest version of the branch, or one commit chosen in the list (an old version). */
const ScanCommitDialog: React.FC<{
  projectId: number; repositoryId: number | null; repoName: string; branch?: string | null;
  onClose: () => void; onStart: (commitSha: string | null) => void;
}> = ({ projectId, repositoryId, repoName, branch, onClose, onStart }) => {
  const [mode, setMode] = useState<"latest" | "commit">("latest");
  const [commit, setCommit] = useState<CommitInfo | null>(null);

  useEffect(() => {
    setMode("latest");
    setCommit(null);
  }, [repositoryId]);

  if (repositoryId == null) return null;
  const ready = mode === "latest" || commit != null;

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 backdrop-blur-sm px-4" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-labelledby="scan-commit-title"
        className="w-full max-w-lg rounded-2xl border border-outline-variant/30 bg-surface-container p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}>
        <h3 id="scan-commit-title" className="font-headline text-lg font-bold text-on-surface mb-4">Scanner {repoName}</h3>
        <div className="space-y-3 text-sm">
          <label className="flex cursor-pointer items-start gap-2">
            <input type="radio" name="scan-target" checked={mode === "latest"} onChange={() => setMode("latest")} className="mt-1" />
            <span>
              <span className="font-semibold text-on-surface">Dernière version</span>
              <span className="block text-xs text-on-surface-variant">Le code actuel de la branche {branch || "par défaut"}.</span>
            </span>
          </label>
          <label className="flex cursor-pointer items-start gap-2">
            <input type="radio" name="scan-target" checked={mode === "commit"} onChange={() => setMode("commit")} className="mt-1" />
            <span>
              <span className="font-semibold text-on-surface">Une ancienne version (un commit précis)</span>
              <span className="block text-xs text-on-surface-variant">Si ce commit est introuvable, le scan s'arrête au lieu d'analyser une autre version.</span>
            </span>
          </label>
          {mode === "commit" && (
            <CommitPicker projectId={projectId} repositoryId={repositoryId} selected={commit} onPick={setCommit} />
          )}
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" onClick={onClose}
            className="px-4 py-2 rounded-xl text-sm font-medium text-on-surface-variant border border-outline-variant/30 hover:bg-surface-container-highest">
            Annuler
          </button>
          <button type="button" disabled={!ready} onClick={() => onStart(mode === "commit" && commit ? commit.sha : null)}
            className="px-4 py-2 rounded-xl text-sm font-bold bg-primary/20 text-primary border border-primary/30 hover:bg-primary/30 disabled:opacity-40">
            {mode === "commit" && commit ? `Scanner ${commit.shortSha}` : "Lancer le scan"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScanCommitDialog;
