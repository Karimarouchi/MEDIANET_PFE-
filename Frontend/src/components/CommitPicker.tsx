import React, { useEffect, useState } from "react";
import { getCommitDetail, getRepoCommits, type CommitInfo } from "../services/api";

function apiMessage(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string; error?: string } } };
  return e?.response?.data?.message || e?.response?.data?.error || fallback;
}

export function commitDate(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

/**
 * Picks one commit of a project repository: the last 30 (message, author, date) or a pasted SHA, checked on
 * GitHub / GitLab so a short SHA becomes the full one. {@code onPick} gets the full commit or null.
 */
const CommitPicker: React.FC<{
  projectId: number; repositoryId: number; selected: CommitInfo | null; onPick: (c: CommitInfo | null) => void;
}> = ({ projectId, repositoryId, selected, onPick }) => {
  const [commits, setCommits] = useState<CommitInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pasted, setPasted] = useState("");
  const [checking, setChecking] = useState(false);
  const [pasteError, setPasteError] = useState<string | null>(null);

  useEffect(() => {
    setCommits(null);
    setError(null);
    getRepoCommits(projectId, repositoryId, 30)
      .then((r) => setCommits(r.data.commits))
      .catch((e) => setError(apiMessage(e, "Impossible de lire les commits.")));
  }, [projectId, repositoryId]);

  const checkPasted = async () => {
    const sha = pasted.trim();
    if (!/^[0-9a-fA-F]{7,40}$/.test(sha)) {
      setPasteError("Un identifiant de commit fait 7 à 40 caractères hexadécimaux (ex. 898e9b3).");
      return;
    }
    setChecking(true);
    setPasteError(null);
    try {
      onPick((await getCommitDetail(projectId, repositoryId, sha)).data.commit);
    } catch (e) {
      setPasteError(apiMessage(e, "Commit introuvable dans ce dépôt."));
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="space-y-2">
      {error && <p className="text-xs text-error" role="alert">{error}</p>}
      {!commits && !error && <p className="text-xs text-outline">Lecture des commits…</p>}
      {commits && commits.length === 0 && <p className="text-xs text-outline">Aucun commit trouvé sur la branche du dépôt.</p>}
      {commits && commits.length > 0 && (
        <ul className="max-h-60 overflow-auto rounded-xl border border-outline-variant/[0.15]" aria-label="Commits du dépôt">
          {commits.map((c, i) => {
            const active = selected?.sha === c.sha;
            return (
              <li key={c.sha}>
                <button type="button" onClick={() => onPick(c)} aria-pressed={active}
                  className={`flex w-full items-start gap-2 border-b border-outline-variant/[0.08] px-3 py-2 text-left text-xs last:border-0 ${active ? "bg-primary/15" : "hover:bg-surface-container-high"}`}>
                  <span className="font-mono text-primary">{c.shortSha}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-on-surface">{c.title || "(sans message)"}</span>
                    <span className="block text-[11px] text-outline">
                      {c.authorName || c.authorLogin || "auteur inconnu"} · {commitDate(c.date)}{i === 0 ? " · dernière version" : ""}
                    </span>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
      <div className="flex gap-2">
        <input value={pasted} onChange={(e) => { setPasted(e.target.value); setPasteError(null); }}
          onKeyDown={(e) => e.key === "Enter" && checkPasted()}
          placeholder="ou collez un identifiant de commit (SHA)" aria-label="Identifiant de commit"
          className="flex-1 rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-3 py-2 font-mono text-xs text-on-surface placeholder:font-sans placeholder:text-outline" />
        <button type="button" onClick={checkPasted} disabled={!pasted.trim() || checking}
          className="rounded-xl border border-outline-variant/[0.2] px-3 text-xs font-semibold text-on-surface disabled:opacity-40">
          {checking ? "…" : "Vérifier"}
        </button>
      </div>
      {pasteError && <p className="text-xs text-error" role="alert">{pasteError}</p>}
      {selected && (
        <p className="text-xs text-on-surface-variant">
          Choisi : <span className="font-mono text-on-surface">{selected.sha.slice(0, 12)}</span> — {selected.title}
        </p>
      )}
    </div>
  );
};

export default CommitPicker;
