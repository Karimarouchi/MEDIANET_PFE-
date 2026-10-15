import React, { useEffect, useState } from "react";
import {
  assignRepositoryToClient,
  getRepositories,
  registerRepository,
  type RepositoryDto,
} from "../services/api";

function normalizeGitUrl(raw: string): string {
  let url = raw.trim();
  if (!url) return "";
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  return url.replace(/\/+$/, "");
}

function repoProvider(url: string): string {
  const lower = url.toLowerCase();
  if (lower.includes("gitlab")) return "GitLab";
  if (lower.includes("github")) return "GitHub";
  return "Git";
}

function repoShort(url: string): string {
  return url.replace(/^https?:\/\//, "").replace(/\.git$/, "");
}

/** Paste a Git URL or pick a known repository, then link it to this project without scanning. */
const AddProjectRepoPanel: React.FC<{
  clientId: number;
  linkedIds: number[];
  onAdded: () => void;
}> = ({ clientId, linkedIds, onAdded }) => {
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState("");
  const [query, setQuery] = useState("");
  const [known, setKnown] = useState<RepositoryDto[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    getRepositories()
      .then((res) => setKnown(res.data.filter((r) => r.repoUrl && !r.repoUrl.startsWith("ssl://") && !r.repoUrl.startsWith("docker://"))))
      .catch(() => setKnown([]));
  }, [open]);

  const link = async (repoId: number) => {
    setBusy(true);
    setError(null);
    try {
      await assignRepositoryToClient(clientId, repoId);
      setUrl("");
      onAdded();
    } catch {
      setError("Liaison du dépôt impossible.");
    } finally {
      setBusy(false);
    }
  };

  const addUrl = async () => {
    const normalized = normalizeGitUrl(url);
    if (!normalized.includes("/")) return;
    setBusy(true);
    setError(null);
    try {
      const created = await registerRepository({ repoUrl: normalized });
      await assignRepositoryToClient(clientId, created.data.id);
      setUrl("");
      onAdded();
    } catch {
      setError("Ajout du dépôt impossible. Vérifiez l'URL.");
    } finally {
      setBusy(false);
    }
  };

  const preview = normalizeGitUrl(url);
  const q = query.trim().toLowerCase();
  const choices = known.filter((r) => !linkedIds.includes(r.id) && (!q || repoShort(r.repoUrl).toLowerCase().includes(q)));

  return (
    <div className="mb-4">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-xl bg-primary/10 border border-primary/30 px-3 py-2 text-xs font-semibold text-primary hover:bg-primary/20"
      >
        <span className="material-symbols-outlined text-sm">add</span>
        {open ? "Fermer" : "Ajouter un dépôt"}
      </button>
      {open && (
        <div className="mt-3 rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4 space-y-3">
          <div className="flex gap-2">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addUrl()}
              placeholder="github.com/organisation/depot"
              className="flex-1 min-w-0 rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-3 py-2 text-xs text-on-surface placeholder:text-outline"
            />
            <button
              type="button"
              disabled={busy || !url.trim()}
              onClick={addUrl}
              className="px-3 rounded-xl bg-primary text-on-primary text-xs font-semibold disabled:opacity-40"
            >
              Lier cette URL
            </button>
          </div>
          {preview.includes("/") && (
            <p className="text-[11px] text-outline">
              {repoProvider(preview)} · {repoShort(preview)}
            </p>
          )}
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ou rechercher un dépôt déjà connu"
            className="w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-3 py-2 text-xs text-on-surface placeholder:text-outline"
          />
          <div className="max-h-36 overflow-y-auto divide-y divide-outline-variant/[0.1]">
            {choices.length === 0 && <p className="text-xs text-outline py-2">Aucun dépôt à lier.</p>}
            {choices.slice(0, 8).map((r) => (
              <button
                key={r.id}
                type="button"
                disabled={busy}
                onClick={() => link(r.id)}
                className="w-full flex items-center justify-between gap-2 py-2 text-left text-xs text-on-surface hover:text-primary disabled:opacity-40"
              >
                <span className="truncate">{repoShort(r.repoUrl)}</span>
                <span className="text-[10px] text-outline shrink-0">Lier</span>
              </button>
            ))}
          </div>
          {error && <p className="text-xs text-error">{error}</p>}
        </div>
      )}
    </div>
  );
};

export default AddProjectRepoPanel;
