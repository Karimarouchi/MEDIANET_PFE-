import React, { useEffect, useState } from "react";
import { getCommitDetail, getProjectActivity, type ActivityCommit, type CommitDetail, type ProjectActivity } from "../services/api";
import { commitDate } from "./CommitPicker";

function apiMessage(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string; error?: string } } };
  return e?.response?.data?.message || e?.response?.data?.error || fallback;
}

const PERIODS = [
  { days: 7, label: "7 jours" },
  { days: 30, label: "30 jours" },
  { days: 90, label: "90 jours" },
  { days: 0, label: "Tout" },
];

const STATUS_FR: Record<string, string> = { added: "ajouté", removed: "supprimé", modified: "modifié", renamed: "renommé" };

/** One commit, opened on demand: files, added / removed lines, full message. */
const CommitRow: React.FC<{ projectId: number; c: ActivityCommit; showAuthor?: boolean }> = ({ projectId, c, showAuthor }) => {
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<CommitDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && !detail) {
      getCommitDetail(projectId, c.repositoryId, c.sha)
        .then((r) => setDetail(r.data))
        .catch((e) => setError(apiMessage(e, "Détail indisponible.")));
    }
  };

  return (
    <li className="border-b border-outline-variant/[0.08] last:border-0">
      <button type="button" onClick={toggle} aria-expanded={open}
        className="flex w-full items-start gap-2 px-3 py-2 text-left text-xs hover:bg-surface-container-high">
        <span className="material-symbols-outlined text-sm text-outline" aria-hidden="true">{open ? "expand_more" : "chevron_right"}</span>
        <span className="font-mono text-primary">{c.shortSha}</span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-on-surface">{c.title || "(sans message)"}</span>
          <span className="block text-[11px] text-outline">
            {c.repository} · {commitDate(c.date)}{showAuthor ? ` · ${c.authorName || c.authorLogin || c.authorEmail || "?"}` : ""}
          </span>
        </span>
      </button>
      {open && (
        <div className="space-y-2 px-9 pb-3 text-xs">
          {error && <p className="text-error">{error}</p>}
          {!detail && !error && <p className="text-outline">Chargement…</p>}
          {detail && (
            <>
              <p className="text-on-surface-variant">
                <span className="text-green-400">+{detail.additions}</span> / <span className="text-red-400">−{detail.deletions}</span> lignes ·{" "}
                {detail.files.length}{detail.truncated ? "+" : ""} fichier(s) · auteur {detail.commit.authorName || "?"}
                {detail.commit.authorEmail ? ` <${detail.commit.authorEmail}>` : ""}
              </p>
              {detail.commit.message.trim() !== detail.commit.title.trim() && (
                <pre className="whitespace-pre-wrap rounded-lg bg-black/30 p-2 font-sans text-on-surface-variant">{detail.commit.message.trim()}</pre>
              )}
              <ul className="max-h-48 overflow-auto rounded-lg border border-outline-variant/[0.12]">
                {detail.files.map((f) => (
                  <li key={f.path} className="flex items-center gap-2 border-b border-outline-variant/[0.06] px-2 py-1 last:border-0">
                    <span className="w-16 shrink-0 text-[10px] uppercase text-outline">{STATUS_FR[f.status] ?? f.status}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-on-surface" title={f.path}>{f.path}</span>
                    <span className="text-green-400">+{f.additions}</span>
                    <span className="text-red-400">−{f.deletions}</span>
                  </li>
                ))}
              </ul>
              {c.url && <a href={c.url} target="_blank" rel="noopener noreferrer" className="font-semibold text-primary hover:underline">Voir sur la forge</a>}
            </>
          )}
        </div>
      )}
    </li>
  );
};

/** Who works on the project: commits of each member assigned to it, then the authors that are not members. */
const ProjectActivityPanel: React.FC<{ projectId: number }> = ({ projectId }) => {
  const [days, setDays] = useState(30);
  const [data, setData] = useState<ProjectActivity | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openMember, setOpenMember] = useState<string | null>(null);

  useEffect(() => {
    setData(null);
    setError(null);
    getProjectActivity(projectId, days)
      .then((r) => setData(r.data))
      .catch((e) => setError(apiMessage(e, "Impossible de lire l'activité du projet.")));
  }, [projectId, days]);

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-headline text-lg font-bold text-on-surface">Activité de l'équipe</h2>
          <p className="text-xs text-on-surface-variant">Commits des dépôts du projet, par membre affecté au projet.</p>
        </div>
        <div className="flex gap-1 rounded-xl bg-surface-container-high p-1" role="group" aria-label="Période">
          {PERIODS.map((p) => (
            <button key={p.days} type="button" onClick={() => setDays(p.days)} aria-pressed={days === p.days}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold ${days === p.days ? "bg-primary text-on-primary" : "text-on-surface-variant hover:text-on-surface"}`}>
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {error && <p className="text-sm text-error" role="alert">{error}</p>}
      {!data && !error && <p className="text-sm text-outline">Lecture des commits sur GitHub / GitLab…</p>}

      {data && (
        <>
          <p className="text-sm text-on-surface-variant">
            {data.totalCommits} commit(s) {data.days ? `sur les ${data.days} derniers jours` : "au total"}.
          </p>
          {data.errors.map((e) => (
            <p key={e.repositoryId} className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
              {e.repository} : {e.message}
            </p>
          ))}
          {data.members.length === 0 && (
            <p className="text-sm text-outline">Aucun membre n'est affecté à ce projet (Admin → projets → affecter un employé).</p>
          )}
          <div className="grid gap-3">
            {data.members.map((m) => {
              const key = `m${m.userId}`;
              const open = openMember === key;
              return (
                <div key={key} className="rounded-xl border border-outline-variant/[0.15] bg-surface-container">
                  <button type="button" onClick={() => setOpenMember(open ? null : key)} aria-expanded={open}
                    className="flex w-full flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 text-left">
                    <span className="font-headline text-sm font-semibold text-on-surface">{m.name || m.login || m.email}</span>
                    <span className="text-xs text-outline">{m.login}{m.email && m.email !== m.login ? ` · ${m.email}` : ""}</span>
                    <span className={`ml-auto rounded-full px-2 py-0.5 text-xs font-bold ${m.commits ? "bg-primary/15 text-primary" : "bg-surface-variant text-on-surface-variant"}`}>
                      {m.commits} commit{m.commits > 1 ? "s" : ""}
                    </span>
                    <span className="w-full text-[11px] text-on-surface-variant">
                      {m.lastCommit ? `Dernier commit : ${commitDate(m.lastCommit)}` : "Aucun commit sur la période"}
                      {m.repositories.length ? ` · ${m.repositories.join(", ")}` : ""}
                    </span>
                  </button>
                  {open && m.list.length > 0 && (
                    <ul className="border-t border-outline-variant/[0.1]">
                      {m.list.map((c) => <CommitRow key={c.sha} projectId={projectId} c={c} />)}
                    </ul>
                  )}
                </div>
              );
            })}
          </div>
          {data.others.length > 0 && (
            <div className="rounded-xl border border-outline-variant/[0.15] bg-surface-container">
              <button type="button" onClick={() => setOpenMember(openMember === "others" ? null : "others")} aria-expanded={openMember === "others"}
                className="flex w-full items-center gap-3 px-4 py-3 text-left">
                <span className="font-headline text-sm font-semibold text-on-surface">Autres auteurs</span>
                <span className="text-xs text-outline">
                  {data.others.map((o) => `${o.name || o.login || o.email} (${o.commits})`).join(", ")}
                </span>
              </button>
              {openMember === "others" && (
                <ul className="border-t border-outline-variant/[0.1]">
                  {data.others.flatMap((o) => o.list).map((c) => <CommitRow key={c.sha} projectId={projectId} c={c} showAuthor />)}
                </ul>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
};

export default ProjectActivityPanel;
