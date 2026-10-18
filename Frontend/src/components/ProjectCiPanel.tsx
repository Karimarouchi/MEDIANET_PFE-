import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  cancelPipeline,
  disableRepoCi,
  enableRepoCi,
  getPipeline,
  getRepoDeployments,
  type CdTarget,
  getPipelines,
  getPipelineStepOutput,
  getProjectCi,
  runPipeline,
  type PipelineDetail,
  type PipelineLogLine,
  type PipelineSummary,
  type ProjectCi,
  type RepoCi,
} from "../services/api";
import { cdNodeFor, ciBlocking, ciDuration, ciStatus, ciStepError, ciStepLabel, ciStepOutcome, isCiActive, type StepOutcome } from "../utils/ci";
import PipelineGraph from "./PipelineGraph";
import CiRepoAnalysisPanel from "./CiRepoAnalysisPanel";
import CdTargetsPanel from "./CdTargetsPanel";

const POLL_MS = 4000;

function apiMessage(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string; error?: string } } };
  return e?.response?.data?.message || e?.response?.data?.error || fallback;
}

const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const s = ciStatus(status);
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold ${s.className}`}>
      <span className={`material-symbols-outlined text-[13px] ${s.spin ? "animate-spin" : ""}`}>{s.icon}</span>
      {s.label}
    </span>
  );
};

/** One pipeline: where it stopped and why, the graph with each step's result, and the output of the chosen step. */
const PipelineView: React.FC<{ repoId: number; number: number; onChanged: () => void }> = ({ repoId, number, onChanged }) => {
  const [detail, setDetail] = useState<PipelineDetail | null>(null);
  const [stepId, setStepId] = useState<number | null>(null);
  const [logs, setLogs] = useState<Record<number, string[]>>({});
  const [error, setError] = useState<string | null>(null);
  const fetched = useRef<Set<number>>(new Set());
  const logRef = useRef<HTMLPreElement>(null);
  const [targets, setTargets] = useState<CdTarget[]>([]);

  const load = useCallback(async () => {
    try {
      const d = (await getPipeline(repoId, number)).data;
      setDetail(d);
      getRepoDeployments(repoId).then((r) => setTargets(r.data)).catch(() => undefined);
      setError(null);
      setStepId((cur) => {
        if (cur != null && d.steps.some((s) => s.id === cur)) return cur;
        const pick = d.steps.find((s) => s.state === "failure" || s.state === "error") || d.steps.find((s) => s.state === "running") || d.steps[d.steps.length - 1];
        return pick ? pick.id : null;
      });
    } catch (e) {
      setError(apiMessage(e, "Impossible de charger ce pipeline."));
    }
  }, [repoId, number]);

  useEffect(() => {
    setDetail(null);
    setStepId(null);
    setLogs({});
    fetched.current = new Set();
    load();
  }, [load]);

  const deployNode = detail ? cdNodeFor(detail.pipeline, targets) : null;
  // Keep refreshing after a green pipeline until its deployment is over.
  const active = detail ? isCiActive(detail.pipeline.status) || deployNode?.tone === "running" : true;
  useEffect(() => {
    if (!active) return;
    const t = window.setInterval(load, POLL_MS);
    return () => window.clearInterval(t);
  }, [active, load]);

  const fetchLogs = useCallback((id: number) =>
    getPipelineStepOutput(repoId, number, id)
      .then((r) => setLogs((cur) => ({ ...cur, [id]: r.data.map((l: PipelineLogLine) => l.text) })))
      .catch(() => undefined), [repoId, number]);

  // Output of every finished step once (to show its result on the graph), running steps on each refresh.
  useEffect(() => {
    if (!detail) return;
    for (const s of detail.steps) {
      const done = !isCiActive(s.state);
      if (s.state === "running" || (done && !fetched.current.has(s.id))) {
        if (done) fetched.current.add(s.id);
        fetchLogs(s.id);
      }
    }
  }, [detail, fetchLogs]);

  const lines = stepId != null ? logs[stepId] ?? [] : [];
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [lines.length, stepId]);

  if (error) return <p className="text-sm text-error">{error}</p>;
  if (!detail) return <p className="text-sm text-outline">Chargement du pipeline…</p>;
  const p = detail.pipeline;
  const outcomes: Record<number, StepOutcome | null> = {};
  for (const s of detail.steps) outcomes[s.id] = ciStepOutcome(s.name, s.state, logs[s.id] ?? [], s.error);
  const blocking = ciBlocking(p.status, detail.steps, detail.errors, logs);
  const step = detail.steps.find((s) => s.id === stepId);

  return (
    <div className="mt-3 rounded-2xl border border-outline-variant/[0.15] bg-surface-container-low p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="font-headline font-bold text-on-surface">Pipeline #{p.number}</span>
          <StatusBadge status={p.status} />
          <span className="font-mono text-[11px] text-outline">{p.commit.slice(0, 10)}</span>
          <span className="text-[11px] text-outline">{p.event === "manual" ? "lancé depuis Vulnix" : `${p.event} de ${p.author}`}</span>
          <span className="text-[11px] text-outline">· {ciDuration(p.started, p.finished)}</span>
        </div>
        {active && (
          <button
            type="button"
            onClick={() => cancelPipeline(repoId, number).then(load).then(onChanged).catch((e) => setError(apiMessage(e, "Annulation refusée.")))}
            className="rounded-xl border border-error/30 px-3 py-1.5 text-xs font-semibold text-error hover:bg-error/10"
          >
            Arrêter
          </button>
        )}
      </div>

      {blocking && (
        <button
          type="button"
          onClick={() => blocking.stepId != null && setStepId(blocking.stepId)}
          className="flex w-full items-start gap-3 rounded-xl border border-error/40 bg-error/10 px-4 py-3 text-left"
        >
          <span className="material-symbols-outlined text-error">block</span>
          <span>
            <span className="block text-[10px] font-bold uppercase tracking-widest text-error">Pipeline bloqué à l'étape « {blocking.where} »</span>
            <span className="mt-0.5 block text-sm text-on-surface">{blocking.why}</span>
          </span>
        </button>
      )}
      {p.status === "success" && (
        <p className="flex items-center gap-2 rounded-xl border border-tertiary/40 bg-tertiary/10 px-4 py-2.5 text-sm text-on-surface">
          <span className="material-symbols-outlined text-tertiary">verified</span>
          Toutes les étapes sont passées : tests, compilation et barrière Vulnix.
        </p>
      )}

      <PipelineGraph
        steps={detail.steps}
        status={p.status}
        outcomes={outcomes}
        selected={stepId}
        blockedStepId={blocking?.stepId ?? null}
        onSelect={setStepId}
        deploy={deployNode}
      />

      {step && (
        <div className="rounded-xl border border-outline-variant/[0.15] bg-black/40">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-outline-variant/[0.12] px-3 py-2">
            <span className="text-xs font-bold text-on-surface">
              {ciStepLabel(step.name).title} <span className="font-normal text-outline">· {ciStepLabel(step.name).detail}</span>
            </span>
            <StatusBadge status={step.state} />
          </div>
          <pre
            ref={logRef}
            className="max-h-[24rem] min-h-[10rem] overflow-auto p-3 font-mono text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap break-all"
          >
            {lines.length > 0
              ? lines.join("\n")
              : step.error
                ? ciStepError(step.error)
                : step.state === "pending" ? "Étape en attente…" : "Pas encore de sortie."}
          </pre>
        </div>
      )}
    </div>
  );
};

const RepoCiCard: React.FC<{ clientId: number; repo: RepoCi; onChanged: () => void }> = ({ clientId, repo, onChanged }) => {
  const [pipelines, setPipelines] = useState<PipelineSummary[] | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const name = repo.forgeFullName || repo.repoUrl;

  const loadHistory = useCallback(async () => {
    if (!repo.enabled) return;
    try {
      const list = (await getPipelines(repo.repositoryId)).data;
      setPipelines(list);
      setOpen((cur) => cur ?? (list[0]?.number ?? null));
    } catch (e) {
      setError(apiMessage(e, "Impossible de lire l'historique."));
    }
  }, [repo.enabled, repo.repositoryId]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const anyActive = (pipelines ?? []).some((p) => isCiActive(p.status));
  useEffect(() => {
    if (!anyActive) return;
    const t = window.setInterval(loadHistory, POLL_MS * 2);
    return () => window.clearInterval(t);
  }, [anyActive, loadHistory]);

  const act = async (fn: () => Promise<unknown>, fallback: string) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(apiMessage(e, fallback));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-headline font-semibold text-on-surface">{name}</p>
          <p className="text-[11px] text-outline">
            Branche {repo.branch}
            {repo.enabled && repo.enabledAt ? ` · CI activée le ${new Date(repo.enabledAt).toLocaleDateString("fr-FR")}` : ""}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {repo.enabled && (
            <button
              type="button"
              disabled={busy || anyActive}
              onClick={() => act(async () => {
                const run = (await runPipeline(repo.repositoryId)).data;
                setOpen(run.number);
                await loadHistory();
              }, "Impossible de lancer le pipeline.")}
              className="flex items-center gap-2 rounded-xl border border-primary/30 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary hover:bg-primary/20 disabled:opacity-50"
            >
              <span className="material-symbols-outlined text-base">play_arrow</span>
              {anyActive ? "Pipeline en cours" : "Lancer la CI"}
            </button>
          )}
          {repo.supported && (
            <button
              type="button"
              disabled={busy}
              onClick={() => act(async () => {
                if (repo.enabled) {
                  if (!window.confirm("Désactiver la CI de ce dépôt ? Le jeton Vulnix du pipeline sera révoqué.")) return;
                  await disableRepoCi(clientId, repo.repositoryId);
                  setPipelines(null);
                  setOpen(null);
                } else {
                  await enableRepoCi(clientId, repo.repositoryId);
                }
                onChanged();
              }, repo.enabled ? "Désactivation refusée." : "Activation refusée.")}
              className={`rounded-xl px-4 py-2 text-sm font-semibold disabled:opacity-50 ${
                repo.enabled ? "text-on-surface-variant hover:text-error" : "bg-tertiary/15 text-tertiary hover:bg-tertiary/25"
              }`}
            >
              {busy ? "…" : repo.enabled ? "Désactiver" : "Activer la CI"}
            </button>
          )}
        </div>
      </div>
      {!repo.supported && <p className="mt-3 text-xs text-outline">{repo.unsupportedReason}</p>}
      {error && <p className="mt-3 text-xs text-error">{error}</p>}
      {repo.supported && (
        <CdTargetsPanel clientId={clientId} repoId={repo.repositoryId} branch={repo.branch} refreshKey={(pipelines ?? []).length + (pipelines?.[0]?.number ?? 0) + (anyActive ? 1 : 0)} />
      )}
      {repo.supported && (
        <CiRepoAnalysisPanel
          clientId={clientId}
          repoId={repo.repositoryId}
          repoName={name}
          showGraph={!repo.enabled || (pipelines != null && pipelines.length === 0)}
        />
      )}

      {repo.enabled && pipelines && pipelines.length === 0 && (
        <p className="mt-4 text-sm text-outline">Aucun pipeline pour l'instant. « Lancer la CI » teste le dernier commit de la branche {repo.branch}.</p>
      )}
      {repo.enabled && pipelines && pipelines.length > 0 && (
        <>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-[10px] uppercase tracking-widest text-outline">
                <tr>
                  <th className="py-1.5 pr-3 text-left">#</th>
                  <th className="py-1.5 pr-3 text-left">Résultat</th>
                  <th className="py-1.5 pr-3 text-left">Commit</th>
                  <th className="py-1.5 pr-3 text-left">Déclenché</th>
                  <th className="py-1.5 text-left">Durée</th>
                </tr>
              </thead>
              <tbody>
                {pipelines.slice(0, 10).map((p) => (
                  <tr
                    key={p.number}
                    onClick={() => setOpen(p.number)}
                    className={`cursor-pointer border-t border-outline-variant/[0.1] hover:bg-primary/5 ${open === p.number ? "bg-primary/5" : ""}`}
                  >
                    <td className="py-1.5 pr-3 font-mono text-outline">{p.number}</td>
                    <td className="py-1.5 pr-3"><StatusBadge status={p.status} /></td>
                    <td className="py-1.5 pr-3 font-mono text-outline">{p.commit.slice(0, 10)}</td>
                    <td className="py-1.5 pr-3 text-outline">
                      {p.event === "manual" ? "depuis Vulnix" : p.event === "push" ? `push de ${p.author}` : p.event}
                      {p.created ? ` · ${new Date(p.created * 1000).toLocaleString("fr-FR", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}` : ""}
                    </td>
                    <td className="py-1.5 text-outline">{ciDuration(p.started, p.finished)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {open != null && <PipelineView repoId={repo.repositoryId} number={open} onChanged={loadHistory} />}
        </>
      )}
    </div>
  );
};

const ProjectCiPanel: React.FC<{ clientId: number }> = ({ clientId }) => {
  const [ci, setCi] = useState<ProjectCi | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getProjectCi(clientId)
      .then((r) => {
        setCi(r.data);
        setError(null);
      })
      .catch((e) => setError(apiMessage(e, "Impossible de charger la CI du projet.")));
  }, [clientId]);

  useEffect(() => {
    load();
  }, [load]);

  if (error) return <p className="text-sm text-error">{error}</p>;
  if (!ci) return <p className="text-sm text-outline">Chargement de la CI…</p>;

  return (
    <section className="space-y-4">
      <div className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container-high/60 p-4">
        <p className="text-[10px] uppercase tracking-widest text-outline">Intégration continue</p>
        <p className="mt-1 text-sm text-on-surface-variant max-w-3xl">
          À chaque pipeline : les tests, le lint et la compilation de chaque partie du dépôt (Maven, npm…), puis le scan Vulnix
          du commit. Le pipeline échoue si un test casse ou si le scan trouve une vulnérabilité critique, élevée ou exploitée (KEV)
          sans exception validée. Rien n'est ajouté au dépôt : Vulnix écrit le pipeline.
        </p>
      </div>
      {!ci.configured && (
        <p className="rounded-2xl border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-300">
          La CI n'est pas encore installée sur ce serveur Vulnix (jeton Woodpecker absent).
        </p>
      )}
      {ci.repositories.length === 0 && <p className="text-sm text-outline">Aucun dépôt lié à ce projet.</p>}
      {ci.repositories.map((r) => (
        <RepoCiCard key={r.repositoryId} clientId={clientId} repo={r} onChanged={load} />
      ))}
    </section>
  );
};

export default ProjectCiPanel;
