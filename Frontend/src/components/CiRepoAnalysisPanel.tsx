import React, { useEffect, useState } from "react";
import { getRepoCiAnalysis, type CiRepoAnalysis, type PipelineStep } from "../services/api";
import type { StepOutcome } from "../utils/ci";
import PipelineGraph from "./PipelineGraph";

function apiMessage(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string; error?: string } } };
  return e?.response?.data?.message || e?.response?.data?.error || fallback;
}

/** Planned steps as graph nodes (negative ids: they do not exist in Woodpecker yet). */
export function plannedGraph(a: CiRepoAnalysis): { steps: PipelineStep[]; outcomes: Record<number, StepOutcome | null> } {
  const steps: PipelineStep[] = a.plannedSteps.map((name, i) => ({
    id: -(i + 1), name, state: "planned", exitCode: null, error: null, started: null, finished: null,
  }));
  const outcomes: Record<number, StepOutcome | null> = {};
  for (const s of steps) {
    const part = a.parts.find((p) => p.step === s.name);
    if (part) {
      outcomes[s.id] = (part.warnings ?? []).length > 0
        ? { tone: "bad", text: `Échouera : ${part.warnings[0].replace(/`/g, "")}` }
        : part.hasTests
          ? { tone: "ok", text: `${part.testFiles} fichier(s) de test · ${part.stack}` }
          : { tone: "warn", text: `Aucun test · ${part.stack}` };
    } else if (s.name === "clone") {
      outcomes[s.id] = { tone: "info", text: "Code du commit poussé." };
    } else if (s.name === "vulnix-scan") {
      outcomes[s.id] = { tone: "info", text: "CVE, secrets, code · barrière critique / élevée / KEV." };
    }
  }
  return { steps, outcomes };
}

const partLabel = (kind: string, dir: string) =>
  `${kind === "maven" ? "Maven" : kind === "npm" ? "npm" : kind === "python" ? "Python" : "PHP"} · ${dir || "racine"}`;

/** Prompt with its scope: which parts, and an optional theme ("auth") to keep the AI's work (and quota) small. */
const PromptDialog: React.FC<{ clientId: number; repoId: number; repoName: string; analysis: CiRepoAnalysis; onClose: () => void }> = ({
  clientId, repoId, repoName, analysis, onClose,
}) => {
  const [steps, setSteps] = useState<string[]>(analysis.parts.map((p) => p.step));
  const [focus, setFocus] = useState("");
  const [prompt, setPrompt] = useState(analysis.prompt);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const refresh = async (nextSteps = steps, nextFocus = focus) => {
    setLoading(true);
    setError(null);
    try {
      setPrompt((await getRepoCiAnalysis(clientId, repoId, { steps: nextSteps, focus: nextFocus })).data.prompt);
    } catch (e) {
      setError(apiMessage(e, "Impossible de régénérer le prompt."));
    } finally {
      setLoading(false);
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(prompt);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2500);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-labelledby="ci-prompt-title" onClick={(e) => e.stopPropagation()}
        className="flex max-h-[92vh] w-full max-w-3xl flex-col rounded-3xl border border-outline-variant/30 bg-surface-container-high p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 id="ci-prompt-title" className="font-headline text-lg font-bold text-on-surface">Prompt pour préparer les tests</h2>
            <p className="mt-1 text-xs text-on-surface-variant">
              {repoName} · à coller dans Claude (ou un autre assistant) ouvert dans le dépôt. L'IA écrit le code des tests ;
              rien n'est exécuté sur votre machine, c'est la CI qui les lance au push. Le prompt ne contient ni code source ni secret.
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Fermer" className="text-outline hover:text-on-surface">
            <span className="material-symbols-outlined">close</span>
          </button>
        </div>

        <div className="mt-4 grid gap-3 rounded-xl border border-outline-variant/20 bg-surface-container p-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <fieldset>
            <legend className="text-[10px] uppercase tracking-widest text-outline">Parties à tester</legend>
            <div className="mt-1.5 flex flex-wrap gap-2">
              {analysis.parts.map((p) => {
                const on = steps.includes(p.step);
                return (
                  <label key={p.step} className={`flex cursor-pointer items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs ${
                    on ? "border-primary/50 bg-primary/10 text-primary" : "border-outline-variant/30 text-on-surface-variant"
                  }`}>
                    <input type="checkbox" className="accent-current" checked={on} onChange={() => {
                      const next = on ? steps.filter((s) => s !== p.step) : [...steps, p.step];
                      if (next.length === 0) return;
                      setSteps(next);
                      refresh(next, focus);
                    }} />
                    {partLabel(p.kind, p.dir)}
                  </label>
                );
              })}
            </div>
          </fieldset>
          <form onSubmit={(e) => { e.preventDefault(); refresh(); }}>
            <label htmlFor="ci-prompt-focus" className="text-[10px] uppercase tracking-widest text-outline">Thème (facultatif)</label>
            <div className="mt-1.5 flex gap-2">
              <input id="ci-prompt-focus" value={focus} onChange={(e) => setFocus(e.target.value)} placeholder="ex. auth, invoice, client"
                className="min-w-0 flex-1 rounded-lg border border-outline-variant/30 bg-surface-container-high px-2.5 py-1.5 text-xs text-on-surface" />
              <button type="submit" disabled={loading}
                className="rounded-lg border border-primary/30 px-3 py-1.5 text-xs font-semibold text-primary hover:bg-primary/10 disabled:opacity-50">
                {loading ? "…" : "Appliquer"}
              </button>
            </div>
            <p className="mt-1 text-[10px] text-outline">Limite les fichiers ciblés à ceux dont le chemin contient ce mot : moins de travail, moins de quota IA.</p>
          </form>
        </div>
        {error && <p className="mt-2 text-xs text-error">{error}</p>}

        <textarea readOnly value={prompt}
          className={`mt-3 min-h-[20rem] flex-1 resize-none rounded-xl border border-outline-variant/30 bg-black/40 p-3 font-mono text-[11px] leading-relaxed text-slate-200 ${loading ? "opacity-50" : ""}`} />
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <p className="text-[11px] text-outline">Ensuite : relisez les fichiers proposés, poussez-les, puis « Lancer la CI ».</p>
          <button type="button" onClick={copy} disabled={loading}
            className="flex items-center gap-2 rounded-xl border border-primary/30 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary hover:bg-primary/20 disabled:opacity-50">
            <span className="material-symbols-outlined text-base">{copied ? "check" : "content_copy"}</span>
            {copied ? "Copié" : "Copier le prompt"}
          </button>
        </div>
      </div>
    </div>
  );
};

/** What the CI will run on the repository, missing tests, problems that will fail it anyway, and the AI prompt. */
const CiRepoAnalysisPanel: React.FC<{ clientId: number; repoId: number; repoName: string; showGraph: boolean }> = ({
  clientId, repoId, repoName, showGraph,
}) => {
  const [analysis, setAnalysis] = useState<CiRepoAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [promptOpen, setPromptOpen] = useState(false);

  useEffect(() => {
    setAnalysis(null);
    setError(null);
    getRepoCiAnalysis(clientId, repoId)
      .then((r) => setAnalysis(r.data))
      .catch((e) => setError(apiMessage(e, "Analyse du dépôt impossible.")));
  }, [clientId, repoId]);

  if (error) return <p className="mt-3 text-xs text-error">{error}</p>;
  if (!analysis) return <p className="mt-3 text-xs text-outline">Analyse du dépôt sur GitHub…</p>;
  const missing = analysis.parts.filter((p) => !p.hasTests);
  const warnings = analysis.parts.flatMap((p) => p.warnings ?? []);
  const graph = plannedGraph(analysis);

  return (
    <div className="mt-4 space-y-3">
      {showGraph && (
        <>
          <p className="text-[10px] uppercase tracking-widest text-outline">Pipeline prévu pour ce dépôt</p>
          <PipelineGraph steps={graph.steps} status="planned" outcomes={graph.outcomes} selected={null} blockedStepId={null} onSelect={() => undefined} />
        </>
      )}
      {warnings.length > 0 && (
        <div className="rounded-xl border border-error/40 bg-error/10 px-4 py-3 text-sm">
          <span className="block text-[10px] font-bold uppercase tracking-widest text-error">Échouera quels que soient les tests</span>
          <ul className="mt-1 space-y-0.5 text-on-surface">
            {warnings.map((w) => <li key={w}>{w.replace(/`/g, "")}</li>)}
          </ul>
        </div>
      )}
      <div className={`flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 ${
        missing.length ? "border-amber-500/40 bg-amber-500/10" : "border-tertiary/30 bg-tertiary/10"
      }`}>
        <div className="text-sm">
          {missing.length === 0 ? (
            <span className="text-on-surface">Chaque partie du dépôt a des tests que la CI exécutera.</span>
          ) : (
            <>
              <span className="block text-[10px] font-bold uppercase tracking-widest text-amber-300">Tests manquants</span>
              <ul className="mt-1 space-y-0.5 text-on-surface">
                {missing.map((p) => <li key={p.step}>{p.dir || "racine"} : {p.missing}</li>)}
              </ul>
              <span className="mt-1 block text-[11px] text-on-surface-variant">
                Sans test, la CI reste verte dès que le code compile : elle ne prouve pas qu'il fonctionne.
              </span>
            </>
          )}
        </div>
        <button type="button" onClick={() => setPromptOpen(true)}
          className="flex shrink-0 items-center gap-2 rounded-xl border border-primary/30 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary hover:bg-primary/20">
          <span className="material-symbols-outlined text-base">auto_awesome</span>
          Générer le prompt IA des tests
        </button>
      </div>
      {promptOpen && (
        <PromptDialog clientId={clientId} repoId={repoId} repoName={repoName} analysis={analysis} onClose={() => setPromptOpen(false)} />
      )}
    </div>
  );
};

export default CiRepoAnalysisPanel;
