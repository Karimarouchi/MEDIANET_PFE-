import React, { useEffect, useState } from "react";
import {
  getPipeline,
  getPipelines,
  getPipelineStepOutput,
  getProjectCi,
  getProjectUptime,
  getRepoDeployments,
  type ProjectUptime,
  type CdTarget,
  type PipelineDetail,
  type PipelineSummary,
  type ProjectCi,
} from "../services/api";
import { ciBlocking, ciStatus, ciTestCount, isCiActive } from "../utils/ci";

type RepoRow = {
  repoId: number;
  name: string;
  enabled: boolean;
  last: PipelineDetail | null;
  lastSuccess: PipelineSummary | null;
  tests: { passed: number; failed: number } | null;
  blocking: { where: string; why: string } | null;
  gate: "pass" | "fail" | null;
  cd: CdTarget[];
};

const SCAN_STEP = "vulnix-scan";

function shortName(url: string): string {
  return url.replace(/\.git$/, "").split("/").pop() || url;
}

function when(unix: number | null | undefined): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleString("fr-FR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

/** Last pipeline of one repository, read the same way as the CI/CD tab (step outputs give tests and the gate). */
async function loadRepo(repoId: number, name: string): Promise<RepoRow> {
  const cd = (await getRepoDeployments(repoId).catch(() => ({ data: [] as CdTarget[] }))).data;
  const history = (await getPipelines(repoId)).data;
  const lastSuccess = history.find((p) => p.status === "success") ?? null;
  if (history.length === 0) return { repoId, name, enabled: true, last: null, lastSuccess, tests: null, blocking: null, gate: null, cd };
  const last = (await getPipeline(repoId, history[0].number)).data;
  const lines: Record<number, string[]> = {};
  await Promise.all(last.steps.filter((s) => s.name !== "clone" && !isCiActive(s.state)).map(async (s) => {
    try {
      lines[s.id] = (await getPipelineStepOutput(repoId, last.pipeline.number, s.id)).data.map((l) => l.text);
    } catch {
      lines[s.id] = [];
    }
  }));
  const counts = last.steps.map((s) => ciTestCount(lines[s.id] ?? [])).filter((c): c is { passed: number; failed: number } => c != null);
  const tests: RepoRow["tests"] = counts.length
    ? { passed: counts.reduce((a, c) => a + c.passed, 0), failed: counts.reduce((a, c) => a + c.failed, 0) }
    : null;
  const scan = last.steps.find((s) => s.name === SCAN_STEP);
  const gate = scan && !isCiActive(scan.state) ? (scan.state === "success" ? "pass" : "fail") : null;
  const b = ciBlocking(last.pipeline.status, last.steps, last.errors, lines);
  return { repoId, name, enabled: true, last, lastSuccess, tests, blocking: b ? { where: b.where, why: b.why } : null, gate, cd };
}

const Kpi: React.FC<{ label: string; value: string; hint: string; tone: string; onClick: () => void }> = ({ label, value, hint, tone, onClick }) => (
  <button type="button" onClick={onClick}
    className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4 text-left hover:border-primary/40 hover:bg-primary/5 transition-all">
    <p className="text-[10px] uppercase tracking-widest text-outline">{label}</p>
    <p className={`text-3xl font-bold font-headline mt-1 ${tone}`}>{value}</p>
    <p className="text-[10px] text-on-surface-variant mt-1">{hint}</p>
  </button>
);

/** Availability of the project's sites, from Uptime Kuma. */
export function uptimeSummary(u: ProjectUptime | null): { value: string; hint: string; tone: string } {
  if (!u || !u.configured) return { value: "—", hint: "Uptime Kuma non configuré", tone: "text-outline" };
  if (!u.reachable) return { value: "?", hint: "Uptime Kuma injoignable", tone: "text-amber-300" };
  if (u.monitors.length === 0) {
    return { value: "—", hint: u.domains.length ? `aucun moniteur nommé ${u.domains[0]}` : "aucun domaine sur ce projet", tone: "text-outline" };
  }
  const down = u.monitors.filter((m) => m.status === "DOWN");
  const known = u.monitors.map((m) => m.uptime24h).filter((v): v is number => v != null);
  const avg = known.length ? known.reduce((a, b) => a + b, 0) / known.length : null;
  const value = avg == null ? "—" : `${(avg * 100).toLocaleString("fr-FR", { maximumFractionDigits: 1 })} %`;
  if (down.length) return { value, hint: `hors ligne : ${down.map((m) => m.name).join(", ")}`, tone: "text-error" };
  return { value, hint: `${u.monitors.length} site(s) en ligne · 24 h`, tone: avg != null && avg < 0.99 ? "text-amber-300" : "text-tertiary" };
}

const UptimeKpi: React.FC<{ uptime: ProjectUptime | null; onClick: () => void }> = ({ uptime, onClick }) => {
  const s = uptimeSummary(uptime);
  return <Kpi label="Disponibilité" value={s.value} hint={s.hint} tone={s.tone} onClick={onClick} />;
};

/** CI/CD block of the project overview: key figures of the last pipeline of each repository. */
const CiOverviewCard: React.FC<{ clientId: number; onOpenCi: () => void }> = ({ clientId, onOpenCi }) => {
  const [ci, setCi] = useState<ProjectCi | null>(null);
  const [rows, setRows] = useState<RepoRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [uptime, setUptime] = useState<ProjectUptime | null>(null);

  useEffect(() => {
    getProjectUptime(clientId).then((r) => setUptime(r.data)).catch(() => setUptime(null));
  }, [clientId]);

  useEffect(() => {
    let alive = true;
    setRows(null);
    setError(null);
    (async () => {
      try {
        const status = (await getProjectCi(clientId)).data;
        if (!alive) return;
        setCi(status);
        const out = await Promise.all(status.repositories.map(async (r) => {
          const name = r.forgeFullName ? r.forgeFullName.split("/").pop()! : shortName(r.repoUrl);
          if (!r.enabled) return { repoId: r.repositoryId, name, enabled: false, last: null, lastSuccess: null, tests: null, blocking: null, gate: null, cd: [] } as RepoRow;
          try {
            return await loadRepo(r.repositoryId, name);
          } catch {
            return { repoId: r.repositoryId, name, enabled: true, last: null, lastSuccess: null, tests: null, blocking: { where: "CI", why: "Pipelines illisibles pour le moment." }, gate: null, cd: [] } as RepoRow;
          }
        }));
        if (alive) setRows(out);
      } catch {
        if (alive) setError("Statut CI/CD indisponible.");
      }
    })();
    return () => {
      alive = false;
    };
  }, [clientId]);

  if (error) return null;
  if (!ci || !rows) {
    return <div className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4 text-sm text-outline">Chargement de la CI/CD…</div>;
  }
  if (!ci.configured || rows.length === 0) return null;

  const enabled = rows.filter((r) => r.enabled);
  const withRun = enabled.filter((r) => r.last);
  const green = withRun.filter((r) => r.last!.pipeline.status === "success").length;
  const running = withRun.filter((r) => isCiActive(r.last!.pipeline.status)).length;
  const passed = enabled.reduce((s, r) => s + (r.tests?.passed ?? 0), 0);
  const failed = enabled.reduce((s, r) => s + (r.tests?.failed ?? 0), 0);
  const gateFail = enabled.filter((r) => r.gate === "fail").length;
  const gateKnown = enabled.filter((r) => r.gate).length;
  const lastSuccess = enabled.map((r) => r.lastSuccess?.finished ?? 0).reduce((a, b) => Math.max(a, b), 0);
  const cdTargets = rows.flatMap((r) => r.cd);
  const cdAuto = cdTargets.filter((t) => t.automatic);
  const prodTimes = cdTargets.map((t) => (t.inProduction?.finishedAt ? Date.parse(t.inProduction.finishedAt) : 0));
  const lastProd = prodTimes.length ? Math.max(...prodTimes) : 0;
  const cdProblem = cdTargets.some((t) => t.last && (t.last.status === "FAILED" || t.last.status === "ROLLED_BACK"));

  return (
    <section className="rounded-3xl border border-outline-variant/[0.15] bg-surface-container-high/60 p-4 space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <p className="text-[10px] uppercase tracking-[0.28em] text-outline">CI/CD</p>
        <button type="button" onClick={onOpenCi} className="text-xs font-semibold text-primary hover:underline">Ouvrir la CI/CD</button>
      </div>

      <div className="grid grid-cols-2 gap-2 lg:grid-cols-7">
        <Kpi label="CI activée" value={`${enabled.length}/${rows.length}`} hint="dépôts avec pipeline"
          tone={enabled.length === rows.length ? "text-tertiary" : "text-amber-300"} onClick={onOpenCi} />
        <Kpi label="Pipelines verts" value={`${green}/${withRun.length}`}
          hint={running ? `${running} en cours` : "dernier pipeline de chaque dépôt"}
          tone={withRun.length > 0 && green === withRun.length ? "text-tertiary" : withRun.length ? "text-error" : "text-outline"} onClick={onOpenCi} />
        <Kpi label="Tests" value={String(passed)} hint={failed ? `${failed} en échec` : passed ? "réussis au dernier pipeline" : "aucun test exécuté"}
          tone={failed ? "text-error" : passed ? "text-tertiary" : "text-amber-300"} onClick={onOpenCi} />
        <Kpi label="Barrière Vulnix" value={gateKnown === 0 ? "—" : gateFail ? "Bloque" : "Passe"}
          hint={gateFail ? `${gateFail} dépôt(s) avec CVE bloquantes` : gateKnown ? "aucune CVE bloquante" : "pas encore exécutée"}
          tone={gateFail ? "text-error" : gateKnown ? "text-tertiary" : "text-outline"} onClick={onOpenCi} />
        <Kpi label="Dernier succès" value={lastSuccess ? when(lastSuccess).split(",")[0] : "Jamais"} hint={lastSuccess ? `à ${when(lastSuccess).split(", ")[1] ?? ""}` : "aucun pipeline vert"}
          tone={lastSuccess ? "text-on-surface" : "text-amber-300"} onClick={onOpenCi} />
        <Kpi label="En production" value={lastProd ? new Date(lastProd).toLocaleDateString("fr-FR", { day: "numeric", month: "short" }) : cdAuto.length ? "—" : "Manuel"}
          hint={cdProblem ? "dernier déploiement en échec ou annulé" : cdAuto.length ? `déploiement auto sur ${cdAuto.length} serveur(s)` : "CD non configuré"}
          tone={cdProblem ? "text-error" : cdAuto.length ? "text-tertiary" : "text-amber-300"} onClick={onOpenCi} />
        <UptimeKpi uptime={uptime} onClick={onOpenCi} />
      </div>

      <ul className="divide-y divide-outline-variant/[0.12] rounded-2xl border border-outline-variant/[0.15] bg-surface-container">
        {rows.map((r) => {
          const st = r.last ? ciStatus(r.last.pipeline.status) : null;
          return (
            <li key={r.repoId}>
              <button type="button" onClick={onOpenCi} className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-left text-sm hover:bg-primary/5">
                <span className="min-w-[9rem] font-headline font-semibold text-on-surface">{r.name}</span>
                {!r.enabled ? (
                  <span className="text-xs text-outline">CI non activée</span>
                ) : !r.last ? (
                  <span className="text-xs text-outline">Aucun pipeline lancé</span>
                ) : (
                  <>
                    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold ${st!.className}`}>
                      <span className={`material-symbols-outlined text-[13px] ${st!.spin ? "animate-spin" : ""}`}>{st!.icon}</span>
                      {st!.label}
                    </span>
                    <span className="font-mono text-[11px] text-outline">#{r.last.pipeline.number} · {r.last.pipeline.commit.slice(0, 8)}</span>
                    {r.tests && (
                      <span className={`text-xs ${r.tests.failed ? "text-error" : "text-tertiary"}`}>
                        {r.tests.passed} test(s) OK{r.tests.failed ? ` · ${r.tests.failed} en échec` : ""}
                      </span>
                    )}
                    {r.blocking && (
                      <span className="w-full text-xs text-error md:w-auto md:flex-1">
                        Bloqué à « {r.blocking.where} » : {r.blocking.why}
                      </span>
                    )}
                  </>
                )}
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
};

export default CiOverviewCard;
