import React, { useMemo, useState } from "react";
import { ansiSpans, failedTests, isErrorLine, stripAnsi, topPackages, vulnixReport, vulnixSummary } from "../utils/ciReport";

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "bg-error/20 text-error",
  HIGH: "bg-orange-500/20 text-orange-300",
  MEDIUM: "bg-amber-500/15 text-amber-300",
  LOW: "bg-surface-variant text-on-surface-variant",
};
const SEVERITY_FR: Record<string, string> = { CRITICAL: "Critique", HIGH: "Élevée", MEDIUM: "Moyenne", LOW: "Faible" };

/** Readable result of one step, above its raw output: which tests failed and why, which vulnerabilities block. */
export const CiStepReport: React.FC<{ stepName: string; state: string; lines: string[] }> = ({ stepName, state, lines }) => {
  const tests = useMemo(() => (state === "failure" ? failedTests(lines) : []), [lines, state]);
  const vulnix = useMemo(() => (stepName === "vulnix-scan" ? vulnixReport(lines) : null), [lines, stepName]);

  if (tests.length > 0) {
    return (
      <div className="border-b border-outline-variant/[0.12] px-3 py-3 space-y-2">
        <p className="text-sm font-bold text-error">
          {tests.length} test{tests.length > 1 ? "s" : ""} en échec
        </p>
        <ul className="space-y-2">
          {tests.slice(0, 20).map((t) => (
            <li key={`${t.file}|${t.name}`} className="rounded-lg border border-error/20 bg-error/5 px-3 py-2">
              <p className="text-sm text-on-surface">
                <span className="material-symbols-outlined align-middle text-base text-error" aria-hidden="true">close</span>{" "}
                {t.name}
              </p>
              {t.file && <p className="font-mono text-[11px] text-outline">{t.file}</p>}
              {t.reason && <p className="mt-1 text-xs text-on-surface-variant">Pourquoi : {t.reason}</p>}
            </li>
          ))}
        </ul>
        {tests.length > 20 && <p className="text-xs text-outline">… et {tests.length - 20} autre(s), voir le journal.</p>}
      </div>
    );
  }

  if (vulnix && (vulnix.blocking.length > 0 || vulnix.passed !== null)) {
    const summary = vulnixSummary(vulnix);
    const top = topPackages(vulnix);
    return (
      <div className="border-b border-outline-variant/[0.12] px-3 py-3 space-y-3">
        {summary && <p className={`text-sm font-bold ${vulnix.passed ? "text-tertiary" : "text-error"}`}>{summary}</p>}
        {top.length > 0 && (
          <p className="text-xs text-on-surface-variant">
            À mettre à jour en priorité : {top.map((t) => `${t.pkg} (${t.count})`).join(", ")}.
          </p>
        )}
        {vulnix.blocking.length > 0 && (
          <div className="max-h-56 overflow-auto rounded-lg border border-outline-variant/[0.15]">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-surface-container text-left text-outline">
                <tr><th className="px-2 py-1 font-semibold">Gravité</th><th className="px-2 py-1 font-semibold">Vulnérabilité</th><th className="px-2 py-1 font-semibold">Paquet</th></tr>
              </thead>
              <tbody>
                {vulnix.blocking.map((f, i) => (
                  <tr key={`${f.cve}-${f.pkg}-${i}`} className="border-t border-outline-variant/[0.08]">
                    <td className="px-2 py-1">
                      <span className={`rounded px-1.5 py-0.5 font-semibold ${SEVERITY_STYLE[f.severity] ?? SEVERITY_STYLE.LOW}`}>{SEVERITY_FR[f.severity] ?? f.severity}</span>
                      {f.kev && <span className="ml-1 rounded bg-error/30 px-1.5 py-0.5 font-bold text-error" title="Activement exploitée (catalogue CISA KEV)">KEV</span>}
                    </td>
                    <td className="px-2 py-1 font-mono text-on-surface">{f.cve}</td>
                    <td className="px-2 py-1 text-on-surface-variant">{f.pkg || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex flex-wrap items-center gap-3 text-xs text-outline">
          {vulnix.accepted > 0 && <span>{vulnix.accepted} acceptée(s) par une exception validée.</span>}
          {vulnix.reportUrl && /^(https?:\/\/|\/)/.test(vulnix.reportUrl) && (
            <a href={vulnix.reportUrl} target="_blank" rel="noopener noreferrer" className="font-semibold text-primary hover:underline">
              Ouvrir le rapport complet
            </a>
          )}
        </div>
      </div>
    );
  }
  return null;
};

/** Step output with its colours (instead of "[33m" codes) and failures marked, optionally errors only. */
export const CiLog = React.forwardRef<HTMLPreElement, { lines: string[]; empty: string }>(({ lines, empty }, ref) => {
  const [errorsOnly, setErrorsOnly] = useState(false);
  const errorCount = useMemo(() => lines.filter(isErrorLine).length, [lines]);
  const shown = errorsOnly ? lines.filter(isErrorLine) : lines;
  return (
    <>
      {lines.length > 0 && errorCount > 0 && (
        <div className="flex items-center justify-end gap-2 px-3 pt-2 text-[11px] text-outline">
          <label className="flex cursor-pointer items-center gap-1.5">
            <input type="checkbox" checked={errorsOnly} onChange={(e) => setErrorsOnly(e.target.checked)} />
            Seulement les lignes d'erreur ({errorCount})
          </label>
        </div>
      )}
      <pre ref={ref} className="max-h-[24rem] min-h-[10rem] overflow-auto p-3 font-mono text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap break-all">
        {lines.length === 0
          ? empty
          : shown.map((line, i) => (
            <div key={i} className={isErrorLine(line) ? "-mx-3 border-l-2 border-error bg-error/10 px-3" : undefined}>
              {stripAnsi(line) === "" ? " " : ansiSpans(line).map((s, j) => (
                <span key={j} className={s.className || undefined}>{s.text}</span>
              ))}
            </div>
          ))}
      </pre>
    </>
  );
});
CiLog.displayName = "CiLog";
