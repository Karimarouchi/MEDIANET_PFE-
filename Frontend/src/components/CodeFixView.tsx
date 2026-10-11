import React from "react";
import type { CveDto } from "../services/api";
import { codeFix } from "../utils/codeFix";

/** How to fix a code finding: the flaw in one sentence, the steps, a before/after example in the file's language. */
const CodeFixView: React.FC<{ cve: CveDto; fallback: string }> = ({ cve, fallback }) => {
  const fix = codeFix(cve);
  if (!fix) return <p>{fallback}</p>;
  return (
    <div className="space-y-3" data-testid="code-fix">
      <p className="text-sm font-semibold text-on-surface">{fix.title}</p>
      <p className="text-xs text-on-surface-variant">{fix.why}</p>
      {cve.filePath && (
        <p className="text-[11px] font-mono text-outline break-all">
          {cve.filePath}
          {cve.lineNumber ? `:${cve.lineNumber}` : ""}
        </p>
      )}
      <ol className="space-y-1.5">
        {fix.steps.map((s, i) => (
          <li key={i} className="flex gap-2 text-sm text-on-surface-variant leading-relaxed">
            <span className="shrink-0 w-5 h-5 rounded-full bg-primary/15 text-primary text-[10px] font-bold flex items-center justify-center mt-0.5">
              {i + 1}
            </span>
            <span>{s}</span>
          </li>
        ))}
      </ol>
      {fix.bad && fix.good && (
        <div className="grid gap-2">
          <div>
            <p className="text-[10px] uppercase tracking-widest text-error font-bold mb-1">À éviter</p>
            <pre className="rounded-lg bg-error/5 border border-error/20 px-3 py-2 text-[11px] font-mono text-on-surface overflow-x-auto whitespace-pre-wrap break-all">{fix.bad}</pre>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-widest text-tertiary font-bold mb-1">À écrire</p>
            <pre className="rounded-lg bg-tertiary/5 border border-tertiary/20 px-3 py-2 text-[11px] font-mono text-on-surface overflow-x-auto whitespace-pre-wrap break-all">{fix.good}</pre>
          </div>
        </div>
      )}
      <a href={fix.ref.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
        {fix.ref.label}
        <span className="material-symbols-outlined text-xs">open_in_new</span>
      </a>
    </div>
  );
};

export default CodeFixView;
