import React from "react";
import type { CveDto } from "../services/api";
import { URGENCY_LABEL, remediationPlan } from "../utils/remediation";

/** What to do about one dependency vulnerability: steps with copy-ready commands, and what to do if that is not possible. */
const RemediationPlanView: React.FC<{ cve: CveDto; fixVersion?: string | null }> = ({ cve, fixVersion }) => {
  const plan = remediationPlan(cve, fixVersion);
  const u = URGENCY_LABEL[plan.urgency];
  return (
    <div className="space-y-3" data-testid="remediation-plan">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${u.cls}`}>{u.label}</span>
        <span className="text-[11px] text-outline">{plan.urgencyReason}</span>
      </div>
      <p className="text-sm font-semibold text-on-surface">{plan.title}</p>
      <ol className="space-y-2">
        {plan.steps.map((s, i) => (
          <li key={i} className="flex gap-2 text-sm text-on-surface-variant leading-relaxed">
            <span className="shrink-0 w-5 h-5 rounded-full bg-primary/15 text-primary text-[10px] font-bold flex items-center justify-center mt-0.5">
              {i + 1}
            </span>
            <div className="min-w-0">
              <p>{s.text}</p>
              {s.code && (
                <pre className="mt-1 rounded-lg bg-surface-container-lowest border border-outline-variant/[0.15] px-3 py-2 text-[11px] font-mono text-on-surface overflow-x-auto whitespace-pre-wrap break-all">
                  {s.code}
                </pre>
              )}
            </div>
          </li>
        ))}
      </ol>
      {plan.alternatives.length > 0 && (
        <div className="rounded-lg border border-outline-variant/[0.15] px-3 py-2">
          <p className="text-[10px] uppercase tracking-widest text-outline font-bold mb-1">Si ce n'est pas possible tout de suite</p>
          <ul className="list-disc pl-5 text-xs text-on-surface-variant space-y-0.5">
            {plan.alternatives.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default RemediationPlanView;
