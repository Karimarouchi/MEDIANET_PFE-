import React from "react";
import type { PipelineStep } from "../services/api";
import { ciDuration, ciStatus, ciStepLabel, type StepOutcome } from "../utils/ci";

const NODE_W = 248;
const NODE_H = 74;
const GAP_Y = 14;
const COL_GAP = 56;

type Node = { key: string; x: number; y: number; step?: PipelineStep; result?: boolean; deploy?: boolean };

/** CD card after the result: what happened on the server for this pipeline. */
export type DeployNode = { tone: "ok" | "warn" | "bad" | "info" | "running"; title: string; text: string };

/**
 * Pipeline drawn like GitHub Actions: clone → the steps that run in parallel → the result. Vulnix writes every step
 * with depends_on: [] so they all start after the clone; a step that does not start shows why on its card.
 */
const PipelineGraph: React.FC<{
  steps: PipelineStep[];
  status: string;
  outcomes: Record<number, StepOutcome | null>;
  selected: number | null;
  blockedStepId: number | null;
  onSelect: (stepId: number) => void;
  deploy?: DeployNode | null;
}> = ({ steps, status, outcomes, selected, blockedStepId, onSelect, deploy }) => {
  const clone = steps.find((s) => s.name === "clone");
  const parallel = steps.filter((s) => s !== clone);
  const rows = Math.max(1, parallel.length);
  const height = rows * NODE_H + (rows - 1) * GAP_Y;
  const midY = (height - NODE_H) / 2;

  const nodes: Node[] = [];
  let col = 0;
  if (clone) nodes.push({ key: `s${clone.id}`, x: 0, y: midY, step: clone });
  if (clone) col++;
  parallel.forEach((s, i) => nodes.push({ key: `s${s.id}`, x: col * (NODE_W + COL_GAP), y: i * (NODE_H + GAP_Y), step: s }));
  if (parallel.length) col++;
  nodes.push({ key: "result", x: col * (NODE_W + COL_GAP), y: midY, result: true });
  if (deploy) {
    col++;
    nodes.push({ key: "deploy", x: col * (NODE_W + COL_GAP), y: midY, deploy: true });
  }
  const width = (col + 1) * NODE_W + col * COL_GAP;

  const edge = (x1: number, y1: number, x2: number, y2: number, k: string, lit: boolean) => {
    const mx = (x1 + x2) / 2;
    return (
      <path key={k} d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`} fill="none"
        stroke={lit ? "#64748b" : "#334155"} strokeWidth="1.6" />
    );
  };
  const edges: React.ReactNode[] = [];
  const cloneNode = nodes.find((n) => n.step === clone);
  const resultNode = nodes.find((n) => n.result)!;
  const deployNode = nodes.find((n) => n.deploy);
  if (deployNode) edges.push(edge(resultNode.x + NODE_W, resultNode.y + NODE_H / 2, deployNode.x, deployNode.y + NODE_H / 2, "rd", true));
  const parallelNodes = nodes.filter((n) => n.step && n.step !== clone);
  for (const n of parallelNodes) {
    if (cloneNode) edges.push(edge(cloneNode.x + NODE_W, cloneNode.y + NODE_H / 2, n.x, n.y + NODE_H / 2, `c${n.key}`, true));
    edges.push(edge(n.x + NODE_W, n.y + NODE_H / 2, resultNode.x, resultNode.y + NODE_H / 2, `r${n.key}`, n.step!.state !== "pending"));
  }
  if (cloneNode && parallelNodes.length === 0) {
    edges.push(edge(cloneNode.x + NODE_W, cloneNode.y + NODE_H / 2, resultNode.x, resultNode.y + NODE_H / 2, "cr", true));
  }

  const result = ciStatus(status);
  return (
    <div className="overflow-x-auto rounded-2xl border border-outline-variant/[0.15] bg-[#0b1020] p-5">
      <div className="relative" style={{ width, height }}>
        <svg className="absolute inset-0" width={width} height={height}>{edges}</svg>
        {nodes.map((n) => {
          if (n.deploy && deploy) {
            const tone = deploy.tone;
            return (
              <div key={n.key} className={`absolute flex items-center gap-3 rounded-xl border px-3 ${
                tone === "ok" ? "border-tertiary/50 bg-tertiary/10" : tone === "bad" ? "border-error/50 bg-error/10"
                  : tone === "warn" ? "border-amber-500/50 bg-amber-500/10" : tone === "running" ? "border-primary/50 bg-primary/10" : "border-outline-variant/30 bg-surface-container"
              }`} style={{ left: n.x, top: n.y, width: NODE_W, height: NODE_H }} title={deploy.text}>
                <span className={`material-symbols-outlined text-2xl ${tone === "running" ? "animate-spin" : ""} ${
                  tone === "ok" ? "text-tertiary" : tone === "bad" ? "text-error" : tone === "warn" ? "text-amber-300" : tone === "running" ? "text-primary" : "text-outline"
                }`}>{tone === "running" ? "progress_activity" : tone === "ok" ? "rocket_launch" : tone === "warn" ? "undo" : tone === "bad" ? "error" : "cloud_off"}</span>
                <span className="min-w-0">
                  <span className="block truncate text-xs font-bold text-on-surface">{deploy.title}</span>
                  <span className="block truncate text-[11px] text-on-surface-variant">{deploy.text}</span>
                </span>
              </div>
            );
          }
          if (n.result) {
            return (
              <div key={n.key} className={`absolute flex items-center gap-3 rounded-xl border px-3 ${
                status === "success" ? "border-tertiary/50 bg-tertiary/10" : status === "failure" || status === "error" ? "border-error/50 bg-error/10" : "border-outline-variant/30 bg-surface-container"
              }`} style={{ left: n.x, top: n.y, width: NODE_W, height: NODE_H }}>
                <span className={`material-symbols-outlined text-2xl ${result.spin ? "animate-spin" : ""} ${
                  status === "success" ? "text-tertiary" : status === "failure" || status === "error" ? "text-error" : "text-outline"
                }`}>{status === "success" ? "verified" : result.icon}</span>
                <span>
                  <span className="block text-xs font-bold text-on-surface">{status === "planned" ? "Résultat" : "Résultat du pipeline"}</span>
                  <span className="block text-[11px] text-on-surface-variant">{result.label}</span>
                </span>
              </div>
            );
          }
          const s = n.step!;
          const st = ciStatus(s.state);
          const label = ciStepLabel(s.name);
          const outcome = outcomes[s.id];
          const isSel = s.id === selected;
          const blocked = s.id === blockedStepId;
          return (
            <button key={n.key} type="button" onClick={() => onSelect(s.id)}
              title={outcome?.text || label.detail}
              className={`absolute rounded-xl border px-3 py-2 text-left transition-all ${
                isSel ? "border-primary/70 bg-primary/10 shadow-[0_0_0_1px_rgba(164,230,255,0.25)]"
                  : blocked ? "border-error/60 bg-error/10" : "border-outline-variant/30 bg-surface-container hover:border-primary/40"
              }`}
              style={{ left: n.x, top: n.y, width: NODE_W, height: NODE_H }}>
              <span className="flex items-center gap-2">
                <span className={`material-symbols-outlined text-[18px] ${st.spin ? "animate-spin" : ""} ${
                  s.state === "success" ? "text-tertiary" : s.state === "failure" || s.state === "error" ? "text-error" : s.state === "running" ? "text-primary" : "text-outline"
                }`}>{st.icon}</span>
                <span className="min-w-0 flex-1 truncate text-xs font-bold text-on-surface">{label.title}</span>
                <span className="shrink-0 text-[10px] text-outline">{ciDuration(s.started, s.finished).replace("en cours · ", "")}</span>
              </span>
              <span className={`mt-1 block truncate text-[11px] ${
                outcome?.tone === "bad" ? "text-error" : outcome?.tone === "ok" ? "text-tertiary" : outcome?.tone === "warn" ? "text-amber-300" : "text-on-surface-variant"
              }`}>
                {outcome ? outcome.text : s.state === "running" ? "En cours…" : s.state === "pending" ? "En attente" : label.detail}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

export default PipelineGraph;
