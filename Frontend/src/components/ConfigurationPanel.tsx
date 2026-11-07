import React, { useState } from "react";
import type { ConfigFindingDto } from "../services/api";
import {
  configSeverityBadge,
  configSeverityLabel,
  countConfigBySeverity,
  groupConfigByCategory,
  splitConfigFindings,
  toolLabel,
} from "../utils/configView";

type Props = {
  findings: ConfigFindingDto[];
  loading: boolean;
};

const Row: React.FC<{ f: ConfigFindingDto }> = ({ f }) => {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr
        className={`border-b border-outline-variant/[0.07] cursor-pointer transition-all hover:bg-primary/5 ${open ? "bg-primary/[0.04]" : ""}`}
        onClick={() => setOpen(o => !o)}
        data-testid="config-row"
      >
        <td className="px-4 py-3 whitespace-nowrap">
          <span className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-bold ${configSeverityBadge(f.severity)}`}>
            {configSeverityLabel(f.severity)}
          </span>
        </td>
        <td className="px-4 py-3 text-sm text-on-surface">
          <div className="font-headline">{f.title}</div>
          <div className="text-[10px] text-outline font-mono">{f.ruleIds.join(" · ")}</div>
        </td>
        <td className="px-4 py-3 text-xs text-on-surface-variant font-mono truncate max-w-0">
          <span title={f.file ?? ""}>{f.file ?? "—"}</span>
        </td>
        <td className="px-4 py-3 text-xs text-center text-outline">{f.startLine ?? "—"}</td>
        <td className="px-4 py-3 whitespace-nowrap">
          {f.sources.map(s => (
            <span key={s} className="mr-1 px-1.5 py-0.5 rounded-md text-[9px] font-bold bg-primary/15 text-primary">
              {toolLabel(s)}
            </span>
          ))}
        </td>
      </tr>
      {open && (
        <tr className="border-b border-outline-variant/[0.07] bg-primary/[0.03]">
          <td colSpan={5} className="px-6 py-4 text-sm text-on-surface-variant space-y-2">
            {f.description && <p>{f.description}</p>}
            {f.resolution && (
              <p>
                <span className="font-bold text-on-surface">Correction : </span>
                {f.resolution}
              </p>
            )}
            {f.resource && <p className="text-xs font-mono">Ressource : {f.resource}</p>}
            {f.referenceUrl && (
              <a className="text-xs text-primary underline" href={f.referenceUrl} target="_blank" rel="noreferrer">
                Documentation de la règle
              </a>
            )}
          </td>
        </tr>
      )}
    </>
  );
};

const Table: React.FC<{ items: ConfigFindingDto[] }> = ({ items }) => (
  <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] overflow-hidden">
    <table className="w-full table-fixed text-left">
      <thead>
        <tr className="border-b border-outline-variant/[0.1] text-[10px] uppercase tracking-widest text-slate-400 font-headline">
          <th className="w-[12%] px-4 py-3">Gravité</th>
          <th className="w-[38%] px-4 py-3">Défaut</th>
          <th className="w-[28%] px-4 py-3">Fichier</th>
          <th className="w-[7%] px-4 py-3 text-center">Ligne</th>
          <th className="w-[15%] px-4 py-3">Outils</th>
        </tr>
      </thead>
      <tbody>
        {items.map(f => (
          <Row key={f.id} f={f} />
        ))}
      </tbody>
    </table>
  </div>
);

const ConfigurationPanel: React.FC<Props> = ({ findings, loading }) => {
  const [showLow, setShowLow] = useState(false);
  const { main, low } = splitConfigFindings(findings);
  const counts = countConfigBySeverity(main);

  return (
    <div className="space-y-4 mb-8">
      <div className="flex flex-wrap items-center gap-2">
        <span className="material-symbols-outlined text-primary text-lg">tune</span>
        <h2 className="font-headline font-bold text-on-surface text-base">Défauts de configuration</h2>
        <span className="text-[11px] text-outline">
          Dockerfile, Kubernetes, Terraform : informatif, ces défauts ne bloquent pas le pipeline.
        </span>
      </div>
      <p className="text-[11px] text-outline">
        Ce ne sont pas des CVE : il n&apos;y a ni paquet vulnérable ni score CVSS. « Non évaluée » signifie que l&apos;outil
        (Checkov) ne donne pas de gravité ; Vulnix n&apos;en invente pas.
      </p>

      {loading ? (
        <div className="flex items-center gap-3 text-outline py-8 justify-center">
          <span className="material-symbols-outlined animate-spin">progress_activity</span> Chargement…
        </div>
      ) : findings.length === 0 ? (
        <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-8 text-center">
          <span className="material-symbols-outlined text-3xl text-tertiary mb-3 block">task_alt</span>
          <p className="text-on-surface font-headline font-bold mb-1">Aucun défaut de configuration</p>
          <p className="text-outline text-sm">Trivy, Checkov et Hadolint n&apos;ont rien signalé dans ce dépôt.</p>
        </div>
      ) : (
        <>
          <div className="flex flex-wrap gap-2" data-testid="config-counts">
            {Object.entries(counts).map(([sev, n]) => (
              <span key={sev} className={`px-2.5 py-1 rounded-full text-[11px] font-bold ${configSeverityBadge(sev)}`}>
                {n} {configSeverityLabel(sev).toLowerCase()}
              </span>
            ))}
          </div>
          {groupConfigByCategory(main).map(g => (
            <div key={g.category} className="space-y-2">
              <h3 className="text-[11px] uppercase tracking-widest text-outline font-bold">
                {g.label} <span className="text-on-surface-variant">({g.items.length})</span>
              </h3>
              <Table items={g.items} />
            </div>
          ))}
          {low.length > 0 && (
            <div className="space-y-2">
              <button
                onClick={() => setShowLow(v => !v)}
                className="text-xs text-primary hover:underline"
                data-testid="config-low-toggle"
              >
                {showLow ? "Masquer" : "Afficher"} {low.length} suggestion{low.length > 1 ? "s" : ""} de niveau info
                (style, bonnes pratiques)
              </button>
              {showLow && <Table items={low} />}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default ConfigurationPanel;
