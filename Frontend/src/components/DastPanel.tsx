import React from "react";
import type { CveDto } from "../services/api";
import { configSeverityBadge, configSeverityLabel, toolLabel } from "../utils/configView";

type Props = { alerts: CveDto[] };

/**
 * Alerts raised on a running application by ZAP or Nuclei. They are findings on a URL, not vulnerabilities of a
 * package, so they have their own list: no package, no fixed version, no CVSS column.
 */
const DastPanel: React.FC<Props> = ({ alerts }) => (
  <div className="space-y-4 mb-8">
    <div className="flex flex-wrap items-center gap-2">
      <span className="material-symbols-outlined text-primary text-lg">travel_explore</span>
      <h2 className="font-headline font-bold text-on-surface text-base">Alertes applicatives (DAST)</h2>
      <span className="text-[11px] text-outline">
        Détectées sur l&apos;application en cours d&apos;exécution (ZAP, Nuclei), pas dans les dépendances.
      </span>
    </div>
    {alerts.length === 0 ? (
      <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-8 text-center">
        <span className="material-symbols-outlined text-3xl text-tertiary mb-3 block">task_alt</span>
        <p className="text-on-surface font-headline font-bold mb-1">Aucune alerte applicative</p>
        <p className="text-outline text-sm">
          Aucun scan dynamique n&apos;a signalé d&apos;alerte pour ce scan (ou aucune URL cible n&apos;a été fournie).
        </p>
      </div>
    ) : (
      <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] overflow-hidden">
        <table className="w-full table-fixed text-left">
          <thead>
            <tr className="border-b border-outline-variant/[0.1] text-[10px] uppercase tracking-widest text-slate-400 font-headline">
              <th className="w-[12%] px-4 py-3">Gravité</th>
              <th className="w-[33%] px-4 py-3">Alerte</th>
              <th className="w-[10%] px-4 py-3">CWE</th>
              <th className="w-[33%] px-4 py-3">URL</th>
              <th className="w-[12%] px-4 py-3">Outil</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map(a => (
              <tr key={a.id} className="border-b border-outline-variant/[0.07]" data-testid="dast-row">
                <td className="px-4 py-3">
                  <span className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-bold ${configSeverityBadge(a.severity)}`}>
                    {configSeverityLabel(a.severity)}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-on-surface">
                  <div className="font-headline">{a.packageName}</div>
                  <div className="text-[10px] text-outline font-mono">{a.cveId}</div>
                </td>
                <td className="px-4 py-3 text-xs text-on-surface-variant">{a.cweId ?? "—"}</td>
                <td className="px-4 py-3 text-xs font-mono text-on-surface-variant truncate max-w-0">
                  <span title={a.filePath ?? ""}>{a.filePath ?? "—"}</span>
                </td>
                <td className="px-4 py-3 text-xs text-on-surface-variant">
                  {(a.sources ?? a.source ?? "")
                    .split(",")
                    .filter(Boolean)
                    .map(s => toolLabel(s))
                    .join(", ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </div>
);

export default DastPanel;
