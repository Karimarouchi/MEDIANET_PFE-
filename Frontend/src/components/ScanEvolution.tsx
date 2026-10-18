import React, { useEffect, useState } from 'react';
import { getRepositoryHistory } from '../services/api';
import { HistoryRow, severe, summarize, formatChange, change, Change } from '../utils/evolution';

type Series = { label: string; color: string; values: number[]; dashed?: boolean };

/** Small multi-series line chart: one shared scale, exact values on the points. */
const LineChart: React.FC<{ rows: HistoryRow[]; series: Series[] }> = ({ rows, series }) => {
  const W = 720, H = 170, PAD = 36, LEFT = 64; // LEFT: room for the axis numbers, so they never touch a point label
  const max = Math.max(1, ...series.flatMap((s) => s.values));
  const x = (i: number) => (rows.length === 1 ? W / 2 : LEFT + (i / (rows.length - 1)) * (W - LEFT - PAD));
  const y = (v: number) => PAD + (1 - v / max) * (H - PAD * 2);
  // Label above the point, or below it when a series drawn before has its point within 16 px at the same scan.
  const labelY = (si: number, i: number) => {
    const py = y(series[si].values[i]);
    const crowded = series.slice(0, si).some((o) => Math.abs(y(o.values[i]) - py) < 16);
    return crowded ? py + 17 : py - 9;
  };
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H + 40}`} className="w-full min-w-[320px]" style={{ height: 230 }}>
        {[0, 0.25, 0.5, 0.75, 1].map((f) => (
          <g key={f}>
            <line x1={LEFT - 14} y1={PAD + f * (H - PAD * 2)} x2={W - PAD} y2={PAD + f * (H - PAD * 2)} stroke="#ffffff10" />
            <text x={LEFT - 20} y={PAD + f * (H - PAD * 2) + 4} textAnchor="end" fill="#64748b" fontSize="10">
              {Math.round(max * (1 - f))}
            </text>
          </g>
        ))}
        {series.map((s, si) => (
          <g key={s.label}>
            <polyline
              points={s.values.map((v, i) => `${x(i)},${y(v)}`).join(' ')}
              fill="none" stroke={s.color} strokeWidth="2.5" strokeLinejoin="round"
              strokeDasharray={s.dashed ? '5 4' : undefined}
            />
            {s.values.map((v, i) => (
              <g key={i}>
                <circle cx={x(i)} cy={y(v)} r="4.5" fill={s.color} stroke="#0f172a" strokeWidth="2" />
                <text x={x(i)} y={labelY(si, i)} textAnchor="middle" fill={s.color} fontSize="10.5" fontWeight="700">{v}</text>
              </g>
            ))}
          </g>
        ))}
        {rows.map((r, i) => (
          <g key={r.scanId}>
            <text x={x(i)} y={H + 18} textAnchor="middle" fill="#64748b" fontSize="9">
              {r.startedAt ? new Date(r.startedAt).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short' }) : '—'}
            </text>
            <text x={x(i)} y={H + 30} textAnchor="middle" fill="#475569" fontSize="9">#{r.scanId}</text>
          </g>
        ))}
      </svg>
      <div className="flex flex-wrap gap-4 px-2 text-[11px] text-on-surface-variant">
        {series.map((s) => (
          <span key={s.label} className="flex items-center gap-1.5">
            <span className="inline-block w-4 h-0.5" style={{ background: s.color, borderTop: s.dashed ? `2px dashed ${s.color}` : undefined }} />
            {s.label}
          </span>
        ))}
      </div>
    </div>
  );
};

const tone = (c: Change) => (c.trend === 'better' ? 'text-tertiary' : c.trend === 'worse' ? 'text-error' : 'text-primary');

const DeltaCell: React.FC<{ c: Change }> = ({ c }) => (
  <span className={`font-bold ${tone(c)}`}>
    {c.delta === 0 ? '±0' : `${c.delta > 0 ? '+' : '−'}${Math.abs(c.delta)}`}
    <span className="text-outline font-normal"> ({c.last})</span>
  </span>
);

const ScanEvolution: React.FC<{ repoId: number }> = ({ repoId }) => {
  const [rows, setRows] = useState<HistoryRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setRows(null);
    setError(null);
    getRepositoryHistory(repoId)
      .then((r) => setRows(r.data))
      .catch(() => setError("Impossible de charger l'historique de ce dépôt."));
  }, [repoId]);

  if (error) return <p className="text-sm text-error">{error}</p>;
  if (!rows) return <p className="text-sm text-outline">Chargement de l'historique…</p>;
  const sum = summarize(rows);
  if (!sum) {
    return (
      <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-12 text-center">
        <span className="material-symbols-outlined text-4xl text-outline mb-4 block">bar_chart</span>
        <p className="text-on-surface font-headline font-bold mb-1">Aucune donnée d'évolution</p>
        <p className="text-outline text-sm">Lancez plusieurs scans pour visualiser la tendance de sécurité dans le temps.</p>
      </div>
    );
  }
  const last = rows[rows.length - 1];

  const cards = [
    {
      icon: 'history', label: 'Scans terminés', value: String(sum.scans),
      sub: sum.repeats > 0 ? `dont ${sum.repeats} identique(s) au précédent (même code)` : `depuis le ${rows[0].startedAt ? new Date(rows[0].startedAt).toLocaleDateString('fr-FR') : '—'}`,
      color: 'text-primary',
    },
    { icon: 'bug_report', label: 'Vulnérabilités (dépendances)', value: String(last.vulnerabilities), sub: `${formatChange(sum.vulnerabilities)} depuis le 1er scan`, color: tone(sum.vulnerabilities) },
    { icon: 'priority_high', label: 'Critiques + élevées', value: String(severe(last)), sub: `${formatChange(sum.severe)} depuis le 1er scan`, color: tone(sum.severe) },
    { icon: 'key', label: 'Secrets à traiter', value: String(last.secrets.toHandle), sub: `${formatChange(sum.secretsToHandle)} · ${last.secrets.toCheck} à vérifier`, color: tone(sum.secretsToHandle) },
  ];

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {cards.map((m) => (
          <div key={m.label} className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className={`material-symbols-outlined text-base ${m.color}`}>{m.icon}</span>
              <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{m.label}</p>
            </div>
            <p className={`text-xl font-headline font-bold ${m.color}`}>{m.value}</p>
            <p className="text-[11px] text-outline mt-0.5">{m.sub}</p>
          </div>
        ))}
      </div>

      <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-5">
        <div className="flex items-center gap-2 mb-1">
          <span className="material-symbols-outlined text-primary text-lg">area_chart</span>
          <h3 className="font-headline font-bold text-on-surface">Vulnérabilités des dépendances</h3>
        </div>
        <p className="text-[11px] text-outline mb-3">
          Une vulnérabilité = un CVE sur un paquet, comptée une fois même si plusieurs outils la signalent.
          Les alertes de code (Semgrep) sont à part : {last.codeAlerts} au dernier scan.
        </p>
        <LineChart rows={rows} series={[
          { label: 'Toutes', color: '#a4e6ff', values: rows.map((r) => r.vulnerabilities) },
          { label: 'Critiques + élevées', color: '#ffb4ab', values: rows.map(severe) },
        ]} />
      </div>

      <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-5">
        <div className="flex items-center gap-2 mb-1">
          <span className="material-symbols-outlined text-amber-300 text-lg">key</span>
          <h3 className="font-headline font-bold text-on-surface">Secrets</h3>
        </div>
        <p className="text-[11px] text-outline mb-3">
          Mêmes groupes que l'onglet « Sécurité du code » : à traiter (probablement réels ou confirmés, hors tests),
          à vérifier (le modèle hésite), faux positifs (modèle ou analyste). Les valeurs de test et de documentation
          sont comptées à part : {last.secrets.testAndDocs} au dernier scan.
        </p>
        <LineChart rows={rows} series={[
          { label: 'À traiter', color: '#ffb4ab', values: rows.map((r) => r.secrets.toHandle) },
          { label: 'À vérifier', color: '#ffe066', values: rows.map((r) => r.secrets.toCheck) },
          { label: 'Faux positifs', color: '#64748b', values: rows.map((r) => r.secrets.falsePositives), dashed: true },
        ]} />
      </div>

      {rows.length >= 2 && (
        <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-5">
          <div className="flex items-center gap-2 mb-4">
            <span className="material-symbols-outlined text-secondary text-lg">compare_arrows</span>
            <h3 className="font-headline font-bold text-on-surface">Comparaison entre scans</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-[10px] uppercase tracking-widest text-outline">
                <tr>
                  <th className="text-left py-2 pr-3">Scans</th>
                  <th className="text-left py-2 pr-3">Date</th>
                  <th className="text-left py-2 pr-3">Vulnérabilités</th>
                  <th className="text-left py-2 pr-3">Critiques + élevées</th>
                  <th className="text-left py-2 pr-3">Alertes code</th>
                  <th className="text-left py-2">Secrets à traiter</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(1).map((r, i) => {
                  const p = rows[i];
                  return (
                    <tr key={r.scanId} className="border-t border-outline-variant/[0.1]">
                      <td className="py-2 pr-3 font-mono text-outline">#{p.scanId} → #{r.scanId}</td>
                      <td className="py-2 pr-3 text-outline">{r.startedAt ? new Date(r.startedAt).toLocaleString('fr-FR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—'}</td>
                      <td className="py-2 pr-3"><DeltaCell c={change(p.vulnerabilities, r.vulnerabilities)} /></td>
                      <td className="py-2 pr-3"><DeltaCell c={change(severe(p), severe(r))} /></td>
                      <td className="py-2 pr-3"><DeltaCell c={change(p.codeAlerts, r.codeAlerts)} /></td>
                      <td className="py-2"><DeltaCell c={change(p.secrets.toHandle, r.secrets.toHandle)} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanEvolution;
