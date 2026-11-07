import React, { useEffect, useState } from 'react';
import { getSslResult, type ScanResultDto } from '../services/api';
import { compareWithLabs, gradeColor, type LabsComparison } from '../utils/sslGrades';

const VERDICT: Record<LabsComparison['verdict'], { label: string; cls: string }> = {
  same: { label: 'Même note', cls: 'bg-tertiary/15 text-tertiary' },
  stricter: { label: 'Vulnix plus sévère', cls: 'bg-[#ffe066]/15 text-[#ffe066]' },
  lenient: { label: 'Vulnix plus clément', cls: 'bg-[#ffaa40]/15 text-[#ffaa40]' },
  no_labs: { label: 'Pas de note SSL Labs', cls: 'bg-surface-variant text-on-surface-variant' },
};

/** Latest finished scan of each domain (the list is newest first). */
export function latestPerDomain(history: ScanResultDto[]): ScanResultDto[] {
  const seen = new Set<string>();
  const out: ScanResultDto[] = [];
  for (const s of history) {
    if (s.status !== 'COMPLETED') continue;
    const d = (s.targetDomain || s.repoUrl.replace('ssl://', '')).toLowerCase();
    if (seen.has(d)) continue;
    seen.add(d);
    out.push(s);
  }
  return out;
}

/** Tab-separated table, to paste into the PFE report (Word / Excel). */
export function comparisonTsv(rows: LabsComparison[]): string {
  const head = ['Domaine', 'Note Vulnix', 'Score', 'Note SSL Labs', 'Écart', 'Explication'];
  const lines = rows.map((r) => [r.domain, r.vulnix, String(r.score), r.labs ?? '—', VERDICT[r.verdict].label, r.reason].join('\t'));
  return [head.join('\t'), ...lines].join('\n');
}

/**
 * Validation study: for each domain scanned, Vulnix's verdict next to SSL Labs' grade and why they differ. It is
 * the table to put in the report to show the grade is sound (same grade, or a difference that is explained).
 */
const SslLabsComparison: React.FC<{ history: ScanResultDto[]; onOpen: (scanId: number) => void }> = ({ history, onOpen }) => {
  const [rows, setRows] = useState<Array<LabsComparison & { scanId: number }> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const scans = latestPerDomain(history);
    (async () => {
      const out: Array<LabsComparison & { scanId: number }> = [];
      for (let i = 0; i < scans.length; i += 4) {
        const batch = await Promise.all(scans.slice(i, i + 4).map((s) =>
          getSslResult(s.id).then((r) => ({ ...compareWithLabs(r.data), scanId: s.id })).catch(() => null)));
        batch.forEach((b) => { if (b) out.push(b); });
      }
      if (!cancelled) setRows(out);
    })().catch(() => { if (!cancelled) setError('Impossible de charger les résultats.'); });
    return () => { cancelled = true; };
  }, [history]);

  if (error) return <p className="text-xs text-error">{error}</p>;
  if (!rows) return <p className="text-xs text-outline">Lecture des derniers scans de chaque domaine…</p>;

  const withLabs = rows.filter((r) => r.verdict !== 'no_labs');
  const same = withLabs.filter((r) => r.verdict === 'same').length;
  const oneStep = withLabs.filter((r) => r.gap != null && Math.abs(r.gap) === 1).length;

  return (
    <div className="glass-panel rounded-2xl border border-outline-variant/[0.1] p-5 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-headline font-bold text-sm text-on-surface">Comparaison avec SSL Labs</h3>
        <span className="text-xs text-outline">
          {rows.length} domaine(s) · {withLabs.length} avec une note SSL Labs · {same} même note · {oneStep} à un cran
        </span>
        <div className="flex-1" />
        <button type="button"
          onClick={() => navigator.clipboard?.writeText(comparisonTsv(rows)).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500); }).catch(() => undefined)}
          className="rounded-lg border border-outline-variant/30 px-3 py-1.5 text-xs font-semibold text-on-surface-variant hover:text-on-surface">
          {copied ? 'Copié' : 'Copier le tableau (Word / Excel)'}
        </button>
      </div>
      <p className="text-[11px] text-outline">
        Les deux notes portent sur la même chose : la configuration SSL/TLS (protocoles, certificat, failles, HSTS).
        La protection HTTP du navigateur est notée à part et n’entre pas dans la comparaison. La colonne « Explication » dit d’où vient un écart.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="text-left text-outline">
            <tr>
              <th className="py-1.5 pr-3 font-semibold">Domaine</th>
              <th className="py-1.5 pr-3 font-semibold">Vulnix</th>
              <th className="py-1.5 pr-3 font-semibold">SSL Labs</th>
              <th className="py-1.5 pr-3 font-semibold">Écart</th>
              <th className="py-1.5 font-semibold">Explication</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.scanId} className="border-t border-outline-variant/[0.08] align-top">
                <td className="py-1.5 pr-3">
                  <button type="button" onClick={() => onOpen(r.scanId)} className="font-semibold text-on-surface hover:text-primary hover:underline text-left">{r.domain}</button>
                </td>
                <td className="py-1.5 pr-3 font-headline font-extrabold" style={{ color: gradeColor(r.vulnix).ring }}>
                  {r.vulnix} <span className="font-sans font-normal text-outline">{r.score}/100</span>
                </td>
                <td className="py-1.5 pr-3 font-headline font-extrabold" style={{ color: r.labs ? gradeColor(r.labs).ring : undefined }}>{r.labs ?? '—'}</td>
                <td className="py-1.5 pr-3"><span className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${VERDICT[r.verdict].cls}`}>{VERDICT[r.verdict].label}</span></td>
                <td className="py-1.5 text-on-surface-variant">{r.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default SslLabsComparison;
