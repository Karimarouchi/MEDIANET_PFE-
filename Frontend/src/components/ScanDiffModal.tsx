import React, { useEffect, useMemo, useState } from 'react';
import {
  getScansByRepo,
  compareScans,
  type ScanResultDto,
  type ScanDiffDto,
  type CveDto,
} from '../services/api';

interface ScanDiffModalProps {
  repoId: number;
  toScanId: number;
  repoLabel: string;
  onClose: () => void;
}

function severityBadgeClass(severity?: string) {
  const s = (severity || '').toUpperCase();
  if (s === 'CRITICAL') return 'bg-error/15 text-error border-error/30';
  if (s === 'HIGH') return 'bg-orange-400/15 text-orange-300 border-orange-400/30';
  if (s === 'MEDIUM') return 'bg-amber-300/15 text-amber-300 border-amber-300/30';
  return 'bg-surface-container-high text-outline border-outline-variant/20';
}

function CveRow({ cve }: { cve: CveDto }) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-xl border border-outline-variant/[0.1] bg-surface-container/40 px-3 py-2">
      <div className="min-w-0">
        <p className="text-xs font-semibold text-on-surface truncate">
          {cve.canonicalId || cve.cveId}
        </p>
        <p className="text-[10px] text-outline truncate">
          {cve.packageName}{cve.packageVersion ? `@${cve.packageVersion}` : ''}
        </p>
      </div>
      <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-mono font-bold border ${severityBadgeClass(cve.severity)}`}>
        {cve.severity}
      </span>
    </div>
  );
}

const ScanDiffModal: React.FC<ScanDiffModalProps> = ({ repoId, toScanId, repoLabel, onClose }) => {
  const [history, setHistory] = useState<ScanResultDto[]>([]);
  const [fromScanId, setFromScanId] = useState<number | null>(null);
  const [diff, setDiff] = useState<ScanDiffDto | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoadingHistory(true);
    getScansByRepo(repoId)
      .then(res => {
        if (!active) return;
        const candidates = res.data
          .filter(s => s.status === 'COMPLETED' && s.id !== toScanId)
          .sort((a, b) => b.id - a.id);
        setHistory(candidates);
        if (candidates.length > 0) setFromScanId(candidates[0].id);
      })
      .catch(() => setError("Impossible de charger l'historique des scans."))
      .finally(() => { if (active) setLoadingHistory(false); });
    return () => { active = false; };
  }, [repoId, toScanId]);

  useEffect(() => {
    if (!fromScanId) { setDiff(null); return; }
    let active = true;
    setLoadingDiff(true);
    setError(null);
    compareScans(fromScanId, toScanId)
      .then(res => { if (active) setDiff(res.data); })
      .catch(() => { if (active) setError('Impossible de comparer ces deux scans.'); })
      .finally(() => { if (active) setLoadingDiff(false); });
    return () => { active = false; };
  }, [fromScanId, toScanId]);

  const summary = useMemo(() => {
    if (!diff) return null;
    return {
      newCount: diff.newCves.length + diff.newSecrets.length,
      fixedCount: diff.fixedCves.length + diff.fixedSecrets.length,
      persistingCount: diff.persistingCves.length,
    };
  }, [diff]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" onClick={onClose}>
      <div
        className="glass-panel w-full max-w-4xl max-h-[85vh] overflow-y-auto rounded-3xl border border-outline-variant/[0.18] p-6 space-y-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="font-headline text-xl font-bold text-on-surface">Comparer des scans</h2>
            <p className="text-xs text-outline mt-1">{repoLabel} — scan actuel #{toScanId}</p>
          </div>
          <button onClick={onClose} className="w-8 h-8 rounded-lg bg-surface-container-high border border-outline-variant/[0.15] flex items-center justify-center text-outline hover:text-on-surface">
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>

        {loadingHistory ? (
          <div className="flex items-center justify-center py-12">
            <span className="material-symbols-outlined text-3xl text-primary animate-spin">progress_activity</span>
          </div>
        ) : history.length === 0 ? (
          <p className="text-sm text-outline py-8 text-center">
            Aucun scan précédent pour ce dépôt — rien à comparer.
          </p>
        ) : (
          <>
            <div className="flex items-center gap-3 flex-wrap">
              <span className="text-xs font-bold uppercase tracking-wider text-outline">Comparer avec</span>
              <select
                value={fromScanId ?? ''}
                onChange={(e) => setFromScanId(Number(e.target.value))}
                className="rounded-xl border border-outline-variant/[0.2] bg-surface-container px-3 py-2 text-sm text-on-surface"
              >
                {history.map(s => (
                  <option key={s.id} value={s.id}>
                    Scan #{s.id} — {new Date(s.finishedAt || s.startedAt).toLocaleString('fr-FR')}
                  </option>
                ))}
              </select>
            </div>

            {loadingDiff ? (
              <div className="flex items-center justify-center py-12">
                <span className="material-symbols-outlined text-3xl text-primary animate-spin">progress_activity</span>
              </div>
            ) : error ? (
              <p className="text-sm text-error py-6 text-center">{error}</p>
            ) : diff && summary ? (
              <>
                <div className="grid grid-cols-3 gap-3">
                  <div className="rounded-2xl border border-error/20 bg-error/5 p-3 text-center">
                    <p className="text-2xl font-headline font-bold text-error">{summary.newCount}</p>
                    <p className="text-[10px] uppercase tracking-widest text-outline mt-1">Nouvelles</p>
                  </div>
                  <div className="rounded-2xl border border-tertiary/20 bg-tertiary/5 p-3 text-center">
                    <p className="text-2xl font-headline font-bold text-tertiary">{summary.fixedCount}</p>
                    <p className="text-[10px] uppercase tracking-widest text-outline mt-1">Corrigées</p>
                  </div>
                  <div className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container/40 p-3 text-center">
                    <p className="text-2xl font-headline font-bold text-on-surface">{summary.persistingCount}</p>
                    <p className="text-[10px] uppercase tracking-widest text-outline mt-1">Persistantes</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-error">
                      Nouvelles CVE ({diff.newCves.length})
                    </h3>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                      {diff.newCves.length === 0 && <p className="text-[11px] text-outline">Aucune</p>}
                      {diff.newCves.map(c => <CveRow key={c.id} cve={c} />)}
                      {diff.newSecrets.map(s => (
                        <div key={`ns-${s.id}`} className="rounded-xl border border-error/20 bg-error/5 px-3 py-2">
                          <p className="text-xs font-semibold text-on-surface truncate">{s.ruleId}</p>
                          <p className="text-[10px] text-outline truncate">{s.file}:{s.startLine}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-tertiary">
                      Corrigées ({diff.fixedCves.length})
                    </h3>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                      {diff.fixedCves.length === 0 && <p className="text-[11px] text-outline">Aucune</p>}
                      {diff.fixedCves.map(c => <CveRow key={c.id} cve={c} />)}
                      {diff.fixedSecrets.map(s => (
                        <div key={`fs-${s.id}`} className="rounded-xl border border-tertiary/20 bg-tertiary/5 px-3 py-2">
                          <p className="text-xs font-semibold text-on-surface truncate">{s.ruleId}</p>
                          <p className="text-[10px] text-outline truncate">{s.file}:{s.startLine}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-outline">
                      Persistantes ({diff.persistingCves.length})
                    </h3>
                    <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                      {diff.persistingCves.length === 0 && <p className="text-[11px] text-outline">Aucune</p>}
                      {diff.persistingCves.map(c => <CveRow key={c.id} cve={c} />)}
                    </div>
                  </div>
                </div>
              </>
            ) : null}
          </>
        )}
      </div>
    </div>
  );
};

export default ScanDiffModal;
