import React, { useEffect, useState } from 'react';
import { getScanWorkers, type ScanWorkerStatus } from '../services/api';

const CATEGORY_META: Record<string, { label: string; icon: string; color: string }> = {
  ssl: { label: 'SSL', icon: 'verified_user', color: 'text-primary' },
  code: { label: 'Code / CVE', icon: 'bug_report', color: 'text-secondary' },
  image: { label: 'Image Docker', icon: 'deployed_code', color: 'text-tertiary' },
};

const WorkersPanel: React.FC = () => {
  const [workers, setWorkers] = useState<ScanWorkerStatus[]>([]);

  useEffect(() => {
    let active = true;
    const load = () => {
      getScanWorkers()
        .then(res => { if (active) setWorkers(res.data); })
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 4000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  if (workers.length === 0) return null;

  return (
    <section>
      <h2 className="text-sm font-bold font-headline text-outline uppercase tracking-widest mb-4 flex items-center gap-2">
        <span className="material-symbols-outlined text-lg">hub</span>
        Workers de scan ({workers.filter(w => w.busy).length}/{workers.length} occupés)
      </h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {workers.map((w) => {
          const meta = CATEGORY_META[w.category] ?? CATEGORY_META.code;
          return (
            <div
              key={w.workerId}
              className={`glass-panel rounded-2xl border p-4 flex items-center gap-3 ${
                w.busy ? 'border-primary/30' : 'border-outline-variant/[0.1]'
              }`}
            >
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                w.busy ? 'bg-primary/10' : 'bg-surface-container-highest'
              }`}>
                <span className={`material-symbols-outlined ${w.busy ? meta.color : 'text-outline'} ${w.busy ? 'animate-pulse' : ''}`}>
                  {meta.icon}
                </span>
              </div>
              <div className="min-w-0">
                <p className="text-xs font-bold font-headline text-on-surface">{w.workerId}</p>
                <p className="text-[10px] text-outline">{meta.label}</p>
                <p className={`text-[10px] font-semibold ${w.busy ? 'text-primary' : 'text-outline'}`}>
                  {w.busy ? `Scan #${w.currentScanId}` : 'Libre'}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
};

export default WorkersPanel;
