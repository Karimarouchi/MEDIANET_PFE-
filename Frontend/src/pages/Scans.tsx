import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAllScans, stopScan, deleteScan, startScan, type ScanResultDto } from '../services/api';

function statusConfig(status: string) {
  switch (status) {
    case 'COMPLETED':
      return { color: 'text-tertiary', bg: 'bg-tertiary/10', border: 'border-tertiary/20', icon: 'check_circle', label: 'Completed', pulse: false };
    case 'RUNNING':
      return { color: 'text-primary', bg: 'bg-primary/10', border: 'border-primary/20', icon: 'progress_activity', label: 'In Progress', pulse: true };
    case 'FAILED':
      return { color: 'text-error', bg: 'bg-error/10', border: 'border-error/20', icon: 'error', label: 'Failed', pulse: false };
    default:
      return { color: 'text-outline', bg: 'bg-surface-container', border: 'border-outline-variant/20', icon: 'schedule', label: 'Pending', pulse: false };
  }
}

function repoName(url: string) {
  if (!url) return 'Unknown';
  const parts = url.replace(/\.git$/, '').split('/');
  return parts[parts.length - 1] || url;
}

function repoOrg(url: string) {
  if (!url) return '';
  const parts = url.replace(/\.git$/, '').split('/');
  return parts.length >= 2 ? parts[parts.length - 2] : '';
}

function timeAgo(dateStr: string) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

const Scans: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanResultDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [rescanning, setRescanning] = useState<number | null>(null);
  const [clientFilter, setClientFilter] = useState('ALL');

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const res = await getAllScans();
        setScans(res.data);
      } catch (err) {
        console.error('Failed to fetch scans', err);
      } finally {
        setLoading(false);
      }
    };
    fetchScans();
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleCardClick = (scan: ScanResultDto) => {
    if (scan.scanMode === 'ssl-only') {
      navigate(`/ssl-analysis?scanId=${scan.id}`);
    } else {
      navigate(`/vulnerabilities?scanId=${scan.id}&repoId=${scan.repoId}`);
    }
  };

  const handleStop = async (e: React.MouseEvent, scanId: number) => {
    e.stopPropagation();
    try { await stopScan(scanId); } catch (err) { console.error('Failed to stop scan', err); }
  };

  const handleDelete = async (e: React.MouseEvent, scanId: number) => {
    e.stopPropagation();
    try { await deleteScan(scanId); setScans(prev => prev.filter(s => s.id !== scanId)); } catch (err) { console.error('Failed to delete scan', err); }
  };

  const handleRescan = async (e: React.MouseEvent, scan: ScanResultDto) => {
    e.stopPropagation();
    setRescanning(scan.id);
    try {
      const { data } = await startScan({
        repoUrl: scan.repoUrl,
        branch: scan.branch || undefined,
        scanMode: scan.scanMode || undefined,
        targetDomain: scan.targetDomain || undefined,
      });
      if (scan.scanMode === 'ssl-only') {
        navigate(`/ssl-analysis?scanId=${data.scanId}`);
      } else {
        navigate(`/vulnerabilities?scanId=${data.scanId}&repoId=${data.repoId}`);
      }
    } catch (err) {
      console.error('Failed to rescan', err);
    } finally {
      setRescanning(null);
    }
  };

  const clientOptions = Array.from(new Set(scans.flatMap((scan) => scan.clientNames ?? []))).sort();
  const visibleScans = scans.filter((scan) =>
    scan.scanMode !== 'ssl-only' && (clientFilter === 'ALL' || (scan.clientNames ?? []).includes(clientFilter))
  );

  const running   = visibleScans.filter(s => s.status === 'RUNNING');
  const failed    = visibleScans.filter(s => s.status === 'FAILED');

  // Keep only the latest scan per repository (deduplicate by repoId)
  const completedAll = visibleScans.filter(s => s.status === 'COMPLETED');
  const latestByRepo = new Map<number | string, ScanResultDto>();
  completedAll.forEach(scan => {
    const key = scan.repoId ?? scan.repoUrl ?? scan.id;
    const existing = latestByRepo.get(key);
    if (!existing || scan.id > existing.id) {
      latestByRepo.set(key, scan);
    }
  });
  const completed = Array.from(latestByRepo.values()).sort((a, b) => b.id - a.id);

  return (
    <div className="space-y-8">
      {/* Header */}
      <header>
        <h1 className="text-3xl font-bold font-headline text-on-surface tracking-tight mb-2">Scan Operations</h1>
        <p className="text-on-surface-variant text-sm max-w-2xl">
          {loading ? 'Loading scan history...' : `${completed.length + failed.length + running.length} scans — ${running.length} actifs, ${completed.length} complétés, ${failed.length} échoués`}
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <span className="text-[11px] uppercase tracking-[0.2em] text-outline">Filtre client</span>
          <select value={clientFilter} onChange={(e) => setClientFilter(e.target.value)} className="rounded-xl border border-outline-variant/[0.2] bg-surface-container px-3 py-2 text-sm text-on-surface">
            <option value="ALL">Tous les clients</option>
            {clientOptions.map((clientName) => (
              <option key={clientName} value={clientName}>{clientName}</option>
            ))}
          </select>
        </div>
      </header>

      {/* Stats Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="glass-panel rounded-xl border border-outline-variant/[0.1] p-4 text-center">
          <p className="text-2xl font-bold font-headline text-on-surface">{running.length + completed.length + failed.length}</p>
          <p className="text-[10px] uppercase tracking-widest text-outline mt-1">Total Scans</p>
        </div>
        <div className="glass-panel rounded-xl border border-primary/[0.15] p-4 text-center">
          <p className="text-2xl font-bold font-headline text-primary">{running.length}</p>
          <p className="text-[10px] uppercase tracking-widest text-outline mt-1">Running</p>
        </div>
        <div className="glass-panel rounded-xl border border-tertiary/[0.15] p-4 text-center">
          <p className="text-2xl font-bold font-headline text-tertiary">{completed.length}</p>
          <p className="text-[10px] uppercase tracking-widest text-outline mt-1">Completed</p>
        </div>
        <div className="glass-panel rounded-xl border border-error/[0.15] p-4 text-center">
          <p className="text-2xl font-bold font-headline text-error">{failed.length}</p>
          <p className="text-[10px] uppercase tracking-widest text-outline mt-1">Failed</p>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="flex items-center justify-center py-24">
          <span className="material-symbols-outlined text-5xl text-primary animate-spin">progress_activity</span>
        </div>
      )}

      {/* Empty State */}
      {!loading && running.length === 0 && completed.length === 0 && failed.length === 0 && (
        <div className="flex flex-col items-center justify-center py-24 text-outline-variant space-y-4">
          <span className="material-symbols-outlined text-6xl">radar</span>
          <p className="text-lg font-headline">No scans yet</p>
          <p className="text-sm">Go to <button onClick={() => navigate('/repositories')} className="text-primary hover:underline">Repositories</button> to start your first scan.</p>
        </div>
      )}

      {/* Running Scans Section */}
      {running.length > 0 && (
        <section>
          <h2 className="text-sm font-bold font-headline text-primary uppercase tracking-widest mb-4 flex items-center gap-2">
            <span className="material-symbols-outlined text-lg animate-spin">progress_activity</span>
            Active Scans
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {running.map(scan => {
              const st = statusConfig(scan.status);
              return (
                <div
                  key={scan.id}
                  onClick={() => handleCardClick(scan)}
                  className="glass-panel rounded-2xl border border-primary/[0.2] p-5 cursor-pointer hover:border-primary/50 hover:shadow-[0_0_30px_rgba(0,209,255,0.1)] transition-all group relative overflow-hidden"
                >
                  <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-primary via-secondary to-primary animate-pulse"></div>
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                        <span className="material-symbols-outlined text-primary">
                          {scan.scanMode === 'ssl-only' ? 'verified_user' : 'code_blocks'}
                        </span>
                      </div>
                      <div>
                        <h3 className="font-bold font-headline text-on-surface group-hover:text-primary transition-colors">
                          {scan.scanMode === 'ssl-only'
                            ? (scan.targetDomain || repoName(scan.repoUrl ?? ''))
                            : repoName(scan.repoUrl ?? '')}
                        </h3>
                        <p className="text-[10px] text-outline flex items-center gap-1">
                          {scan.scanMode === 'ssl-only'
                            ? <><span className="material-symbols-outlined text-[10px] text-secondary">lock</span> SSL Analysis</>
                            : repoOrg(scan.repoUrl ?? '')}
                        </p>
                        {scan.clientNames?.length ? (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {scan.clientNames.map((clientName) => (
                              <span key={`${scan.id}-${clientName}`} className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">{clientName}</span>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    </div>
                    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold ${st.bg} ${st.color} border ${st.border}`}>
                      <span className={`material-symbols-outlined text-xs ${st.pulse ? 'animate-spin' : ''}`}>{st.icon}</span>
                      {st.label}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 text-xs text-outline">
                      <span className="flex items-center gap-1"><span className="material-symbols-outlined text-sm">schedule</span>{timeAgo(scan.startedAt)}</span>
                      <span className="flex items-center gap-1"><span className="material-symbols-outlined text-sm">tag</span>#{scan.id}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={(e) => handleStop(e, scan.id)} title="Stop scan"
                        className="w-8 h-8 rounded-lg bg-error/10 border border-error/20 flex items-center justify-center hover:bg-error/20 transition-colors">
                        <span className="material-symbols-outlined text-error text-sm">stop_circle</span>
                      </button>
                      <button onClick={(e) => handleDelete(e, scan.id)} title="Delete scan"
                        className="w-8 h-8 rounded-lg bg-surface-container-highest border border-outline-variant/20 flex items-center justify-center hover:bg-error/10 hover:border-error/20 transition-colors">
                        <span className="material-symbols-outlined text-outline hover:text-error text-sm">delete</span>
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* Completed Scans Section */}
      {completed.length > 0 && (
        <section>
          <h2 className="text-sm font-bold font-headline text-tertiary uppercase tracking-widest mb-4 flex items-center gap-2">
            <span className="material-symbols-outlined text-lg">check_circle</span>
            Completed Scans
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {completed.map(scan => {
              const st = statusConfig(scan.status);
              return (
                <div
                  key={scan.id}
                  onClick={() => handleCardClick(scan)}
                  className="glass-panel rounded-2xl border border-outline-variant/[0.1] p-5 cursor-pointer hover:border-tertiary/40 hover:shadow-[0_0_20px_rgba(0,252,146,0.06)] transition-all group"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-tertiary/10 flex items-center justify-center">
                        <span className="material-symbols-outlined text-tertiary">
                          {scan.scanMode === 'ssl-only' ? 'verified_user' : 'code_blocks'}
                        </span>
                      </div>
                      <div>
                        <h3 className="font-bold font-headline text-on-surface group-hover:text-tertiary transition-colors">
                          {scan.scanMode === 'ssl-only'
                            ? (scan.targetDomain || repoName(scan.repoUrl ?? ''))
                            : repoName(scan.repoUrl ?? '')}
                        </h3>
                        <p className="text-[10px] text-outline flex items-center gap-1">
                          {scan.scanMode === 'ssl-only'
                            ? <><span className="material-symbols-outlined text-[10px] text-secondary">lock</span> SSL Analysis</>
                            : repoOrg(scan.repoUrl ?? '')}
                        </p>
                        {scan.clientNames?.length ? (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {scan.clientNames.map((clientName) => (
                              <span key={`${scan.id}-${clientName}`} className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">{clientName}</span>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    </div>
                    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold ${st.bg} ${st.color} border ${st.border}`}>
                      <span className="material-symbols-outlined text-xs">{st.icon}</span>
                      {st.label}
                    </span>
                  </div>
                    <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 text-xs text-outline">
                      <span className="flex items-center gap-1"><span className="material-symbols-outlined text-sm">schedule</span>{timeAgo(scan.finishedAt || scan.startedAt)}</span>
                      <span className="flex items-center gap-1"><span className="material-symbols-outlined text-sm">tag</span>#{scan.id}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-3 text-xs">
                        <span className="flex items-center gap-1 text-error font-bold"><span className="material-symbols-outlined text-sm">bug_report</span>{scan.cveCount}</span>
                        <span className="flex items-center gap-1 text-secondary font-bold"><span className="material-symbols-outlined text-sm">key</span>{scan.secretCount}</span>
                      </div>
                      <button onClick={(e) => handleRescan(e, scan)} title="Refaire le scan" disabled={rescanning === scan.id}
                        className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center hover:bg-primary/20 transition-colors disabled:opacity-40">
                        <span className={`material-symbols-outlined text-primary text-sm ${rescanning === scan.id ? 'animate-spin' : ''}`}>
                          {rescanning === scan.id ? 'progress_activity' : 'replay'}
                        </span>
                      </button>
                      <button onClick={(e) => handleDelete(e, scan.id)} title="Delete scan"
                        className="w-8 h-8 rounded-lg bg-surface-container-highest border border-outline-variant/20 flex items-center justify-center hover:bg-error/10 hover:border-error/20 transition-colors">
                        <span className="material-symbols-outlined text-outline hover:text-error text-sm">delete</span>
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* Failed Scans Section */}
      {failed.length > 0 && (
        <section>
          <h2 className="text-sm font-bold font-headline text-error uppercase tracking-widest mb-4 flex items-center gap-2">
            <span className="material-symbols-outlined text-lg">error</span>
            Failed Scans
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {failed.map(scan => {
              const st = statusConfig(scan.status);
              return (
                <div
                  key={scan.id}
                  onClick={() => handleCardClick(scan)}
                  className="glass-panel rounded-2xl border border-error/[0.1] p-5 cursor-pointer hover:border-error/30 transition-all group"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-error/10 flex items-center justify-center">
                        <span className="material-symbols-outlined text-error">
                          {scan.scanMode === 'ssl-only' ? 'verified_user' : 'code_blocks'}
                        </span>
                      </div>
                      <div>
                        <h3 className="font-bold font-headline text-on-surface group-hover:text-error transition-colors">
                          {scan.scanMode === 'ssl-only'
                            ? (scan.targetDomain || repoName(scan.repoUrl ?? ''))
                            : repoName(scan.repoUrl ?? '')}
                        </h3>
                        <p className="text-[10px] text-outline flex items-center gap-1">
                          {scan.scanMode === 'ssl-only'
                            ? <><span className="material-symbols-outlined text-[10px] text-secondary">lock</span> SSL Analysis</>
                            : repoOrg(scan.repoUrl ?? '')}
                        </p>
                        {scan.clientNames?.length ? (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {scan.clientNames.map((clientName) => (
                              <span key={`${scan.id}-${clientName}`} className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">{clientName}</span>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    </div>
                    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold ${st.bg} ${st.color} border ${st.border}`}>
                      <span className="material-symbols-outlined text-xs">{st.icon}</span>
                      {st.label}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 text-xs text-outline">
                      <span className="flex items-center gap-1"><span className="material-symbols-outlined text-sm">schedule</span>{timeAgo(scan.startedAt)}</span>
                      <span className="flex items-center gap-1"><span className="material-symbols-outlined text-sm">tag</span>#{scan.id}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={(e) => handleRescan(e, scan)} title="Refaire le scan" disabled={rescanning === scan.id}
                        className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center hover:bg-primary/20 transition-colors disabled:opacity-40">
                        <span className={`material-symbols-outlined text-primary text-sm ${rescanning === scan.id ? 'animate-spin' : ''}`}>
                          {rescanning === scan.id ? 'progress_activity' : 'replay'}
                        </span>
                      </button>
                      <button onClick={(e) => handleDelete(e, scan.id)} title="Delete scan"
                        className="w-8 h-8 rounded-lg bg-surface-container-highest border border-outline-variant/20 flex items-center justify-center hover:bg-error/10 hover:border-error/20 transition-colors">
                        <span className="material-symbols-outlined text-outline hover:text-error text-sm">delete</span>
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
};

export default Scans;
