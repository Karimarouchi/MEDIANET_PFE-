import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getClients, getAllScans, type ClientDto, type ScanResultDto } from '../services/api';

const ProjectsPage: React.FC = () => {
  const navigate = useNavigate();
  const [clients, setClients] = useState<ClientDto[]>([]);
  const [scans, setScans] = useState<ScanResultDto[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getClients(), getAllScans()])
      .then(([c, s]) => { setClients(c.data); setScans(s.data); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  /* For each client, find the latest completed scan among its repos */
  const latestScanForClient = (client: ClientDto): ScanResultDto | null => {
    const relevant = scans
      .filter(s => (s.clientIds ?? []).includes(client.id) && s.status === 'COMPLETED')
      .sort((a, b) => b.id - a.id);
    return relevant[0] ?? null;
  };

  const totalCvesForClient = (client: ClientDto): number =>
    scans
      .filter(s => (s.clientIds ?? []).includes(client.id) && s.status === 'COMPLETED')
      .reduce((acc, s) => acc + (s.cveCount ?? 0), 0);

  const totalScansForClient = (client: ClientDto): number =>
    scans.filter(s => (s.clientIds ?? []).includes(client.id)).length;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <span className="material-symbols-outlined text-5xl text-primary animate-spin">progress_activity</span>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <header>
        <p className="text-xs uppercase tracking-[0.35em] text-outline mb-1">Vue d'ensemble</p>
        <h1 className="font-headline text-3xl font-bold text-on-surface tracking-tight">Projects</h1>
        <p className="text-sm text-on-surface-variant mt-1 max-w-2xl">
          {clients.length} projet(s) — chaque projet regroupe des dépôts et leurs scans associés.
        </p>
      </header>

      {/* Empty state */}
      {clients.length === 0 && (
        <div className="flex flex-col items-center justify-center py-24 text-outline-variant space-y-4">
          <span className="material-symbols-outlined text-6xl">folder_special</span>
          <p className="text-lg font-headline">Aucun projet</p>
          <p className="text-sm text-center max-w-xs">
            Créez des projets depuis le panneau Admin pour regrouper vos dépôts par client.
          </p>
          <button
            onClick={() => navigate('/admin/projects')}
            className="mt-2 flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary/10 border border-primary/30 text-primary text-sm font-semibold hover:bg-primary/20 transition-all"
          >
            <span className="material-symbols-outlined text-base">admin_panel_settings</span>
            Gérer les projets (Admin)
          </button>
        </div>
      )}

      {/* Projects grid */}
      {clients.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {clients.map(client => {
            const latest = latestScanForClient(client);
            const totalCves = totalCvesForClient(client);
            const totalScans = totalScansForClient(client);

            return (
              <div
                key={client.id}
                onClick={() => navigate(`/projects/${client.id}`)}
                className="glass-panel rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-5 cursor-pointer hover:border-primary/40 hover:bg-primary/5 hover:shadow-[0_0_20px_rgba(0,209,255,0.08)] transition-all group"
              >
                {/* Header */}
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0">
                      <span className="material-symbols-outlined text-primary text-lg">folder_special</span>
                    </div>
                    <div>
                      <h2 className="font-headline font-bold text-on-surface group-hover:text-primary transition-colors">
                        {client.name}
                      </h2>
                      {client.company && (
                        <p className="text-[11px] text-outline">{client.company}</p>
                      )}
                    </div>
                  </div>
                  <span className="material-symbols-outlined text-outline group-hover:text-primary transition-colors text-base">
                    arrow_forward
                  </span>
                </div>

                {/* Stats row */}
                <div className="grid grid-cols-3 gap-3 mb-4">
                  <div className="rounded-xl bg-surface-container-high px-3 py-2 text-center">
                    <p className="text-lg font-bold font-headline text-on-surface">
                      {client.repositoryIds?.length ?? 0}
                    </p>
                    <p className="text-[9px] uppercase tracking-widest text-outline mt-0.5">Repos</p>
                  </div>
                  <div className="rounded-xl bg-surface-container-high px-3 py-2 text-center">
                    <p className="text-lg font-bold font-headline text-on-surface">{totalScans}</p>
                    <p className="text-[9px] uppercase tracking-widest text-outline mt-0.5">Scans</p>
                  </div>
                  <div className={`rounded-xl px-3 py-2 text-center ${totalCves > 0 ? 'bg-error/10' : 'bg-tertiary/10'}`}>
                    <p className={`text-lg font-bold font-headline ${totalCves > 0 ? 'text-error' : 'text-tertiary'}`}>
                      {totalCves}
                    </p>
                    <p className="text-[9px] uppercase tracking-widest text-outline mt-0.5">CVEs</p>
                  </div>
                </div>

                {/* Latest scan */}
                {latest ? (
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-container-lowest/60 border border-outline-variant/[0.1]">
                    <span className="material-symbols-outlined text-tertiary text-[13px]">check_circle</span>
                    <span className="text-[10px] text-outline flex-1 truncate">
                      Dernier scan :&nbsp;
                      <span className="text-on-surface-variant font-medium">
                        {latest.repoUrl?.split('/').pop() ?? latest.repoUrl}
                      </span>
                    </span>
                    <span className="text-[10px] text-outline shrink-0">
                      {latest.finishedAt
                        ? new Date(latest.finishedAt).toLocaleDateString('fr-FR')
                        : '—'}
                    </span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-container-lowest/60 border border-outline-variant/[0.1]">
                    <span className="material-symbols-outlined text-outline text-[13px]">schedule</span>
                    <span className="text-[10px] text-outline italic">Aucun scan effectué</span>
                  </div>
                )}

                {/* Collaborators */}
                {client.employeeLogins?.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1">
                    {client.employeeLogins.slice(0, 3).map(login => (
                      <span key={login} className="px-2 py-0.5 rounded-full bg-secondary/10 text-secondary text-[10px] font-medium">
                        {login}
                      </span>
                    ))}
                    {client.employeeLogins.length > 3 && (
                      <span className="px-2 py-0.5 rounded-full bg-surface-container-high text-outline text-[10px]">
                        +{client.employeeLogins.length - 3}
                      </span>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default ProjectsPage;
