import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getGithubRepos, getGitlabProjects, getRepositories, startScan, type GitRepoDto, type RepositoryDto } from '../services/api';
import { useAuth } from '../context/AuthContext';

const scanTypes = [
  { value: 'auto', label: 'Auto (recommended)', icon: 'auto_awesome' },
  { value: 'full', label: 'Full Scan', icon: 'radar' },
  { value: 'nodejs', label: 'Node.js', icon: 'code' },
  { value: 'python', label: 'Python', icon: 'code' },
  { value: 'php', label: 'PHP', icon: 'code' },
  { value: 'java', label: 'Java', icon: 'code' },
  { value: 'go', label: 'Go', icon: 'code' },
  { value: 'rust', label: 'Rust', icon: 'code' },
  { value: 'dast', label: 'DAST (ZAP)', icon: 'travel_explore' },
  { value: 'docker-image', label: 'Docker Image', icon: 'deployed_code' },
];

interface LogLine {
  time: string;
  prefix: string;
  text: string;
}

function parseLogLine(raw: string): LogLine {
  const now = new Date();
  const time = now.toTimeString().slice(0, 8);
  const prefixes = ['[SYSTEM]', '[SUCCESS]', '[SCAN]', '[WARN]', '[ERROR]', '[INFO]'];
  for (const p of prefixes) {
    if (raw.includes(p)) {
      return { time, prefix: p, text: raw.replace(p, '').trim() };
    }
  }
  return { time, prefix: '', text: raw };
}

function prefixColor(prefix: string): string {
  switch (prefix) {
    case '[SYSTEM]': return 'text-outline';
    case '[SUCCESS]': return 'text-tertiary';
    case '[SCAN]': return 'text-primary';
    case '[WARN]': return 'text-[#FFBD2E]';
    case '[ERROR]': return 'text-error';
    case '[INFO]': return 'text-secondary';
    default: return 'text-on-surface-variant';
  }
}

const Repositories: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('');
  const [targetDomain, setTargetDomain] = useState('');
  const [dastTargetUrl, setDastTargetUrl] = useState('');
  const [dockerImageRef, setDockerImageRef] = useState('');
  const [containerPort, setContainerPort] = useState('3000');
  const [scanType, setScanType] = useState('auto');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  /** Idée 3 — OS cible pour Grype (e.g. "ubuntu:22.04") */
  const [targetOs, setTargetOs] = useState('');
  /** Idée 2 — Profil de conformité OpenSCAP */
  const [complianceProfile, setComplianceProfile] = useState('');
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Linked Git providers state
  const [gitRepos, setGitRepos] = useState<GitRepoDto[]>([]);
  const [scannedRepositories, setScannedRepositories] = useState<RepositoryDto[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [reposError, setReposError] = useState('');
  const [repoSearch, setRepoSearch] = useState('');
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
  const scanFormRef = useRef<HTMLDivElement>(null);

  // Dedicated views: GitHub repositories, GitLab repositories, or direct URL scan
  const [scanSource, setScanSource] = useState<'github' | 'gitlab' | 'url'>('github');

  // Refs to allow cancelling an in-progress scan
  const evtSourceRef = useRef<EventSource | null>(null);
  const navTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const selectedScan = scanTypes.find(s => s.value === scanType) || scanTypes[0];

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Fetch linked GitHub + GitLab repos on mount
  useEffect(() => {
    let active = true;
    const loadRepos = async () => {
      setReposLoading(true);
      setReposError('');
      const [githubResult, gitlabResult, scannedResult] = await Promise.allSettled([
        getGithubRepos(),
        getGitlabProjects(),
        getRepositories(),
      ]);

      if (!active) return;

      const merged: GitRepoDto[] = [];
      if (githubResult.status === 'fulfilled') {
        merged.push(...githubResult.value.data);
      }
      if (gitlabResult.status === 'fulfilled') {
        merged.push(...gitlabResult.value.data);
      }

      if (!merged.length && githubResult.status === 'rejected' && gitlabResult.status === 'rejected') {
        setReposError('Impossible de charger les dépôts liés.');
      }

      setGitRepos(merged);
      setScanSource((current) => {
        if (current === 'url') {
          return current;
        }
        if (githubResult.status === 'fulfilled' && githubResult.value.data.length > 0) {
          return 'github';
        }
        if (gitlabResult.status === 'fulfilled' && gitlabResult.value.data.length > 0) {
          return 'gitlab';
        }
        if (user?.hasGithubLinked) {
          return 'github';
        }
        if (user?.hasGitlabLinked) {
          return 'gitlab';
        }
        return 'url';
      });
      if (scannedResult.status === 'fulfilled') {
        setScannedRepositories(scannedResult.value.data);
      }
      setReposLoading(false);
    };

    loadRepos();
    return () => { active = false; };
  }, [user?.hasGithubLinked, user?.hasGitlabLinked]);

  const handleStopScan = () => {
    if (evtSourceRef.current) { evtSourceRef.current.close(); evtSourceRef.current = null; }
    if (navTimeoutRef.current) { clearTimeout(navTimeoutRef.current); navTimeoutRef.current = null; }
    setScanning(false);
    setLogs([]);
    setRepoUrl('');
    setSelectedRepo(null);
  };

  const handleSelectRepo = (repo: GitRepoDto) => {
    setRepoUrl(repo.htmlUrl);
    setSelectedRepo(repo.fullName);
    setTimeout(() => scanFormRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 100);
  };

  const handleQuickScan = async (repo: GitRepoDto) => {
    setRepoUrl(repo.htmlUrl);
    setSelectedRepo(repo.fullName);
    setScanning(true);
    setLogs([]);

    try {
      const { data } = await startScan({
        repoUrl: repo.htmlUrl,
        scanMode: 'auto',
      });

      const { scanId, repoId } = data;
      const token = localStorage.getItem('vulnix_token') ?? '';
      const evtSource = new EventSource(`http://localhost:8080/api/scans/${scanId}/logs?token=${encodeURIComponent(token)}`);
      evtSourceRef.current = evtSource;

      evtSource.onmessage = (event) => {
        const raw = event.data;
        if (raw === '%%SCAN_COMPLETE%%') {
          evtSource.close();
          evtSourceRef.current = null;
          setScanning(false);
          navTimeoutRef.current = setTimeout(() => {
            navigate(`/vulnerabilities?repoId=${repoId}&scanId=${scanId}`);
          }, 2000);
          return;
        }
        setLogs(prev => [...prev, parseLogLine(raw)]);
      };

      evtSource.onerror = () => {
        evtSource.close();
        evtSourceRef.current = null;
        setScanning(false);
      };
    } catch (err) {
      setLogs(prev => [...prev, parseLogLine('[ERROR] Failed to start scan.')]);
      setScanning(false);
    }

    setTimeout(() => scanFormRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 300);
  };

  const langColor: Record<string, string> = {
    TypeScript: '#3178c6', JavaScript: '#f1e05a', Python: '#3572A5',
    Java: '#b07219', Go: '#00ADD8', Rust: '#dea584', PHP: '#4F5D95',
    'C#': '#178600', C: '#555555', 'C++': '#f34b7d', Ruby: '#701516',
    Swift: '#F05138', Kotlin: '#A97BFF', Shell: '#89e051',
  };

  const filteredRepos = gitRepos.filter(r =>
    r.name.toLowerCase().includes(repoSearch.toLowerCase()) ||
    (r.description || '').toLowerCase().includes(repoSearch.toLowerCase())
  );

  const githubFilteredRepos = filteredRepos.filter(r => r.provider === 'GITHUB');
  const gitlabFilteredRepos = filteredRepos.filter(r => r.provider === 'GITLAB');
  const hasGithubLinked = Boolean(user?.hasGithubLinked);
  const hasGitlabLinked = Boolean(user?.hasGitlabLinked);
  const isGitlabView = scanSource === 'gitlab';
  const activeRepoTitle = isGitlabView ? 'Dépôts GitLab' : 'Dépôts GitHub';
  const activeRepoCount = isGitlabView ? gitlabFilteredRepos.length : githubFilteredRepos.length;
  const activeRepos = isGitlabView ? gitlabFilteredRepos : githubFilteredRepos;
  const activeEmptyMessage = isGitlabView
    ? (hasGitlabLinked ? 'Aucun dépôt GitLab trouvé.' : 'Connecte ton compte GitLab pour afficher ses dépôts.')
    : (hasGithubLinked ? 'Aucun dépôt GitHub trouvé.' : 'Connecte ton compte GitHub pour afficher ses dépôts.');

  const isRepoPrivate = (repo: GitRepoDto) => Boolean(repo.private ?? repo.isPrivate);
  const canScanRepo = (repo: GitRepoDto) => repo.provider === 'GITLAB' || !isRepoPrivate(repo);
  const findAssignedRepo = (repo: GitRepoDto) => scannedRepositories.find((entry) => entry.repoUrl === repo.htmlUrl);
  const selectedRepoEntry = selectedRepo ? gitRepos.find((repo) => repo.fullName === selectedRepo) : undefined;
  const selectedAssignedRepo = selectedRepoEntry ? findAssignedRepo(selectedRepoEntry) : undefined;
  const selectedRepoMatchesView = selectedRepoEntry
    ? selectedRepoEntry.provider === (isGitlabView ? 'GITLAB' : 'GITHUB')
    : false;

  const switchScanSource = (nextSource: 'github' | 'gitlab' | 'url') => {
    setScanSource(nextSource);
    setSelectedRepo(null);
    setRepoUrl('');
    if (nextSource === 'url') {
      setTimeout(() => scanFormRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
    }
  };

  useEffect(() => {
    if (scanSource === 'github' && !hasGithubLinked) {
      setScanSource(hasGitlabLinked ? 'gitlab' : 'url');
      return;
    }
    if (scanSource === 'gitlab' && !hasGitlabLinked) {
      setScanSource(hasGithubLinked ? 'github' : 'url');
    }
  }, [scanSource, hasGithubLinked, hasGitlabLinked]);

  const tabButtonClass = (tab: 'github' | 'gitlab' | 'url') => {
    const base = 'flex items-center justify-center gap-2 rounded-2xl px-5 py-3 text-sm font-headline font-semibold border transition-all duration-200';
    if (scanSource !== tab) {
      return `${base} border-transparent text-outline hover:text-on-surface-variant hover:bg-surface-container/60`;
    }
    if (tab === 'github') {
      return `${base} border-sky-400/30 bg-sky-400/10 text-sky-300 shadow-[0_0_18px_rgba(56,189,248,0.12)]`;
    }
    if (tab === 'gitlab') {
      return `${base} border-orange-400/30 bg-orange-400/10 text-orange-300 shadow-[0_0_18px_rgba(251,146,60,0.12)]`;
    }
    return `${base} border-primary/30 bg-primary/10 text-primary shadow-[0_0_18px_rgba(0,209,255,0.12)]`;
  };

  const handleStartScan = async () => {
    const isDast = scanType === 'dast';
    const isDockerImage = scanType === 'docker-image';
    if (isDast && !dastTargetUrl.trim()) return;
    if (isDockerImage && !dockerImageRef.trim()) return;
    if (!isDast && !isDockerImage && !repoUrl.trim()) return;
    setScanning(true);
    setLogs([]);

    try {
      const { data } = await startScan({
        repoUrl: isDast ? dastTargetUrl.trim() : isDockerImage ? dockerImageRef.trim() : repoUrl.trim(),
        scanMode: scanType,
        branch: branch.trim() || undefined,
        targetDomain: targetDomain.trim() || undefined,
        dastTargetUrl: isDast ? dastTargetUrl.trim() : undefined,
        dockerImage: isDockerImage ? dockerImageRef.trim() : undefined,
        containerPort: isDockerImage ? parseInt(containerPort, 10) || 3000 : undefined,
        // Idée 3 — OS cible
        targetOs: targetOs.trim() || undefined,
        // Idée 2 — Profil conformité
        complianceProfile: complianceProfile || undefined,
      });

      const { scanId, repoId } = data;

      // Connect to SSE for logs
      const token = localStorage.getItem('vulnix_token') ?? '';
      const evtSource = new EventSource(`http://localhost:8080/api/scans/${scanId}/logs?token=${encodeURIComponent(token)}`);
      evtSourceRef.current = evtSource;

      evtSource.onmessage = (event) => {
        const raw = event.data;

        if (raw === '%%SCAN_COMPLETE%%') {
          evtSource.close();
          evtSourceRef.current = null;
          setScanning(false);
          navTimeoutRef.current = setTimeout(() => {
            navigate(`/vulnerabilities?repoId=${repoId}&scanId=${scanId}`);
          }, 2000);
          return;
        }

        setLogs(prev => [...prev, parseLogLine(raw)]);
      };

      evtSource.onerror = () => {
        evtSource.close();
        evtSourceRef.current = null;
        setScanning(false);
      };

    } catch (err) {
      setLogs(prev => [...prev, parseLogLine('[ERROR] Failed to start scan. Is the backend running?')]);
      setScanning(false);
    }
  };

  const renderRepoCard = (repo: GitRepoDto) => {
    const assignedRepo = findAssignedRepo(repo);
    return (
      <div
        key={repo.fullName}
        onClick={() => handleSelectRepo(repo)}
        className={`text-left p-4 rounded-xl border transition-all duration-200 hover:border-primary/50 hover:bg-primary/5 group ${
          selectedRepo === repo.fullName
            ? 'border-primary bg-primary/10 shadow-[0_0_12px_rgba(0,209,255,0.15)]'
            : 'border-outline-variant/[0.15] bg-surface-container'
        }`}
      >
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex items-center gap-2 min-w-0">
            <span className="material-symbols-outlined text-sm text-outline flex-shrink-0">
              {isRepoPrivate(repo) ? 'lock' : 'folder_open'}
            </span>
            <span className="font-headline font-semibold text-sm text-on-surface truncate group-hover:text-primary transition-colors">
              {repo.name}
            </span>
          </div>
          {selectedRepo === repo.fullName && (
            <span className="material-symbols-outlined text-primary text-sm flex-shrink-0">check_circle</span>
          )}
        </div>
        {repo.description && (
          <p className="text-xs text-outline-variant mb-2 line-clamp-1">{repo.description}</p>
        )}
        {assignedRepo?.clientNames?.length ? (
          <div className="mb-3 flex flex-wrap gap-1.5">
            {assignedRepo.clientNames.map((clientName) => (
              <span key={`${repo.fullName}-${clientName}`} className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">
                {clientName}
              </span>
            ))}
          </div>
        ) : null}
        <div className="flex items-center gap-3 text-xs text-outline">
          {repo.language && (
            <span className="flex items-center gap-1">
              <span
                className="w-2 h-2 rounded-full flex-shrink-0"
                style={{ backgroundColor: langColor[repo.language] || '#8b949e' }}
              ></span>
              {repo.language}
            </span>
          )}
          {repo.stars > 0 && (
            <span className="flex items-center gap-1">
              <span className="material-symbols-outlined text-xs">star</span>
              {repo.stars}
            </span>
          )}
          <span className={`ml-auto px-1.5 py-0.5 rounded text-[10px] font-medium ${isRepoPrivate(repo) ? 'bg-error/10 text-error' : 'bg-tertiary/10 text-tertiary'}`}>
            {isRepoPrivate(repo) ? 'Privé' : 'Public'}
          </span>
        </div>
        <div className="mt-3 flex gap-2">
          <button
            onClick={(e) => { e.stopPropagation(); handleQuickScan(repo); }}
            disabled={(scanning && selectedRepo === repo.fullName) || !canScanRepo(repo)}
            title={!canScanRepo(repo) ? 'Les dépôts privés GitHub ne peuvent pas être scannés ici' : undefined}
            className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-semibold transition-all duration-200 border disabled:cursor-not-allowed ${
              !canScanRepo(repo)
                ? 'bg-surface-container border-outline-variant/[0.1] text-outline opacity-50'
                : 'bg-primary/10 text-primary hover:bg-primary hover:text-on-primary hover:shadow-[0_0_16px_rgba(0,209,255,0.3)] disabled:opacity-50 border-primary/20 hover:border-primary'
            }`}
          >
            <span className="material-symbols-outlined text-sm">
              {!canScanRepo(repo) ? 'lock' : scanning && selectedRepo === repo.fullName ? 'progress_activity' : 'radar'}
            </span>
            {!canScanRepo(repo) ? 'Privé' : scanning && selectedRepo === repo.fullName ? 'Scan...' : 'Scanner'}
          </button>
          <a
            href={repo.htmlUrl}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            title={`Voir sur ${repo.provider === 'GITLAB' ? 'GitLab' : 'GitHub'}`}
            className="flex items-center justify-center px-3 py-2 rounded-lg text-xs border border-outline-variant/[0.2] text-outline hover:text-on-surface hover:border-outline-variant/50 transition-all duration-200"
          >
            <span className="material-symbols-outlined text-sm">open_in_new</span>
          </a>
        </div>
      </div>
    );
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-[calc(100vh-12rem)] relative overflow-hidden">
      {/* Ambient Background Glows */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/5 blur-[120px] rounded-full pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-secondary/5 blur-[120px] rounded-full pointer-events-none"></div>

      {/* ── Source Toggle ───────────────────────────────────────────────── */}
      {user && (
        <div className="z-10 mb-8">
          <div className={`grid gap-2 rounded-3xl border border-outline-variant/[0.15] bg-surface-container-low p-2 glass-panel shadow-lg ${hasGithubLinked && hasGitlabLinked ? 'sm:grid-cols-3' : 'sm:grid-cols-2'}`}>
            {hasGithubLinked && (
              <button
                onClick={() => switchScanSource('github')}
                className={tabButtonClass('github')}
              >
                <svg className="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
                </svg>
                Dépôts GitHub
              </button>
            )}

            {hasGitlabLinked && (
              <button
                onClick={() => switchScanSource('gitlab')}
                className={tabButtonClass('gitlab')}
              >
                <svg className="w-4 h-4 flex-shrink-0" viewBox="0 0 380 380" fill="currentColor">
                  <path d="M282.83 170.73l-.27-.69-26.14-68.22a6.81 6.81 0 0 0-2.69-3.24 7 7 0 0 0-8 .43 7 7 0 0 0-2.32 3.52l-17.65 54H154.29l-17.65-54a6.86 6.86 0 0 0-2.32-3.52 7 7 0 0 0-8-.43 6.85 6.85 0 0 0-2.69 3.24L97.44 170l-.26.69a48.54 48.54 0 0 0 16.1 56.1l.09.07.24.17 39.82 29.82 19.7 14.91 12 9.06a8.07 8.07 0 0 0 9.76 0l12-9.06 19.7-14.91 40.06-30 .1-.08a48.56 48.56 0 0 0 16.08-56.04z"/>
                </svg>
                Dépôts GitLab
              </button>
            )}

            <button
              onClick={() => switchScanSource('url')}
              className={tabButtonClass('url')}
            >
              <span className="material-symbols-outlined text-base">link</span>
              Lien direct
            </button>
          </div>
        </div>
      )}

      {/* ── Linked Repositories Panel ────────────────────────────────────── */}
      {user && scanSource !== 'url' && ((scanSource === 'github' && hasGithubLinked) || (scanSource === 'gitlab' && hasGitlabLinked)) && (
        <div className="w-full max-w-5xl mb-12 z-10">
          <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 bg-surface-container-highest/40 border-b border-outline-variant/[0.1]">
              <div className="flex items-center gap-3">
                {isGitlabView ? (
                  <svg className="w-5 h-5 text-orange-400" viewBox="0 0 380 380" fill="currentColor">
                    <path d="M282.83 170.73l-.27-.69-26.14-68.22a6.81 6.81 0 0 0-2.69-3.24 7 7 0 0 0-8 .43 7 7 0 0 0-2.32 3.52l-17.65 54H154.29l-17.65-54a6.86 6.86 0 0 0-2.32-3.52 7 7 0 0 0-8-.43 6.85 6.85 0 0 0-2.69 3.24L97.44 170l-.26.69a48.54 48.54 0 0 0 16.1 56.1l.09.07.24.17 39.82 29.82 19.7 14.91 12 9.06a8.07 8.07 0 0 0 9.76 0l12-9.06 19.7-14.91 40.06-30 .1-.08a48.56 48.56 0 0 0 16.08-56.04z"/>
                  </svg>
                ) : (
                  <svg className="w-5 h-5 text-sky-300" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
                  </svg>
                )}
                <span className="font-headline font-bold text-on-surface">{activeRepoTitle}</span>
                <span className="text-xs text-outline bg-surface-container px-2 py-0.5 rounded-full">
                  {activeRepoCount} dépôts
                </span>
              </div>
              <div className="relative">
                <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-sm">search</span>
                <input
                  className="bg-surface-container border border-outline-variant/[0.2] rounded-full pl-8 pr-4 py-1.5 text-sm text-on-surface placeholder:text-outline focus:ring-1 focus:ring-primary focus:border-primary/50 transition-all w-52"
                  placeholder="Rechercher..."
                  value={repoSearch}
                  onChange={e => setRepoSearch(e.target.value)}
                />
              </div>
            </div>

            {/* Repos Grid */}
            <div className="p-4 space-y-5">
              {reposLoading && (
                <div className="flex items-center justify-center py-8 gap-3 text-outline">
                  <span className="material-symbols-outlined animate-spin">progress_activity</span>
                  <span className="text-sm">Chargement des dépôts...</span>
                </div>
              )}
              {reposError && (
                <div className="flex items-center justify-center py-8 gap-2 text-error text-sm">
                  <span className="material-symbols-outlined text-sm">error</span>
                  {reposError}
                </div>
              )}
              {!reposLoading && !reposError && activeRepos.length === 0 && (
                <div className="flex items-center justify-center py-8 text-outline text-sm">
                  {activeEmptyMessage}
                </div>
              )}
              {!reposLoading && !reposError && activeRepos.length > 0 && (
                <section className={`rounded-2xl border p-4 ${
                  isGitlabView ? 'border-orange-400/15 bg-orange-400/[0.03]' : 'border-sky-400/15 bg-sky-400/[0.03]'
                }`}>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {activeRepos.map(renderRepoCard)}
                  </div>
                </section>
              )}
            </div>

            {/* Selected repo info bar */}
            {selectedRepo && selectedRepoMatchesView && (
              <div className="px-6 py-3 bg-primary/5 border-t border-primary/20 flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm text-primary">
                  <span className="material-symbols-outlined text-sm">{scanning ? 'progress_activity' : 'check_circle'}</span>
                  <div className="flex flex-col gap-1">
                    <span className="font-headline font-medium">{selectedRepo}</span>
                    {selectedAssignedRepo?.clientNames?.length ? (
                      <div className="flex flex-wrap gap-1.5">
                        {selectedAssignedRepo.clientNames.map((clientName) => (
                          <span key={`selected-${clientName}`} className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">
                            {clientName}
                          </span>
                        ))}
                      </div>
                    ) : null}
                  </div>
                  <span className="text-outline text-xs">{scanning ? '— scan en cours...' : '— sélectionné'}</span>
                </div>
                <button
                  onClick={() => { setSelectedRepo(null); setRepoUrl(''); }}
                  className="text-outline hover:text-error transition-colors"
                >
                  <span className="material-symbols-outlined text-sm">close</span>
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Centered Scan Interface — shown when in URL mode or not logged in */}
      {(!user || scanSource === 'url') && (
      <div ref={scanFormRef} className="w-full max-w-4xl flex flex-col items-center space-y-12 z-10">
        {/* Scan Progress Indicator */}
        <div className="relative flex items-center justify-center h-64 w-64">
          <div className={`absolute w-full h-full rounded-full ${scanning ? 'scan-ring-outer' : 'border-2 border-primary/20'}`}></div>
          <div className={`absolute w-4/5 h-4/5 rounded-full ${scanning ? 'scan-ring-inner' : 'border-2 border-dashed border-secondary/20'}`}></div>
          <div className="absolute w-3/5 h-3/5 rounded-full bg-surface-container flex flex-col items-center justify-center border border-primary/[0.2] shadow-[0_0_40px_rgba(0,209,255,0.1)]">
            <span className="material-symbols-outlined text-4xl text-primary mb-2" style={{ fontVariationSettings: "'FILL' 1" }}>
              {scanning ? 'radar' : 'shield_with_heart'}
            </span>
            <span className="text-[10px] uppercase tracking-[0.2em] text-outline font-bold">
              {scanning ? 'Scanning...' : 'Observer Mode'}
            </span>
          </div>
          <div className="absolute -top-4 right-4 w-2 h-2 rounded-full bg-tertiary shadow-[0_0_10px_#00FF94] animate-pulse"></div>
          <div className="absolute -bottom-2 left-10 w-1.5 h-1.5 rounded-full bg-secondary shadow-[0_0_10px_#7000FF] animate-pulse"></div>
        </div>

        {/* Input Area */}
        <div className="w-full text-center space-y-8">
          <div className="space-y-3">
            <h1 className="text-4xl md:text-5xl font-bold font-headline tracking-tighter text-on-surface">Initiate Protocol Scan</h1>
            <p className="text-outline-variant max-w-lg mx-auto">
              {scanType === 'dast'
                ? 'Entrez l\'URL de l\'application en cours d\'exécution pour lancer le scan dynamique ZAP.'
                : scanType === 'docker-image'
                ? 'Entrez le nom d\'une image Docker Hub pour scanner ses CVEs et tester l\'application en direct.'
                : 'Input your Git repository endpoint to begin deep-packet analysis and vulnerability identification.'}
            </p>
          </div>

          {/* Main URL / Image Input */}
          <div className="relative max-w-2xl mx-auto group">
            <div className={`absolute inset-0 blur-xl opacity-0 group-focus-within:opacity-100 transition-opacity duration-500 rounded-full ${
              scanType === 'dast' ? 'bg-orange-500/20'
              : scanType === 'docker-image' ? 'bg-purple-500/20'
              : 'bg-primary/20'
            }`}></div>
            <div className={`relative flex items-center p-2 bg-surface-container-low rounded-full border glass-panel transition-all shadow-2xl ${
              scanType === 'dast' ? 'border-orange-500/40 group-focus-within:border-orange-500/70'
              : scanType === 'docker-image' ? 'border-purple-500/40 group-focus-within:border-purple-500/70'
              : 'border-outline-variant/[0.15] group-focus-within:border-primary/50'
            }`}>
              <div className="pl-6 flex items-center gap-3">
                <span className={`material-symbols-outlined ${
                  scanType === 'dast' ? 'text-orange-400'
                  : scanType === 'docker-image' ? 'text-purple-400'
                  : 'text-primary'
                }`}>
                  {scanType === 'dast' ? 'travel_explore' : scanType === 'docker-image' ? 'deployed_code' : 'link'}
                </span>
              </div>
              <input
                className="flex-1 bg-transparent border-none focus:ring-0 text-lg font-headline text-on-surface placeholder:text-outline-variant py-4 px-4"
                placeholder={
                  scanType === 'dast' ? 'https://monapp.example.com'
                  : scanType === 'docker-image' ? 'docker.io/user/image:latest'
                  : 'github.com/organisation/repo ou gitlab.com/groupe/projet'
                }
                type="text"
                value={scanType === 'dast' ? dastTargetUrl : scanType === 'docker-image' ? dockerImageRef : repoUrl}
                onChange={e =>
                  scanType === 'dast' ? setDastTargetUrl(e.target.value)
                  : scanType === 'docker-image' ? setDockerImageRef(e.target.value)
                  : setRepoUrl(e.target.value)
                }
                onKeyDown={e => e.key === 'Enter' && handleStartScan()}
                disabled={scanning}
              />
              <button
                onClick={handleStartScan}
                disabled={scanning || (
                  scanType === 'dast' ? !dastTargetUrl.trim()
                  : scanType === 'docker-image' ? !dockerImageRef.trim()
                  : !repoUrl.trim()
                )}
                className={`text-on-primary-container active:scale-95 transition-all duration-300 font-bold px-8 py-4 rounded-full font-headline flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed ${
                  scanType === 'dast'
                    ? 'bg-orange-500/80 hover:shadow-[0_0_20px_rgba(249,115,22,0.6)]'
                    : scanType === 'docker-image'
                    ? 'bg-purple-600/80 hover:shadow-[0_0_20px_rgba(168,85,247,0.6)]'
                    : 'bg-primary-container hover:shadow-[0_0_20px_#00D1FF]'
                }`}
              >
                <span>{scanning ? 'Scanning...' : scanType === 'docker-image' ? 'Scan Image' : 'Start Security Scan'}</span>
                <span className="material-symbols-outlined text-lg">{scanning ? 'hourglass_top' : scanType === 'docker-image' ? 'deployed_code' : 'bolt'}</span>
              </button>
            </div>
          </div>

          {/* Docker Image — port field */}
          {scanType === 'docker-image' && (
            <div className="flex items-center gap-3 max-w-xs mx-auto -mt-4">
              <label className="text-xs text-outline whitespace-nowrap">Port exposé :</label>
              <input
                className="flex-1 bg-surface-container-low border border-purple-500/30 rounded-full px-4 py-2 text-sm font-headline text-on-surface placeholder:text-outline-variant focus:ring-1 focus:ring-purple-500 focus:border-purple-500/50 text-center"
                placeholder="3000"
                type="number"
                min="1"
                max="65535"
                value={containerPort}
                onChange={e => setContainerPort(e.target.value)}
                disabled={scanning}
              />
            </div>
          )}

          {/* Scan Type + Advanced Toggle */}
          <div className="flex items-center justify-center gap-4 flex-wrap">
            {/* Scan Type Dropdown */}
            <div className="relative">
              <button
                onClick={() => setDropdownOpen(!dropdownOpen)}
                disabled={scanning}
                className="flex items-center justify-between gap-3 px-5 py-3 bg-surface-container-low rounded-full border border-outline-variant/[0.15] hover:border-primary/40 transition-all glass-panel min-w-[220px] disabled:opacity-50"
              >
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-primary text-lg">{selectedScan.icon}</span>
                  <span className="text-sm font-headline text-on-surface">{selectedScan.label}</span>
                </div>
                <span className={`material-symbols-outlined text-outline text-lg transition-transform duration-200 ${dropdownOpen ? 'rotate-180' : ''}`}>expand_more</span>
              </button>

              {dropdownOpen && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setDropdownOpen(false)}></div>
                  <div className="absolute z-20 mt-2 w-full rounded-2xl border border-outline-variant/[0.15] bg-surface-container-low glass-panel shadow-2xl shadow-primary/5 max-h-60 overflow-y-auto custom-scrollbar">
                    {scanTypes.map((type) => (
                      <button
                        key={type.value}
                        onClick={() => { setScanType(type.value); setDropdownOpen(false); }}
                        className={`w-full flex items-center gap-3 px-5 py-3 text-left text-sm font-headline transition-all hover:bg-primary/10
                          ${scanType === type.value ? 'text-primary bg-primary/[0.07]' : 'text-on-surface-variant'}`}
                      >
                        <span className={`material-symbols-outlined text-lg ${scanType === type.value ? 'text-primary' : 'text-outline'}`}>{type.icon}</span>
                        <span>{type.label}</span>
                        {scanType === type.value && (
                          <span className="material-symbols-outlined text-primary text-sm ml-auto">check</span>
                        )}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>

            {/* Advanced Options Toggle */}
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-2 px-4 py-3 text-sm text-outline hover:text-on-surface transition-colors"
            >
              <span className="material-symbols-outlined text-lg">tune</span>
              <span className="font-headline">Advanced</span>
              <span className={`material-symbols-outlined text-sm transition-transform ${showAdvanced ? 'rotate-180' : ''}`}>expand_more</span>
            </button>
          </div>

          {/* Advanced Options */}
          {showAdvanced && (
            <div className="flex flex-col gap-4 max-w-xl mx-auto">
              {/* Existing: Branch + Target domain */}
              <div className="flex gap-4">
                <div className="flex-1">
                  <input
                    className="w-full bg-surface-container-low border border-outline-variant/[0.15] rounded-full px-5 py-3 text-sm font-headline text-on-surface placeholder:text-outline-variant focus:ring-1 focus:ring-primary focus:border-primary/50"
                    placeholder="Branch (default: main)"
                    value={branch}
                    onChange={e => setBranch(e.target.value)}
                    disabled={scanning}
                  />
                </div>
                <div className="flex-1">
                  <input
                    className="w-full bg-surface-container-low border border-outline-variant/[0.15] rounded-full px-5 py-3 text-sm font-headline text-on-surface placeholder:text-outline-variant focus:ring-1 focus:ring-primary focus:border-primary/50"
                    placeholder="Target domain (e.g. example.com)"
                    value={targetDomain}
                    onChange={e => setTargetDomain(e.target.value)}
                    disabled={scanning}
                  />
                </div>
              </div>

              {/* Idée 3 — OS cible + Idée 2 — Profil conformité */}
              <div className="flex gap-4">
                <div className="flex-1">
                  <select
                    className="w-full bg-surface-container-low border border-outline-variant/[0.15] rounded-full px-5 py-3 text-sm font-headline text-on-surface focus:ring-1 focus:ring-primary focus:border-primary/50"
                    value={targetOs}
                    onChange={e => setTargetOs(e.target.value)}
                    disabled={scanning}
                    title="OS cible (utilisé par Grype pour préciser les CVEs selon le système d'exploitation)"
                  >
                    <option value="">🌐 OS cible — auto-détection</option>
                    <option value="ubuntu:22.04">🐧 Ubuntu 22.04</option>
                    <option value="ubuntu:20.04">🐧 Ubuntu 20.04</option>
                    <option value="debian:12">🐧 Debian 12</option>
                    <option value="alpine:3.18">🐧 Alpine 3.18</option>
                    <option value="centos:8">🐧 CentOS 8</option>
                    <option value="rhel:9">🐧 RHEL 9</option>
                    <option value="windows:2022">🪟 Windows Server 2022</option>
                    <option value="windows:2019">🪟 Windows Server 2019</option>
                  </select>
                </div>
                <div className="flex-1">
                  <select
                    className="w-full bg-surface-container-low border border-outline-variant/[0.15] rounded-full px-5 py-3 text-sm font-headline text-on-surface focus:ring-1 focus:ring-primary focus:border-primary/50"
                    value={complianceProfile}
                    onChange={e => setComplianceProfile(e.target.value)}
                    disabled={scanning}
                    title="Profil de conformité OpenSCAP — exécute un audit CIS/NIST/PCI sur le conteneur scanner"
                  >
                    <option value="">🔓 Conformité — aucune</option>
                    <option value="CIS_L1">🛡️ CIS Level 1 (recommandé)</option>
                    <option value="CIS_L2">🛡️ CIS Level 2 (strict)</option>
                    <option value="NIST_800-53">📋 NIST SP 800-53</option>
                    <option value="PCI_DSS">💳 PCI DSS</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* Mode hints */}
          {scanType === 'dast' && (
            <p className="text-[11px] text-orange-400/70 text-center -mt-4">
              ZAP scannera cette URL en direct — l'application doit être accessible et en cours d'exécution
            </p>
          )}
          {scanType === 'docker-image' && (
            <p className="text-[11px] text-purple-400/70 text-center -mt-4">
              L'image sera téléchargée, analysée (Trivy + Grype), démarrée sur le port indiqué, puis scannée avec ZAP
            </p>
          )}

          <div className="flex items-center justify-center gap-8 mt-4">
            <div className="flex items-center gap-2 text-xs text-outline">
              <span className="w-2 h-2 rounded-full bg-tertiary"></span> SAST Analysis
            </div>
            <div className="flex items-center gap-2 text-xs text-outline">
              <span className="w-2 h-2 rounded-full bg-secondary"></span> Secret Detection
            </div>
            <div className="flex items-center gap-2 text-xs text-outline">
              <span className="w-2 h-2 rounded-full bg-primary"></span> Dependency Audit
            </div>
          </div>
        </div>
      </div>
      )} {/* end scanSource === 'url' || !user */}

      {/* Live Logs Panel */}
      <div className="w-full mt-16 max-w-5xl glass-panel rounded-t-2xl border-t border-x border-outline-variant/[0.15] overflow-hidden">
        <div className="bg-surface-container-highest/50 px-6 py-3 flex items-center justify-between border-b border-outline-variant/[0.1]">
          <div className="flex items-center gap-4">
            <div className="flex gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-[#FF5F56]"></div>
              <div className="w-2.5 h-2.5 rounded-full bg-[#FFBD2E]"></div>
              <div className="w-2.5 h-2.5 rounded-full bg-[#27C93F]"></div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {scanning && (
              <button
                onClick={handleStopScan}
                className="flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-mono font-semibold bg-error/10 text-error border border-error/30 hover:bg-error/20 transition-all"
              >
                <span className="material-symbols-outlined text-xs">stop_circle</span>
                Arrêter
              </button>
            )}
            <span className="text-[10px] font-mono text-tertiary flex items-center gap-1.5">
              {scanning ? (
                <>
                  <span className="w-1.5 h-1.5 bg-tertiary rounded-full animate-pulse"></span> Scan in progress...
                </>
              ) : logs.length > 0 ? (
                <>
                  <span className="w-1.5 h-1.5 bg-tertiary rounded-full"></span> Scan complete
                </>
              ) : (
                <>
                  <span className="w-1.5 h-1.5 bg-outline rounded-full"></span> Waiting for scan...
                </>
              )}
            </span>
          </div>
        </div>
        <div className="p-6 font-mono text-xs leading-relaxed h-64 overflow-y-auto bg-surface-container-lowest/80 custom-scrollbar">
          {logs.length === 0 && !scanning && (
            <div className="flex items-center gap-3 text-outline opacity-50">
              <span className="material-symbols-outlined text-base">terminal</span>
              <span>Awaiting scan initiation...</span>
            </div>
          )}
          {logs.map((log, i) => (
            <div key={i} className="flex gap-4 mb-1">
              <span className="text-outline opacity-40 shrink-0">{log.time}</span>
              {log.prefix && <span className={`${prefixColor(log.prefix)} shrink-0`}>{log.prefix}</span>}
              <span className="text-on-surface-variant break-all">{log.text}</span>
            </div>
          ))}
          <div ref={logsEndRef} />
        </div>
      </div>
    </div>
  );
};


export default Repositories;