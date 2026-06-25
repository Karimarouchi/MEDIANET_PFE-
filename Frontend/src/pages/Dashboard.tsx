import React, { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  getRepositories,
  getAllScans,
  getSslResult,
  getScheduledScans,
  pauseScheduledScan,
  resumeScheduledScan,
  deleteScheduledScan,
  type RepositoryDto,
  type ScanResultDto,
  type SslResultDto,
  type ScheduledScan,
} from '../services/api';

// Grade coloring helper for SSL scans
function getSslGradeStyle(grade: string) {
  const g = (grade || '?').toUpperCase();
  if (g === 'A+') return { text: 'text-tertiary', border: 'border-tertiary/30', bg: 'bg-tertiary/10', glow: 'shadow-[0_0_12px_rgba(0,252,146,0.25)]' };
  if (g === 'A')  return { text: 'text-primary', border: 'border-primary/30', bg: 'bg-primary/10', glow: 'shadow-[0_0_12px_rgba(164,230,255,0.25)]' };
  if (g === 'B')  return { text: 'text-amber-300', border: 'border-amber-300/30', bg: 'bg-amber-300/10', glow: 'shadow-[0_0_12px_rgba(252,211,77,0.25)]' };
  if (g === 'C')  return { text: 'text-orange-300', border: 'border-orange-300/30', bg: 'bg-orange-300/10', glow: 'shadow-[0_0_12px_rgba(253,186,116,0.25)]' };
  if (g === 'D')  return { text: 'text-orange-400', border: 'border-orange-400/30', bg: 'bg-orange-400/10', glow: 'shadow-[0_0_12px_rgba(251,146,60,0.25)]' };
  if (g === 'F')  return { text: 'text-error', border: 'border-error/30', bg: 'bg-error/10', glow: 'shadow-[0_0_12px_rgba(255,180,171,0.25)]' };
  return { text: 'text-outline', border: 'border-outline-variant/30', bg: 'bg-surface-container-high', glow: '' };
}

// Git Provider logo helper
function renderProviderIcon(provider?: string) {
  const p = (provider || '').toUpperCase();
  if (p === 'GITHUB') {
    return (
      <svg className="w-4 h-4 fill-current text-on-surface" viewBox="0 0 24 24">
        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
      </svg>
    );
  }
  if (p === 'GITLAB') {
    return (
      <svg className="w-4 h-4 fill-current text-orange-500" viewBox="0 0 24 24">
        <path d="M23.953 13.07a.977.977 0 0 0-.34-.993L12 3.22 2.387 12.077a.977.977 0 0 0-.34.993l3.297 10.147a.978.978 0 0 0 .93.673h11.452a.978.978 0 0 0 .93-.673l3.297-10.147zM12 5.8l2.977 2.723H9.023L12 5.8zm-3.8 3.723h7.6L12 17.6 8.2 9.523zm-1.897.977H2.88l3.197 2.923-2.274.654 2.497-3.577zm11.394 0l2.497 3.577-2.274-.654 3.197-2.923h-3.42z"/>
      </svg>
    );
  }
  return <span className="material-symbols-outlined text-[16px] text-outline">dns</span>;
}

const Dashboard: React.FC = () => {
  const { user } = useAuth();
  const [repositories, setRepositories] = useState<RepositoryDto[]>([]);
  const [scans, setScans] = useState<ScanResultDto[]>([]);
  const [sslResults, setSslResults] = useState<Record<number, SslResultDto>>({});
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'repos' | 'ssl'>('repos');
  const [scheduledScans, setScheduledScans] = useState<ScheduledScan[]>([]);
  const [scheduledLoading, setScheduledLoading] = useState(true);

  // State for interactive tooltip on the trend chart
  const [hoveredNode, setHoveredNode] = useState<{
    chart: string;
    index: number;
    x: number;
    y: number;
    val: any;
  } | null>(null);

  useEffect(() => {
    let active = true;

    const loadData = async () => {
      try {
        setLoading(true);
        const [reposRes, scansRes] = await Promise.all([
          getRepositories(),
          getAllScans()
        ]);

        if (!active) return;
        setRepositories(reposRes.data);
        setScans(scansRes.data);

        // Find the latest scan for each SSL domain to fetch their grade/details
        const sslScans = scansRes.data.filter(s => s.scanMode === 'ssl-only');
        const latestSslScansMap: Record<string, ScanResultDto> = {};
        
        sslScans.forEach(s => {
          const domainKey = s.targetDomain || s.repoUrl.replace('ssl://', '');
          if (domainKey) {
            const existing = latestSslScansMap[domainKey];
            if (!existing || new Date(s.startedAt) > new Date(existing.startedAt)) {
              latestSslScansMap[domainKey] = s;
            }
          }
        });

        const sslPromises = Object.values(latestSslScansMap).map(async (scan) => {
          try {
            const res = await getSslResult(scan.id);
            return { id: scan.id, data: res.data };
          } catch {
            return { id: scan.id, data: null };
          }
        });

        const sslDetails = await Promise.all(sslPromises);
        if (!active) return;

        const resultsMap: Record<number, SslResultDto> = {};
        sslDetails.forEach(item => {
          if (item.data) {
            resultsMap[item.id] = item.data;
          }
        });
        setSslResults(resultsMap);
      } catch (err) {
        console.error("Failed to load dashboard statistics", err);
      } finally {
        if (active) setLoading(false);
      }
    };

    loadData();

    return () => {
      active = false;
    };
  }, []);

  // Load scheduled scans
  useEffect(() => {
    setScheduledLoading(true);
    getScheduledScans()
      .then(res => setScheduledScans(res.data))
      .catch(() => {})
      .finally(() => setScheduledLoading(false));
  }, []);

  const handlePauseSchedule = async (id: number) => {
    await pauseScheduledScan(id).catch(() => {});
    setScheduledScans(prev => prev.map(s => s.id === id ? { ...s, status: 'PAUSED', enabled: false } : s));
  };

  const handleResumeSchedule = async (id: number) => {
    await resumeScheduledScan(id).catch(() => {});
    setScheduledScans(prev => prev.map(s => s.id === id ? { ...s, status: 'ACTIVE', enabled: true } : s));
  };

  const handleDeleteSchedule = async (id: number) => {
    await deleteScheduledScan(id).catch(() => {});
    setScheduledScans(prev => prev.filter(s => s.id !== id));
  };

  // Compute stats on the fly
  const stats = useMemo(() => {
    const codeRepos = repositories.filter(r => !r.repoUrl.startsWith('ssl://'));
    const totalRepos = codeRepos.length;
    const codeScans = scans.filter(s => s.scanMode !== 'ssl-only');
    const sslScans = scans.filter(s => s.scanMode === 'ssl-only');

    const totalScans = scans.length;
    const completedScans = scans.filter(s => s.status === 'COMPLETED').length;
    
    // Scan success rate
    const successRate = totalScans > 0
      ? Math.round((completedScans / totalScans) * 100)
      : 100;

    // Unique SSL domains scanned
    const sslDomains = Array.from(new Set(
      sslScans.map(s => s.targetDomain || s.repoUrl.replace('ssl://', ''))
    )).filter(Boolean);
    const totalSslDomains = sslDomains.length;

    // Active vulnerabilities (CVEs + Secrets) from the LATEST completed scan of each codebase
    const latestCodeScans: Record<number, ScanResultDto> = {};
    codeScans.forEach(s => {
      if (s.status === 'COMPLETED') {
        const existing = latestCodeScans[s.repoId];
        if (!existing || new Date(s.startedAt) > new Date(existing.startedAt)) {
          latestCodeScans[s.repoId] = s;
        }
      }
    });

    let activeCves = 0;
    let activeSecrets = 0;
    Object.values(latestCodeScans).forEach(s => {
      activeCves += s.cveCount || 0;
      activeSecrets += s.secretCount || 0;
    });

    const activeVulnerabilities = activeCves + activeSecrets;

    // Security Score (0 to 10 scale, subtracting penalties)
    const penalty = (activeCves * 0.1) + (activeSecrets * 0.35);
    const securityScore = totalRepos > 0
      ? Math.max(1.0, Math.min(10.0, parseFloat((10.0 - penalty).toFixed(1))))
      : 10.0;

    return {
      totalRepos,
      totalScans,
      successRate,
      totalSslDomains,
      activeCves,
      activeSecrets,
      activeVulnerabilities,
      securityScore
    };
  }, [repositories, scans]);

  // Compute trend data (last 8 completed repository scans)
  const trendData = useMemo(() => {
    const completedCodeScans = scans
      .filter(s => s.scanMode !== 'ssl-only' && s.status === 'COMPLETED')
      .sort((a, b) => new Date(a.finishedAt || a.startedAt).getTime() - new Date(b.finishedAt || b.startedAt).getTime());

    const lastScans = completedCodeScans.slice(-8);

    return lastScans.map(s => {
      const date = new Date(s.finishedAt || s.startedAt);
      const label = date.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short' });
      const repoName = s.repoUrl ? s.repoUrl.split('/').pop()?.replace('.git', '') : 'Dépôt';
      return {
        id: s.id,
        label,
        repoName,
        cves: s.cveCount || 0,
        secrets: s.secretCount || 0,
        total: (s.cveCount || 0) + (s.secretCount || 0)
      };
    });
  }, [scans]);

  // Compute technology/ecosystems breakdown
  const ecosystemData = useMemo(() => {
    const counts: Record<string, number> = {};
    const latestCodeScans: Record<number, ScanResultDto> = {};

    scans
      .filter(s => s.scanMode !== 'ssl-only' && s.status === 'COMPLETED')
      .forEach(s => {
        const existing = latestCodeScans[s.repoId];
        if (!existing || new Date(s.startedAt) > new Date(existing.startedAt)) {
          latestCodeScans[s.repoId] = s;
        }
      });

    Object.values(latestCodeScans).forEach(s => {
      if (s.ecosystemsDetected) {
        const list = s.ecosystemsDetected
          .split(/[\s,]+/)
          .map(item => item.trim().toLowerCase())
          .filter(Boolean);

        list.forEach(eco => {
          let name = eco;
          if (eco === 'npm' || eco === 'node') name = 'Node.js (npm)';
          else if (eco === 'maven' || eco === 'java') name = 'Java (Maven)';
          else if (eco === 'pip' || eco === 'python') name = 'Python (pip)';
          else if (eco === 'go' || eco === 'golang') name = 'Go (golang)';
          else if (eco === 'nuget' || eco === 'dotnet') name = 'C# (.NET)';
          else if (eco === 'composer' || eco === 'php') name = 'PHP (Composer)';
          else {
            name = eco.charAt(0).toUpperCase() + eco.slice(1);
          }
          counts[name] = (counts[name] ?? 0) + 1;
        });
      }
    });

    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total === 0) return [];

    const colors = ['#00d1ff', '#d1bcff', '#00fc92', '#ffe066', '#ff7b54', '#859399'];

    return Object.entries(counts)
      .map(([name, count], index) => {
        const percentage = Math.round((count / total) * 100);
        return {
          name,
          count,
          percentage,
          color: colors[index % colors.length]
        };
      })
      .sort((a, b) => b.count - a.count);
  }, [scans]);

  // Compute the list of repositories with their latest scan status
  const repositoryStatusList = useMemo(() => {
    const listMap: Record<number, { repo: RepositoryDto; lastScan?: ScanResultDto }> = {};
    
    // Filter out SSL-only domains from code repositories list
    const codeRepos = repositories.filter(repo => !repo.repoUrl.startsWith('ssl://'));
    
    codeRepos.forEach(repo => {
      listMap[repo.id] = { repo };
    });

    scans
      .filter(s => s.scanMode !== 'ssl-only')
      .forEach(s => {
        const item = listMap[s.repoId];
        if (item) {
          const existing = item.lastScan;
          if (!existing || new Date(s.startedAt) > new Date(existing.startedAt)) {
            item.lastScan = s;
          }
        }
      });

    return Object.values(listMap).sort((a, b) => {
      const aTime = a.lastScan ? new Date(a.lastScan.startedAt).getTime() : 0;
      const bTime = b.lastScan ? new Date(b.lastScan.startedAt).getTime() : 0;
      return bTime - aTime;
    });
  }, [repositories, scans]);

  // Compute the list of scanned SSL domains
  const sslStatusList = useMemo(() => {
    const sslScans = scans.filter(s => s.scanMode === 'ssl-only');
    const latestSslScansMap: Record<string, { scan: ScanResultDto; details?: SslResultDto }> = {};

    sslScans.forEach(s => {
      const domainKey = s.targetDomain || s.repoUrl.replace('ssl://', '');
      if (domainKey) {
        const existing = latestSslScansMap[domainKey];
        if (!existing || new Date(s.startedAt) > new Date(existing.scan.startedAt)) {
          latestSslScansMap[domainKey] = {
            scan: s,
            details: sslResults[s.id]
          };
        }
      }
    });

    return Object.values(latestSslScansMap).sort((a, b) => 
      new Date(b.scan.startedAt).getTime() - new Date(a.scan.startedAt).getTime()
    );
  }, [scans, sslResults]);

  // Real-time activity timeline
  const activityTimeline = useMemo(() => {
    return [...scans]
      .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())
      .slice(0, 4);
  }, [scans]);

  // Render SVG Line Chart
  const renderTrendChart = () => {
    if (trendData.length < 2) {
      return (
        <div className="flex flex-col items-center justify-center h-full text-outline text-sm py-12">
          <span className="material-symbols-outlined text-4xl mb-2 text-outline-variant">show_chart</span>
          <p>Pas assez de données de scan pour tracer les tendances.</p>
        </div>
      );
    }

    const width = 500;
    const height = 180;
    const paddingX = 40;
    const paddingY = 20;

    const maxVal = Math.max(...trendData.map(d => Math.max(d.cves, d.secrets, d.total)), 5);
    const stepX = (width - paddingX * 2) / (trendData.length - 1);

    const getPoints = (key: 'cves' | 'secrets' | 'total') => {
      return trendData.map((d, i) => {
        const x = paddingX + i * stepX;
        const y = height - paddingY - (d[key] / maxVal) * (height - paddingY * 2);
        return { x, y, val: d[key], data: d };
      });
    };

    const cvePoints = getPoints('cves');
    const secretPoints = getPoints('secrets');
    const totalPoints = getPoints('total');

    const getPathString = (points: typeof cvePoints) => {
      return points.map((p, i) => (i === 0 ? `M ${p.x} ${p.y}` : `L ${p.x} ${p.y}`)).join(' ');
    };

    const getAreaPathString = (points: typeof cvePoints) => {
      if (points.length === 0) return '';
      const startX = points[0].x;
      const endX = points[points.length - 1].x;
      const bottomY = height - paddingY;
      return `${getPathString(points)} L ${endX} ${bottomY} L ${startX} ${bottomY} Z`;
    };

    return (
      <div className="relative w-full h-full flex flex-col justify-between">
        <div className="relative flex-1 min-h-[160px]">
          <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full overflow-visible">
            <defs>
              <linearGradient id="total-gradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#00fc92" stopOpacity="0.2" />
                <stop offset="100%" stopColor="#00fc92" stopOpacity="0" />
              </linearGradient>
            </defs>

            {/* Grid lines */}
            {[0, 0.25, 0.5, 0.75, 1].map((ratio, index) => {
              const y = paddingY + ratio * (height - paddingY * 2);
              const val = Math.round(maxVal * (1 - ratio));
              return (
                <g key={index} className="opacity-30">
                  <line
                    x1={paddingX}
                    y1={y}
                    x2={width - paddingX}
                    y2={y}
                    stroke="var(--color-outline-variant, #3c494e)"
                    strokeWidth="0.5"
                    strokeDasharray="4 4"
                  />
                  <text
                    x={paddingX - 10}
                    y={y + 4}
                    textAnchor="end"
                    className="fill-outline text-[10px] font-mono"
                  >
                    {val}
                  </text>
                </g>
              );
            })}

            {/* Area under total line */}
            <path
              d={getAreaPathString(totalPoints)}
              fill="url(#total-gradient)"
            />

            {/* Lines */}
            <path
              d={getPathString(cvePoints)}
              fill="none"
              stroke="#00d1ff"
              strokeWidth="2.5"
              strokeLinecap="round"
            />
            <path
              d={getPathString(secretPoints)}
              fill="none"
              stroke="#d1bcff"
              strokeWidth="2"
              strokeLinecap="round"
              strokeDasharray="3 3"
            />
            <path
              d={getPathString(totalPoints)}
              fill="none"
              stroke="#00fc92"
              strokeWidth="3"
              strokeLinecap="round"
            />

            {/* Interactive hover target circles */}
            {totalPoints.map((p, i) => (
              <g key={i} className="group/node">
                <circle
                  cx={p.x}
                  cy={p.y}
                  r="12"
                  className="fill-transparent cursor-pointer"
                  onMouseEnter={(e) => {
                    setHoveredNode({
                      chart: 'trend',
                      index: i,
                      x: p.x,
                      y: p.y,
                      val: p.data
                    });
                  }}
                  onMouseLeave={() => setHoveredNode(null)}
                />
                <circle
                  cx={p.x}
                  cy={p.y}
                  r="4"
                  className="fill-surface stroke-tertiary stroke-[2px] transition-all group-hover/node:r-6 group-hover/node:stroke-[3px]"
                />
              </g>
            ))}
          </svg>

          {/* Tooltip */}
          {hoveredNode && hoveredNode.chart === 'trend' && (
            <div
              className="absolute z-20 bg-surface-container-high border border-outline-variant p-3 rounded-2xl shadow-xl text-xs space-y-1.5 backdrop-blur-md pointer-events-none transition-all duration-100"
              style={{
                left: `${(hoveredNode.x / width) * 100}%`,
                top: `${(hoveredNode.y / height) * 100 - 85}%`,
                transform: 'translateX(-50%)',
              }}
            >
              <div className="font-headline font-bold text-on-surface flex items-center justify-between gap-4">
                <span>{hoveredNode.val.repoName}</span>
                <span className="text-[9px] text-outline font-mono">{hoveredNode.val.label}</span>
              </div>
              <div className="space-y-1 border-t border-outline-variant/[0.12] pt-1.5 mt-1 text-[10px] font-medium">
                <div className="flex justify-between items-center gap-6">
                  <span className="text-on-surface-variant flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-primary-container" />
                    CVEs :
                  </span>
                  <span className="font-bold text-on-surface">{hoveredNode.val.cves}</span>
                </div>
                <div className="flex justify-between items-center gap-6">
                  <span className="text-on-surface-variant flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-secondary" />
                    Secrets :
                  </span>
                  <span className="font-bold text-on-surface">{hoveredNode.val.secrets}</span>
                </div>
                <div className="flex justify-between items-center gap-6 border-t border-outline-variant/[0.1] pt-1 mt-1 font-bold">
                  <span className="text-tertiary flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-tertiary" />
                    Total :
                  </span>
                  <span className="text-tertiary">{hoveredNode.val.total}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Legend */}
        <div className="flex flex-wrap justify-center gap-4 text-[10px] text-outline font-semibold mt-1">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-primary-container inline-block" />
            <span>CVEs</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 border-t border-dashed border-secondary inline-block" />
            <span>Secrets de code</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-tertiary inline-block" />
            <span>Vulnérabilités totales</span>
          </div>
        </div>
      </div>
    );
  };

  // Render SVG Donut Chart
  const renderEcosystemDonut = () => {
    if (ecosystemData.length === 0) {
      return (
        <div className="flex flex-col items-center justify-center h-full text-outline text-sm py-12">
          <span className="material-symbols-outlined text-4xl mb-2 text-outline-variant">pie_chart</span>
          <p>Aucune technologie détectée sur les dépôts.</p>
        </div>
      );
    }

    const cx = 60;
    const cy = 60;
    const r = 40;
    const strokeWidth = 9;
    const C = 2 * Math.PI * r;

    let accumulatedPercentage = 0;

    return (
      <div className="flex flex-col sm:flex-row items-center justify-center gap-6 h-full py-2">
        <div className="relative w-28 h-28 shrink-0">
          <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
            <circle
              cx={cx}
              cy={cy}
              r={r}
              fill="none"
              stroke="var(--color-outline-variant, #3c494e)"
              strokeWidth={strokeWidth}
              className="opacity-10"
            />
            {ecosystemData.map((slice, index) => {
              const strokeDasharray = `${(slice.percentage / 100) * C} ${C}`;
              const strokeDashoffset = C - (accumulatedPercentage / 100) * C;
              accumulatedPercentage += slice.percentage;

              return (
                <circle
                  key={index}
                  cx={cx}
                  cy={cy}
                  r={r}
                  fill="none"
                  stroke={slice.color}
                  strokeWidth={strokeWidth}
                  strokeDasharray={strokeDasharray}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  className="transition-all duration-300 hover:stroke-[11px] cursor-pointer"
                >
                  <title>{`${slice.name}: ${slice.percentage}%`}</title>
                </circle>
              );
            })}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-xl font-headline font-bold text-on-surface">{stats.totalRepos}</span>
            <span className="text-[8px] text-outline uppercase tracking-wider">Dépôts</span>
          </div>
        </div>

        <div className="flex-1 space-y-2 w-full">
          {ecosystemData.slice(0, 4).map((slice, index) => (
            <div key={index} className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: slice.color }} />
                <span className="text-on-surface-variant font-medium truncate max-w-[120px]">{slice.name}</span>
              </div>
              <div className="flex items-center gap-2 shrink-0 font-mono">
                <span className="text-on-surface font-semibold">{slice.count}</span>
                <span className="text-outline text-[9px]">({slice.percentage}%)</span>
              </div>
            </div>
          ))}
          {ecosystemData.length > 4 && (
            <p className="text-[9px] text-outline text-right font-medium italic">
              + {ecosystemData.length - 4} autres technologies
            </p>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-8">
      {/* Welcome Banner */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 border-b border-outline-variant/[0.12] pb-6">
        <div>
          <h1 className="font-headline text-3xl font-extrabold tracking-tight text-on-surface">
            Ravi de vous revoir, {user?.name || user?.login || 'Commandant'}.
          </h1>
          <div className="flex items-center gap-2 mt-2">
            <span className="flex h-2.5 w-2.5 rounded-full bg-tertiary pulse-secure" />
            <p className="text-xs text-outline font-semibold">
              Statut Sécurité : <span className="text-tertiary font-bold tracking-wider uppercase">SÉCURISÉ</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4 bg-surface-container-low p-1.5 rounded-2xl border border-outline-variant/[0.12] self-start md:self-auto">
          <span className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-outline">Période</span>
          <span className="px-4 py-2 text-xs font-headline font-bold uppercase tracking-wider bg-surface-container-high text-primary-container rounded-xl shadow-md border border-outline-variant/[0.1]">
            Temps Réel
          </span>
        </div>
      </div>

      {/* Loading state spinner */}
      {loading ? (
        <div className="flex flex-col items-center justify-center py-24 space-y-4">
          <span className="material-symbols-outlined text-primary text-4xl animate-spin">
            progress_activity
          </span>
          <p className="text-sm text-outline font-medium">Récupération des métriques de sécurité...</p>
        </div>
      ) : (
        <>
          {/* Bento Stats Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            
            {/* Card: Repositories monitored */}
            <div className="glass-panel p-6 rounded-3xl border border-outline-variant/[0.18] group hover:border-primary-container/[0.3] transition-all duration-300 relative overflow-hidden flex flex-col justify-between min-h-[160px]">
              <div className="absolute -right-8 -top-8 w-24 h-24 bg-primary/5 blur-2xl rounded-full transition-all group-hover:bg-primary/10" />
              <div>
                <div className="flex justify-between items-start mb-4">
                  <span className="text-outline text-[11px] font-bold uppercase tracking-widest font-label">Dépôts Scannés</span>
                  <span className="material-symbols-outlined text-primary-container">source</span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-4xl font-headline font-bold text-on-surface glow-text-primary">
                    {String(stats.totalRepos).padStart(2, '0')}
                  </span>
                  <span className="text-tertiary text-xs font-bold uppercase tracking-wide bg-tertiary/10 border border-tertiary/20 rounded px-1.5 py-0.5">
                    Actifs
                  </span>
                </div>
              </div>
              <div className="mt-3 flex items-center gap-1.5 text-[10px] font-semibold border-t border-outline-variant/[0.08] pt-2">
                {stats.activeVulnerabilities > 0 ? (
                  <>
                    <span className="material-symbols-outlined text-[14px] text-error">warning</span>
                    <span className="text-error">{stats.activeVulnerabilities} vulnérabilités actives</span>
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined text-[14px] text-tertiary">check_circle</span>
                    <span className="text-tertiary">Aucun problème détecté</span>
                  </>
                )}
              </div>
            </div>

            {/* Card: Total Scans Run */}
            <div className="glass-panel p-6 rounded-3xl border border-outline-variant/[0.18] group hover:border-secondary/[0.3] transition-all duration-300 relative overflow-hidden flex flex-col justify-between min-h-[160px]">
              <div className="absolute -right-8 -top-8 w-24 h-24 bg-secondary/5 blur-2xl rounded-full transition-all group-hover:bg-secondary/10" />
              <div>
                <div className="flex justify-between items-start mb-4">
                  <span className="text-outline text-[11px] font-bold uppercase tracking-widest font-label">Scans Exécutés</span>
                  <span className="material-symbols-outlined text-secondary">explore</span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-4xl font-headline font-bold text-on-surface">
                    {String(stats.totalScans).padStart(2, '0')}
                  </span>
                  <span className="text-outline text-xs font-semibold">
                    ({stats.successRate}% succès)
                  </span>
                </div>
              </div>
              <div className="mt-3 border-t border-outline-variant/[0.08] pt-2">
                <div className="h-1.5 w-full bg-surface-container-highest rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-tertiary rounded-full transition-all duration-500" 
                    style={{ width: `${stats.successRate}%` }} 
                  />
                </div>
              </div>
            </div>

            {/* Card: SSL Domains Scanned */}
            <div className="glass-panel p-6 rounded-3xl border border-outline-variant/[0.18] group hover:border-tertiary/[0.3] transition-all duration-300 relative overflow-hidden flex flex-col justify-between min-h-[160px]">
              <div className="absolute -right-8 -top-8 w-24 h-24 bg-tertiary/5 blur-2xl rounded-full transition-all group-hover:bg-tertiary/10" />
              <div>
                <div className="flex justify-between items-start mb-4">
                  <span className="text-outline text-[11px] font-bold uppercase tracking-widest font-label">Scans SSL</span>
                  <span className="material-symbols-outlined text-tertiary">domain</span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-4xl font-headline font-bold text-on-surface">
                    {String(stats.totalSslDomains).padStart(2, '0')}
                  </span>
                  <span className="text-outline text-xs font-semibold">domaines</span>
                </div>
              </div>
              <div className="mt-3 flex items-center gap-1.5 text-[10px] font-semibold border-t border-outline-variant/[0.08] pt-2">
                {Object.values(sslResults).some(r => r.certExpired || (r.certDaysLeft !== -1 && r.certDaysLeft < 30)) ? (
                  <>
                    <span className="material-symbols-outlined text-[14px] text-error">warning</span>
                    <span className="text-error">Alertes de certificat détectées</span>
                  </>
                ) : stats.totalSslDomains > 0 ? (
                  <>
                    <span className="material-symbols-outlined text-[14px] text-tertiary">check_circle</span>
                    <span className="text-tertiary">Tous les certificats sont valides</span>
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined text-[14px] text-outline">info</span>
                    <span className="text-outline">Aucun domaine audité</span>
                  </>
                )}
              </div>
            </div>

            {/* Card: Global Security Score */}
            <div className="glass-panel p-6 rounded-3xl border border-outline-variant/[0.18] group hover:border-primary/[0.3] transition-all duration-300 flex items-center justify-between min-h-[160px]">
              <div>
                <span className="text-outline text-[11px] font-bold uppercase tracking-widest font-label block mb-1">Score Sécurité</span>
                <span className="text-[10px] text-outline-variant block mb-3">Télémétrie temps réel</span>
                <div className="flex items-baseline">
                  <span className="text-3xl font-headline font-bold text-primary">{stats.securityScore}</span>
                  <span className="text-outline text-base font-headline">/10</span>
                </div>
              </div>
              <div className="relative w-20 h-20 shrink-0">
                <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                  <circle className="stroke-surface-container-highest opacity-25" cx="18" cy="18" fill="none" r="16" strokeWidth="3" />
                  <circle 
                    className="stroke-primary transition-all duration-500" 
                    cx="18" 
                    cy="18" 
                    fill="none" 
                    r="16" 
                    strokeDasharray={`${stats.securityScore * 10}, 100`} 
                    strokeLinecap="round" 
                    strokeWidth="3" 
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="material-symbols-outlined text-primary text-xl">verified_user</span>
                </div>
              </div>
            </div>

          </div>

          {/* Diagrams Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            {/* Chart: Security Trends */}
            <div className="lg:col-span-2 glass-panel p-6 rounded-3xl border border-outline-variant/[0.18] flex flex-col justify-between">
              <div className="flex justify-between items-start mb-6">
                <div>
                  <h3 className="font-headline text-lg font-bold text-on-surface">Évolution des Vulnérabilités</h3>
                  <p className="text-xs text-outline">Compteurs cumulés de CVEs et Secrets détectés au fil des scans</p>
                </div>
                <Link to="/scans" className="inline-flex h-8 w-8 items-center justify-center rounded-xl bg-surface-container-high border border-outline-variant/[0.15] text-outline hover:text-primary transition-colors">
                  <span className="material-symbols-outlined text-[18px]">open_in_new</span>
                </Link>
              </div>
              <div className="flex-1 flex items-center">
                {renderTrendChart()}
              </div>
            </div>

            {/* Chart: Ecosystems Breakdown */}
            <div className="glass-panel p-6 rounded-3xl border border-outline-variant/[0.18] flex flex-col justify-between">
              <div className="mb-6">
                <h3 className="font-headline text-lg font-bold text-on-surface">Écosystèmes & Technos</h3>
                <p className="text-xs text-outline">Répartition des frameworks de dépendances analysés</p>
              </div>
              <div className="flex-1 flex items-center justify-center">
                {renderEcosystemDonut()}
              </div>
            </div>

          </div>

          {/* Details Tables tabs container */}
          <div className="glass-panel rounded-3xl border border-outline-variant/[0.18] overflow-hidden">
            
            {/* Tabs Header */}
            <div className="flex items-center justify-between border-b border-outline-variant/[0.12] bg-surface-container px-6 py-4 flex-wrap gap-4">
              <div className="flex gap-2">
                <button
                  onClick={() => setActiveTab('repos')}
                  className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-headline font-bold tracking-wide transition-all border ${
                    activeTab === 'repos'
                      ? 'bg-primary/10 border-primary/20 text-primary'
                      : 'border-transparent text-outline hover:text-on-surface hover:bg-surface-container-high'
                  }`}
                >
                  <span className="material-symbols-outlined text-[16px]">folder_special</span>
                  <span>Dépôts Code Scannés ({stats.totalRepos})</span>
                </button>
                <button
                  onClick={() => setActiveTab('ssl')}
                  className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-headline font-bold tracking-wide transition-all border ${
                    activeTab === 'ssl'
                      ? 'bg-tertiary/10 border-tertiary/20 text-tertiary'
                      : 'border-transparent text-outline hover:text-on-surface hover:bg-surface-container-high'
                  }`}
                >
                  <span className="material-symbols-outlined text-[16px]">lock</span>
                  <span>Scans SSL Actifs ({stats.totalSslDomains})</span>
                </button>
              </div>
              
              <Link 
                to={activeTab === 'repos' ? '/repositories' : '/ssl-analysis'}
                className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline font-semibold"
              >
                <span>Accéder aux configurations</span>
                <span className="material-symbols-outlined text-[16px]">arrow_right_alt</span>
              </Link>
            </div>

            {/* Tab content area */}
            <div className="p-6">
              {activeTab === 'repos' ? (
                // Repositories Scanned List
                <div className="overflow-x-auto">
                  {repositoryStatusList.length === 0 ? (
                    <div className="text-center py-12 text-outline text-sm">
                      Aucun dépôt scanné enregistré.
                    </div>
                  ) : (
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-outline-variant/[0.08] text-[10px] uppercase tracking-wider text-outline">
                          <th className="pb-3 pl-2">Nom du dépôt</th>
                          <th className="pb-3">Branche / Mode</th>
                          <th className="pb-3">Dernier Scan</th>
                          <th className="pb-3">Statut</th>
                          <th className="pb-3 text-center">Menaces</th>
                          <th className="pb-3 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-outline-variant/[0.06] text-xs">
                        {repositoryStatusList.map(({ repo, lastScan }) => {
                          const name = repo.repoUrl.replace(/\.git$/, '').split('/').pop() || repo.repoUrl;
                          const hasScans = !!lastScan;
                          const completed = lastScan?.status === 'COMPLETED';
                          const scanDateStr = lastScan
                            ? new Date(lastScan.finishedAt || lastScan.startedAt).toLocaleString('fr-FR', {
                                day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
                              })
                            : 'Aucun scan';

                          return (
                            <tr key={repo.id} className="hover:bg-surface-container-high/20 group">
                              <td className="py-4 pl-2 font-medium">
                                <div className="flex items-center gap-3">
                                  <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-surface-container border border-outline-variant/[0.12] shrink-0">
                                    {renderProviderIcon(repo.gitProvider)}
                                  </div>
                                  <div>
                                    <p className="text-sm font-headline font-semibold text-on-surface line-clamp-1 group-hover:text-primary transition-colors">
                                      {name}
                                    </p>
                                    <p className="text-[10px] text-outline line-clamp-1 truncate max-w-[200px]" title={repo.repoUrl}>
                                      {repo.repoUrl}
                                    </p>
                                  </div>
                                </div>
                              </td>
                              <td className="py-4">
                                <span className="rounded-full bg-surface-container-high border border-outline-variant/[0.15] px-2 py-0.5 text-[10px] font-mono font-bold text-on-surface-variant">
                                  {repo.branch}
                                </span>
                                <p className="text-[10px] text-outline mt-1 font-medium italic">{repo.scanMode}</p>
                              </td>
                              <td className="py-4 text-on-surface-variant font-medium">
                                {scanDateStr}
                              </td>
                              <td className="py-4">
                                {hasScans ? (
                                  <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[10px] font-bold uppercase tracking-wider ${
                                    lastScan.status === 'COMPLETED'
                                      ? 'bg-tertiary/10 border-tertiary/20 text-tertiary'
                                      : lastScan.status === 'FAILED'
                                      ? 'bg-error/10 border-error/20 text-error'
                                      : 'bg-secondary/10 border-secondary/20 text-secondary animate-pulse'
                                  }`}>
                                    <span className={`h-1.5 w-1.5 rounded-full ${
                                      lastScan.status === 'COMPLETED' ? 'bg-tertiary' : lastScan.status === 'FAILED' ? 'bg-error' : 'bg-secondary pulsar'
                                    }`} />
                                    {lastScan.status}
                                  </span>
                                ) : (
                                  <span className="text-outline text-[10px] italic">Non planifié</span>
                                )}
                              </td>
                              <td className="py-4 text-center">
                                {hasScans && completed ? (
                                  <div className="inline-flex gap-2">
                                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-bold ${
                                      (lastScan.cveCount || 0) > 0 ? 'bg-error-container text-on-error-container' : 'bg-surface-container text-outline'
                                    }`}>
                                      {(lastScan.cveCount || 0)} CVEs
                                    </span>
                                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-bold ${
                                      (lastScan.secretCount || 0) > 0 ? 'bg-secondary-container text-on-secondary-container' : 'bg-surface-container text-outline'
                                    }`}>
                                      {(lastScan.secretCount || 0)} Secrets
                                    </span>
                                  </div>
                                ) : (
                                  <span className="text-outline">—</span>
                                )}
                              </td>
                              <td className="py-4 text-right">
                                <Link
                                  to={hasScans && completed ? `/vulnerabilities?scanId=${lastScan.id}` : `/repositories`}
                                  className="inline-flex h-8 px-3 items-center justify-center rounded-xl border border-outline-variant/[0.22] bg-surface-container-high text-xs font-semibold text-on-surface hover:border-primary/40 hover:text-primary transition-colors"
                                >
                                  {hasScans && completed ? 'Consulter' : 'Lancer'}
                                </Link>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              ) : (
                // SSL Domains Scanned List
                <div className="overflow-x-auto">
                  {sslStatusList.length === 0 ? (
                    <div className="text-center py-12 text-outline text-sm">
                      Aucun audit SSL disponible.
                    </div>
                  ) : (
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-outline-variant/[0.08] text-[10px] uppercase tracking-wider text-outline">
                          <th className="pb-3 pl-2">Domaine / Hôte</th>
                          <th className="pb-3">Dernière analyse</th>
                          <th className="pb-3">Statut scan</th>
                          <th className="pb-3 text-center">Note SSL</th>
                          <th className="pb-3">Validité Certificat</th>
                          <th className="pb-3">Protocoles actifs</th>
                          <th className="pb-3 text-right">Détails</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-outline-variant/[0.06] text-xs">
                        {sslStatusList.map(({ scan, details }) => {
                          const domain = scan.targetDomain || scan.repoUrl.replace('ssl://', '');
                          const finishedAt = scan.finishedAt || scan.startedAt;
                          const scanDateStr = new Date(finishedAt).toLocaleString('fr-FR', {
                            day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
                          });

                          // Grade formatting
                          const grade = details?.grade || '?';
                          const gradeStyle = getSslGradeStyle(grade);

                          // Certificate validity
                          const daysLeft = details ? details.certDaysLeft : -1;
                          let certStatusElement = <span className="text-outline">Non résolu</span>;
                          if (details) {
                            if (details.certExpired || daysLeft <= 0) {
                              certStatusElement = <span className="text-error font-bold flex items-center gap-1"><span className="material-symbols-outlined text-[14px]">warning</span> Expiré</span>;
                            } else if (daysLeft < 30) {
                              certStatusElement = <span className="text-amber-400 font-bold flex items-center gap-1"><span className="material-symbols-outlined text-[14px]">error</span> {daysLeft} jours</span>;
                            } else {
                              certStatusElement = <span className="text-tertiary font-medium">{daysLeft} jours restants</span>;
                            }
                          }

                          // Protocols summary
                          const protocols: string[] = [];
                          if (details) {
                            if (details.tls13) protocols.push('TLS 1.3');
                            if (details.tls12) protocols.push('TLS 1.2');
                            if (details.tls11) protocols.push('TLS 1.1 ⚠️');
                            if (details.tls10) protocols.push('TLS 1.0 ⚠️');
                          }

                          return (
                            <tr key={scan.id} className="hover:bg-surface-container-high/20">
                              <td className="py-4 pl-2 font-medium">
                                <div className="flex items-center gap-2.5">
                                  <span className="material-symbols-outlined text-outline text-base">dns</span>
                                  <span className="font-headline text-sm font-semibold text-on-surface">{domain}</span>
                                </div>
                              </td>
                              <td className="py-4 text-on-surface-variant font-medium">
                                {scanDateStr}
                              </td>
                              <td className="py-4">
                                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider border ${
                                  scan.status === 'COMPLETED'
                                    ? 'bg-surface-container-high border-outline-variant/30 text-outline'
                                    : scan.status === 'FAILED'
                                    ? 'bg-error/10 border-error/20 text-error'
                                    : 'bg-secondary/10 border-secondary/20 text-secondary animate-pulse'
                                }`}>
                                  {scan.status}
                                </span>
                              </td>
                              <td className="py-4 text-center">
                                <span className={`inline-flex items-center justify-center w-8 h-8 rounded-full border font-headline text-sm font-extrabold ${gradeStyle.bg} ${gradeStyle.border} ${gradeStyle.text} ${gradeStyle.glow}`}>
                                  {grade}
                                </span>
                              </td>
                              <td className="py-4">
                                {certStatusElement}
                              </td>
                              <td className="py-4 font-mono text-[10px] text-on-surface-variant">
                                {protocols.length > 0 ? protocols.join(', ') : '—'}
                              </td>
                              <td className="py-4 text-right">
                                <Link
                                  to={`/ssl-analysis`}
                                  className="inline-flex h-8 px-3 items-center justify-center rounded-xl border border-outline-variant/[0.22] bg-surface-container-high text-xs font-semibold text-on-surface hover:border-tertiary/40 hover:text-tertiary transition-colors"
                                >
                                  Détail
                                </Link>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              )}
            </div>

          </div>

          {/* ── Scans Planifiés Section ──────────────────────────────── */}
          <div className="glass-panel rounded-3xl border border-outline-variant/[0.18] overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 bg-surface-container border-b border-outline-variant/[0.12]">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-violet-400 text-xl" style={{ fontVariationSettings: "'FILL' 1" }}>calendar_clock</span>
                <div>
                  <h3 className="font-headline text-base font-bold text-on-surface">Scans Planifiés</h3>
                  <p className="text-[11px] text-outline">Tâches automatiques actives et programmées</p>
                </div>
              </div>
              {scheduledLoading && <span className="material-symbols-outlined text-sm animate-spin text-violet-400">progress_activity</span>}
            </div>

            {!scheduledLoading && scheduledScans.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 gap-3 text-center">
                <span className="material-symbols-outlined text-4xl text-outline-variant">event_busy</span>
                <p className="text-sm text-outline">Aucun scan planifié pour le moment.</p>
                <div className="flex gap-3 mt-2">
                  <Link to="/repositories" className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-outline-variant/20 text-xs font-bold text-outline hover:text-primary hover:border-primary/30 transition-all">
                    <span className="material-symbols-outlined text-[15px]">folder_special</span>Planifier sur un dépôt
                  </Link>
                  <Link to="/ssl-analysis" className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-outline-variant/20 text-xs font-bold text-outline hover:text-tertiary hover:border-tertiary/30 transition-all">
                    <span className="material-symbols-outlined text-[15px]">lock</span>Planifier un scan SSL
                  </Link>
                </div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-outline-variant/[0.08] text-[10px] uppercase tracking-wider text-outline px-6">
                      <th className="pb-3 pt-4 pl-6">Cible</th>
                      <th className="pb-3 pt-4">Type</th>
                      <th className="pb-3 pt-4">Fréquence</th>
                      <th className="pb-3 pt-4">Prochaine exécution</th>
                      <th className="pb-3 pt-4">Dernière exécution</th>
                      <th className="pb-3 pt-4 text-center">Statut</th>
                      <th className="pb-3 pt-4 pr-6 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-outline-variant/[0.06] text-xs">
                    {scheduledScans.map(s => {
                      const isSSL = s.scanMode === 'ssl-only';
                      const targetName = isSSL
                        ? (s.targetDomain || s.repoUrl?.replace('ssl://', '') || s.repositoryName)
                        : s.repositoryName;
                      const frequencyLabels: Record<string, string> = {
                        ONCE: 'Une fois',
                        WEEKLY: 'Hebdomadaire',
                        EVERY_15_DAYS: 'Tous les 15 j.',
                        MONTHLY: 'Mensuel',
                      };
                      const frequencyLabel = frequencyLabels[s.scheduleType] || s.scheduleType;

                      const nextRunStr = s.nextRunAt
                        ? new Date(s.nextRunAt).toLocaleString('fr-FR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })
                        : '—';
                      const lastRunStr = s.lastRunAt
                        ? new Date(s.lastRunAt).toLocaleString('fr-FR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })
                        : '—';

                      const statusConfig: Record<string, { cls: string; dot: string; label: string }> = {
                        ACTIVE:    { cls: 'bg-tertiary/10 border-tertiary/20 text-tertiary', dot: 'bg-tertiary', label: 'Actif' },
                        RUNNING:   { cls: 'bg-primary/10 border-primary/20 text-primary', dot: 'bg-primary animate-pulse', label: 'En cours' },
                        PAUSED:    { cls: 'bg-outline/10 border-outline/20 text-outline', dot: 'bg-outline', label: 'Suspendu' },
                        COMPLETED: { cls: 'bg-secondary/10 border-secondary/20 text-secondary', dot: 'bg-secondary', label: 'Terminé' },
                        FAILED:    { cls: 'bg-error/10 border-error/20 text-error', dot: 'bg-error', label: 'Échoué' },
                      };
                      const sc = statusConfig[s.status] || statusConfig.PAUSED;

                      return (
                        <tr key={s.id} className="hover:bg-surface-container-high/20 group">
                          <td className="py-3 pl-6 font-medium">
                            <div className="flex items-center gap-2.5">
                              <div className={`flex h-7 w-7 items-center justify-center rounded-lg border shrink-0 ${ isSSL ? 'bg-tertiary/10 border-tertiary/20' : 'bg-primary/10 border-primary/20'}`}>
                                <span className={`material-symbols-outlined text-[14px] ${ isSSL ? 'text-tertiary' : 'text-primary'}`} style={{ fontVariationSettings: "'FILL' 1" }}>
                                  {isSSL ? 'lock' : 'folder_special'}
                                </span>
                              </div>
                              <div>
                                <p className="font-headline font-semibold text-sm text-on-surface group-hover:text-primary transition-colors truncate max-w-[160px]">{targetName}</p>
                                {s.branch && !isSSL && <p className="text-[10px] text-outline font-mono">{s.branch}</p>}
                              </div>
                            </div>
                          </td>
                          <td className="py-3">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${ isSSL ? 'bg-tertiary/10 border-tertiary/20 text-tertiary' : 'bg-primary/10 border-primary/20 text-primary'}`}>
                              {isSSL ? 'SSL' : s.scanMode?.toUpperCase() || 'CODE'}
                            </span>
                          </td>
                          <td className="py-3 font-medium text-on-surface-variant">
                            <div className="flex items-center gap-1.5">
                              <span className="material-symbols-outlined text-[14px] text-violet-400">repeat</span>
                              {frequencyLabel}
                            </div>
                          </td>
                          <td className="py-3 text-on-surface-variant font-medium">
                            {nextRunStr}
                          </td>
                          <td className="py-3 text-outline">
                            {lastRunStr}
                          </td>
                          <td className="py-3 text-center">
                            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[9px] font-bold uppercase tracking-wider ${sc.cls}`}>
                              <span className={`h-1.5 w-1.5 rounded-full ${sc.dot}`} />
                              {sc.label}
                            </span>
                          </td>
                          <td className="py-3 pr-6 text-right">
                            <div className="inline-flex items-center gap-1">
                              {s.status === 'ACTIVE' || s.status === 'RUNNING' ? (
                                <button
                                  onClick={() => handlePauseSchedule(s.id)}
                                  title="Suspendre"
                                  className="w-7 h-7 rounded-lg border border-outline-variant/20 flex items-center justify-center hover:bg-amber-500/10 hover:border-amber-500/20 transition-colors"
                                >
                                  <span className="material-symbols-outlined text-outline hover:text-amber-400 text-[14px]">pause</span>
                                </button>
                              ) : s.status === 'PAUSED' ? (
                                <button
                                  onClick={() => handleResumeSchedule(s.id)}
                                  title="Reprendre"
                                  className="w-7 h-7 rounded-lg border border-outline-variant/20 flex items-center justify-center hover:bg-tertiary/10 hover:border-tertiary/20 transition-colors"
                                >
                                  <span className="material-symbols-outlined text-outline hover:text-tertiary text-[14px]">play_arrow</span>
                                </button>
                              ) : null}
                              <button
                                onClick={() => handleDeleteSchedule(s.id)}
                                title="Supprimer"
                                className="w-7 h-7 rounded-lg border border-outline-variant/20 flex items-center justify-center hover:bg-error/10 hover:border-error/20 transition-colors"
                              >
                                <span className="material-symbols-outlined text-outline hover:text-error text-[14px]">delete</span>
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Activity Timeline Log */}
          <div className="glass-panel p-6 rounded-3xl border border-outline-variant/[0.18]">
            <div className="flex justify-between items-center mb-6">
              <h3 className="font-headline text-lg font-bold text-on-surface">Journal d'Activité Récent</h3>
              <Link to="/scans" className="text-xs font-bold text-primary-container uppercase tracking-widest hover:underline">
                Voir l'historique complet
              </Link>
            </div>
            
            <div className="space-y-2 relative">
              {activityTimeline.length === 0 ? (
                <p className="text-center py-6 text-outline text-xs">Aucun scan récent.</p>
              ) : (
                <>
                  <div className="absolute left-[19px] top-4 bottom-4 w-px bg-outline-variant/[0.15]" />
                  {activityTimeline.map((item) => {
                    const date = new Date(item.startedAt);
                    const hours = date.getHours().toString().padStart(2, '0');
                    const mins = date.getMinutes().toString().padStart(2, '0');
                    
                    const isSsl = item.scanMode === 'ssl-only';
                    const targetName = isSsl
                      ? item.targetDomain || item.repoUrl.replace('ssl://', '')
                      : item.repoUrl.split('/').pop()?.replace('.git', '') || 'Dépôt';

                    let iconName = 'sync';
                    let iconColor = 'text-secondary';
                    let borderClass = 'border-secondary';
                    let statusLabel = 'En cours';
                    let badgeClass = 'bg-secondary/10 border-secondary/20 text-secondary';
                    
                    if (item.status === 'COMPLETED') {
                      iconName = 'check_circle';
                      iconColor = 'text-tertiary';
                      borderClass = 'border-tertiary';
                      statusLabel = 'Complété';
                      badgeClass = 'bg-tertiary/10 border-tertiary/20 text-tertiary';
                    } else if (item.status === 'FAILED') {
                      iconName = 'warning';
                      iconColor = 'text-error';
                      borderClass = 'border-error';
                      statusLabel = 'Échec';
                      badgeClass = 'bg-error/10 border-error/20 text-error';
                    } else if (item.status === 'PENDING') {
                      iconName = 'pending';
                      iconColor = 'text-outline';
                      borderClass = 'border-outline-variant';
                      statusLabel = 'En attente';
                      badgeClass = 'bg-surface-container border-outline-variant/[0.3] text-outline';
                    }

                    return (
                      <div key={item.id} className="relative flex items-center gap-6 py-3.5 px-2 hover:bg-surface-container-high/30 rounded-2xl transition-colors group">
                        <div className={`z-10 w-8 h-8 rounded-full bg-surface-container border-2 ${borderClass} flex items-center justify-center`}>
                          <span className={`material-symbols-outlined ${iconColor} text-lg`}>{iconName}</span>
                        </div>
                        <div className="flex-1 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div>
                            <p className="text-sm font-semibold text-on-surface">
                              {isSsl ? `Audit SSL de ${targetName}` : `Scan de vulnérabilité : ${targetName}`}
                            </p>
                            <p className="text-[11px] text-outline">
                              Débuté à {hours}:{mins} • Type : {isSsl ? 'SSL/TLS' : `Dépôt (mode ${item.scanMode})`}
                            </p>
                          </div>
                          
                          <div className="flex items-center gap-3 self-start sm:self-auto shrink-0">
                            {!isSsl && item.status === 'COMPLETED' && (
                              <span className="text-[10px] font-mono font-bold text-on-surface-variant bg-surface-container border border-outline-variant/[0.12] rounded px-1.5 py-0.5">
                                {item.cveCount} CVEs • {item.secretCount} Sec
                              </span>
                            )}
                            <span className={`px-2.5 py-0.5 text-[9px] font-headline font-bold uppercase rounded-full border ${badgeClass}`}>
                              {statusLabel}
                            </span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;
