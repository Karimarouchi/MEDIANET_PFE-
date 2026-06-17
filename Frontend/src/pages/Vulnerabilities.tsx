import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import {
  getCvesByScan, getAllScans, requestFix, applyFix, getSecretsByScan, getSastByScan, getAiSummary, getSbomByScan,
  getComplianceResults,
  type CveDto, type ScanResultDto, type FixPreviewResponse, type SecretDto, type SastDto, type SbomComponent,
  type ComplianceResponse,
} from '../services/api';

/* ── helpers ── */

function secretSeverity(ruleId: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' {
  const id = (ruleId || '').toLowerCase();
  if (/aws|azure|gcp|private.?key|github.?token|stripe|twilio|jwt.?secret/.test(id)) return 'CRITICAL';
  if (/generic.?api.?key|password|credential/.test(id)) return 'HIGH';
  return 'MEDIUM';
}

const SECRET_SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-error-container text-on-error-container',
  HIGH: 'bg-secondary-container text-on-secondary-container',
  MEDIUM: 'bg-surface-variant text-on-surface-variant',
};

const SECRET_SEVERITY_DOT: Record<string, string> = {
  CRITICAL: 'bg-error',
  HIGH: 'bg-secondary',
  MEDIUM: 'bg-outline',
};

// OWASP category colour coding
const OWASP_COLORS: Record<string, string> = {
  'A01': 'text-error border-error/30 bg-error/5',
  'A02': 'text-secondary border-secondary/30 bg-secondary/5',
  'A03': 'text-error border-error/30 bg-error/5',
  'A04': 'text-tertiary border-tertiary/30 bg-tertiary/5',
  'A05': 'text-secondary border-secondary/30 bg-secondary/5',
  'A06': 'text-error border-error/30 bg-error/5',
  'A07': 'text-error border-error/30 bg-error/5',
  'A08': 'text-secondary border-secondary/30 bg-secondary/5',
  'A09': 'text-on-surface-variant border-outline-variant/30 bg-surface-variant/20',
  'A10': 'text-tertiary border-tertiary/30 bg-tertiary/5',
};
function owaspColor(category: string) {
  for (const key of Object.keys(OWASP_COLORS)) {
    if (category.includes(key)) return OWASP_COLORS[key];
  }
  return 'text-on-surface-variant border-outline-variant/30 bg-surface-variant/20';
}

function severityBadge(severity: string) {
  switch (severity) {
    case 'CRITICAL': return 'bg-error-container text-on-error-container';
    case 'HIGH': return 'bg-secondary-container text-on-secondary-container';
    case 'MEDIUM': return 'bg-surface-variant text-on-surface-variant';
    case 'LOW': return 'bg-tertiary-container text-on-tertiary-container';
    default: return 'bg-surface-container text-outline';
  }
}
function severityBorder(severity: string) {
  switch (severity) {
    case 'CRITICAL': return 'border-error/[0.3] text-error';
    case 'HIGH': return 'border-secondary/[0.3] text-secondary';
    case 'MEDIUM': return 'border-outline-variant/[0.3] text-on-surface-variant';
    case 'LOW': return 'border-tertiary/[0.3] text-tertiary';
    default: return 'border-outline-variant/[0.3] text-outline';
  }
}
function detailBorderColor(severity: string) {
  switch (severity) {
    case 'CRITICAL': return 'border-error/[0.2]';
    case 'HIGH': return 'border-secondary/[0.2]';
    case 'MEDIUM': return 'border-outline-variant/[0.2]';
    case 'LOW': return 'border-tertiary/[0.2]';
    default: return 'border-outline-variant/[0.2]';
  }
}
function severityLabel(severity: string) {
  switch (severity) {
    case 'CRITICAL': return { color: 'text-error', label: 'Critical Vulnerability' };
    case 'HIGH': return { color: 'text-secondary', label: 'High Vulnerability' };
    case 'MEDIUM': return { color: 'text-on-surface-variant', label: 'Medium Vulnerability' };
    case 'LOW': return { color: 'text-tertiary', label: 'Low Vulnerability' };
    default: return { color: 'text-outline', label: 'Unknown Severity' };
  }
}

function repoName(url: string) {
  if (!url) return 'Unknown';
  return url.replace(/\.git$/, '').split('/').pop() || url;
}

/** Estimated fix time based on severity and threat context. */
function estimatedFixTime(cve: CveDto): string {
  if (cve.kevListed || (cve.exploitAvailable && cve.severity === 'CRITICAL')) return '< 24h ⚠️';
  if (cve.severity === 'CRITICAL') return '1–3 jours';
  if (cve.severity === 'HIGH' && cve.exploitAvailable) return '3–5 jours';
  if (cve.severity === 'HIGH') return '1–2 semaines';
  if (cve.severity === 'MEDIUM') return '2–4 semaines';
  if (cve.severity === 'LOW') return '1–3 mois';
  return 'À planifier';
}

/** Returns color classes and label based on EPSS score (0–1). */
function epssInfo(score: number | null): { bar: string; text: string; label: string } {
  if (score === null || score === undefined) return { bar: 'bg-slate-300', text: 'text-slate-400', label: 'N/A' };
  if (score >= 0.7) return { bar: 'bg-red-500', text: 'text-red-500', label: 'Très élevé' };
  if (score >= 0.3) return { bar: 'bg-orange-500', text: 'text-orange-500', label: 'Élevé' };
  if (score >= 0.05) return { bar: 'bg-yellow-500', text: 'text-yellow-600', label: 'Modéré' };
  return { bar: 'bg-slate-400', text: 'text-slate-400', label: 'Faible' };
}

function calcPriority(cve: CveDto): { score: number; label: string; emoji: string; color: string; bgClass: string } {
  // CISA KEV = actively exploited in the real world → always URGENT
  if (cve.kevListed) {
    return { score: 1.0, label: 'URGENT', emoji: '🔴', color: 'text-red-500', bgClass: 'bg-red-500/15 border border-red-500/30' };
  }

  const cvssNorm = (cve.cvssScore ?? 0) / 10;
  const epss     = cve.epssScore ?? 0;
  const exploit  = cve.exploitAvailable ? 1 : 0;

  // Multi-tool confirmation bonus: 3+ tools → +0.15, 2 tools → +0.10
  // Accounts for Trivy + Grype + OSV-Scanner cross-validation
  const confirmedBy   = cve.confirmedBy ?? 1;
  const confirmBonus  = confirmedBy >= 3 ? 0.15 : confirmedBy >= 2 ? 0.10 : 0;

  // Weighted composite score
  //   CVSS 45% — severity is the primary signal
  //   EPSS 30% — real-world exploitation probability (FIRST.org)
  //   Exploit 20% — public exploit available (Exploit-DB)
  //   Confirmation up to +15% — cross-validated by multiple scanners
  const score = (cvssNorm * 0.45) + (epss * 0.30) + (exploit * 0.20) + confirmBonus;

  // Thresholds
  let label: string;
  if      (score >= 0.65) label = 'URGENT';
  else if (score >= 0.40) label = 'ÉLEVÉ';
  else if (score >= 0.25) label = 'MOYEN';
  else                    label = 'FAIBLE';

  // Severity floor — a CRITICAL CVE can never be below ÉLEVÉ,
  // a HIGH CVE can never be FAIBLE (even when EPSS data is missing)
  const sev = (cve.severity ?? '').toUpperCase();
  if (sev === 'CRITICAL' && (label === 'MOYEN' || label === 'FAIBLE')) label = 'ÉLEVÉ';
  if (sev === 'HIGH'     && label === 'FAIBLE')                        label = 'MOYEN';

  if (label === 'URGENT') return { score, label, emoji: '🔴', color: 'text-red-500',    bgClass: 'bg-red-500/15 border border-red-500/30' };
  if (label === 'ÉLEVÉ')  return { score, label, emoji: '🟠', color: 'text-orange-500', bgClass: 'bg-orange-500/15 border border-orange-500/30' };
  if (label === 'MOYEN')  return { score, label, emoji: '🟡', color: 'text-yellow-500', bgClass: 'bg-yellow-500/15 border border-yellow-500/30' };
  return                         { score, label: 'FAIBLE', emoji: '🟢', color: 'text-slate-400', bgClass: 'bg-slate-500/10 border border-slate-500/20' };
}

type FindingType = 'CVE' | 'GHSA' | 'CWE' | 'CODE';

function inferGitProvider(repoUrl: string, provider?: string): 'GITHUB' | 'GITLAB' {
  if (provider === 'GITLAB' || repoUrl?.includes('gitlab.com')) {
    return 'GITLAB';
  }
  return 'GITHUB';
}

/** Extract owner/repo or group/project from a GitHub/GitLab repo URL */
function extractRepoFullName(repoUrl: string, provider?: string): string | null {
  const gitProvider = inferGitProvider(repoUrl, provider);
  if (gitProvider === 'GITLAB') {
    const httpsMatch = repoUrl?.match(/gitlab\.com\/([^?#]+?)(?:\.git)?(?:\/.*)?$/);
    if (httpsMatch) return httpsMatch[1].replace(/\/$/, '');
    const sshMatch = repoUrl?.match(/git@gitlab\.com:([^#?]+?)(?:\.git)?$/);
    if (sshMatch) return sshMatch[1].replace(/\/$/, '');
    return null;
  }

  const httpsMatch = repoUrl?.match(/github\.com\/([^/]+\/[^/.]+?)(?:\.git)?(?:\/.*)?$/);
  if (httpsMatch) return httpsMatch[1];
  const sshMatch = repoUrl?.match(/git@github\.com:([^/]+\/[^/]+?)(?:\.git)?$/);
  if (sshMatch) return sshMatch[1];
  return null;
}

type DiffLine = { type: 'unchanged' | 'removed' | 'added'; line: string; lineNo: number };

/**
 * Produce a unified-style diff using Myers / LCS algorithm.
 * This correctly handles insertions, deletions, and modifications
 * without scrambling the output when lines shift.
 */
function computeDiff(original: string[], fixed: string[]): DiffLine[] {
  const n = original.length;
  const m = fixed.length;

  // Build LCS table
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      dp[i][j] = original[i - 1] === fixed[j - 1]
        ? dp[i - 1][j - 1] + 1
        : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }

  // Backtrack to produce diff
  const result: DiffLine[] = [];
  let i = n, j = m;
  const stack: DiffLine[] = [];
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && original[i - 1] === fixed[j - 1]) {
      stack.push({ type: 'unchanged', line: original[i - 1], lineNo: 0 });
      i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      stack.push({ type: 'added', line: fixed[j - 1], lineNo: 0 });
      j--;
    } else {
      stack.push({ type: 'removed', line: original[i - 1], lineNo: 0 });
      i--;
    }
  }
  stack.reverse();

  // Assign line numbers: removed lines count in original, added in fixed, unchanged in both
  let origLine = 1, fixLine = 1;
  for (const entry of stack) {
    if (entry.type === 'removed') {
      entry.lineNo = origLine++;
    } else if (entry.type === 'added') {
      entry.lineNo = fixLine++;
    } else {
      entry.lineNo = fixLine++;
      origLine++;
    }
    result.push(entry);
  }

  return result;
}
function findingType(cve: { cveId: string; source: string }): FindingType {
  if (cve.cveId?.startsWith('CVE-')) return 'CVE';
  if (cve.cveId?.startsWith('GHSA-')) return 'GHSA';
  if (cve.cveId?.startsWith('CWE-')) return 'CWE';
  return 'CODE';
}
function findingCategory(type: FindingType): { label: string; icon: string; color: string } {
  switch (type) {
    case 'CVE': return { label: 'Dependency Vulnerability', icon: 'package_2', color: 'text-secondary' };
    case 'GHSA': return { label: 'Security Advisory', icon: 'shield', color: 'text-primary' };
    case 'CWE': return { label: 'Code Security Issue', icon: 'code', color: 'text-[#FFBD2E]' };
    case 'CODE': return { label: 'Code Security Issue', icon: 'code', color: 'text-[#FFBD2E]' };
  }
}

interface LogLine { time: string; prefix: string; text: string; }

function parseLogLine(raw: string): LogLine {
  const time = new Date().toTimeString().slice(0, 8);
  const prefixes = ['[SYSTEM]', '[SUCCESS]', '[SCAN]', '[WARN]', '[ERROR]', '[INFO]'];
  for (const p of prefixes) {
    if (raw.includes(p)) return { time, prefix: p, text: raw.replace(p, '').trim() };
  }
  // Try to parse timestamp from scanner output like [2026-04-10 12:34:09]
  const tsMatch = raw.match(/^\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s*(.*)/);
  if (tsMatch) return { time: tsMatch[1].split(' ')[1], prefix: '[SCAN]', text: tsMatch[2] };
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

/* ── component ── */

const Vulnerabilities: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const scanIdParam = searchParams.get('scanId');

  const [allScans, setAllScans] = useState<ScanResultDto[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(scanIdParam ? Number(scanIdParam) : null);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [scanClientFilter, setScanClientFilter] = useState('ALL');
  const [activeTab, setActiveTab] = useState<'cve' | 'findings' | 'sbom' | 'evolution' | 'compliance'>('cve');

  const [cves, setCves] = useState<CveDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<CveDto | null>(null);

  const [secrets, setSecrets] = useState<SecretDto[]>([]);
  const [secretsLoading, setSecretsLoading] = useState(false);
  const [expandedSecret, setExpandedSecret] = useState<number | null>(null);

  const [sastFindings, setSastFindings] = useState<SastDto[]>([]);
  const [sastLoading, setSastLoading] = useState(false);
  const [expandedOwasp, setExpandedOwasp] = useState<string | null>(null);

  const [sbomComponents, setSbomComponents] = useState<SbomComponent[]>([]);
  const [sbomLoading, setSbomLoading] = useState(false);
  const [sbomSearch, setSbomSearch] = useState('');
  const [sbomFilter, setSbomFilter] = useState<'all' | 'with-cve' | 'without-cve'>('all');
  const [sbomEcosystem, setSbomEcosystem] = useState('');
  const [sbomSelectedPkg, setSbomSelectedPkg] = useState<SbomComponent | null>(null);

  // Idée 2 — Compliance (OpenSCAP) state
  const [complianceData, setComplianceData] = useState<ComplianceResponse | null>(null);
  const [complianceLoading, setComplianceLoading] = useState(false);
  const [complianceFilter, setComplianceFilter] = useState<'all' | 'fail' | 'pass'>('all');

  // Live logs state
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [scanRunning, setScanRunning] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const currentStatusRef = useRef<string | null>(null);

  // AI summary state (Q1)
  const [aiSummaryOpen, setAiSummaryOpen] = useState(false);
  const [aiSummary, setAiSummary] = useState<string | null>(null);
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false);

  // Auto-fix state
  const [fixLoading, setFixLoading] = useState(false);
  const [fixError, setFixError] = useState<string | null>(null);
  const [fixPreview, setFixPreview] = useState<(FixPreviewResponse & { repoFullName: string }) | null>(null);
  const [applyLoading, setApplyLoading] = useState(false);
  const [applySuccess, setApplySuccess] = useState<string | null>(null);
  const [fixedCveIds, setFixedCveIds] = useState<Set<number>>(new Set());

  const currentScan = allScans.find(s => s.id === selectedScanId);
  const scanClientOptions = React.useMemo(
    () => Array.from(new Set(allScans.flatMap((scan) => scan.clientNames ?? []))).sort(),
    [allScans]
  );
  const visibleScans = React.useMemo(
    () => allScans.filter((scan) => scanClientFilter === 'ALL' || (scan.clientNames ?? []).includes(scanClientFilter)),
    [allScans, scanClientFilter]
  );

  // Group CVEs by same package + version + file so one fix resolves them all
  const fixGroups = React.useMemo(() => {
    const map = new Map<string, CveDto[]>();
    for (const cve of cves) {
      if (!cve.packageName || !cve.fixedVersion) continue;
      const key = `${cve.packageName}|${cve.packageVersion ?? ''}|${cve.filePath ?? ''}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(cve);
    }
    return map;
  }, [cves]);

  // Fetch all scans
  useEffect(() => {
    const fetchScans = async () => {
      try {
        const res = await getAllScans();
        setAllScans(res.data);
        setSelectedScanId((currentSelectedScanId) => currentSelectedScanId ?? (res.data[0]?.id ?? null));
      } catch (err) {
        console.error('Failed to fetch scans', err);
      }
    };
    fetchScans();
    const interval = setInterval(fetchScans, 10000);
    return () => clearInterval(interval);
  }, []);

  // When scanId param changes, update selection
  useEffect(() => {
    if (scanIdParam) setSelectedScanId(Number(scanIdParam));
  }, [scanIdParam]);

  // Detect status change for selected scan and trigger load only when needed
  const selectedScanStatus = currentScan?.status || null;

  // Derived flag: show logs when scan is running OR status not yet known
  const showLogs = scanRunning || selectedScanStatus === 'RUNNING' || (selectedScanId != null && !selectedScanStatus);

  useEffect(() => {
    if (!selectedScanId) { setLoading(false); return; }

    // Don't proceed until we know the actual scan status
    if (!selectedScanStatus) { setLoading(true); return; }

    // Skip if same scan + same status (no real change)
    const statusKey = `${selectedScanId}-${selectedScanStatus}`;
    if (currentStatusRef.current === statusKey) return;
    currentStatusRef.current = statusKey;

    // Cleanup previous SSE
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }

    if (selectedScanStatus === 'RUNNING') {
      // Connect to SSE for live logs
      setScanRunning(true);
      setLogs([]);
      setCves([]);
      setSelected(null);
      setLoading(false);

      const token = localStorage.getItem('vulnix_token') ?? '';
      const evtSource = new EventSource(`http://localhost:8080/api/scans/${selectedScanId}/logs?token=${encodeURIComponent(token)}`);
      eventSourceRef.current = evtSource;

      evtSource.onmessage = (event) => {
        const raw = event.data;
        if (raw === '%%SCAN_COMPLETE%%') {
          evtSource.close();
          eventSourceRef.current = null;
          setScanRunning(false);
          currentStatusRef.current = null; // force reload on next poll
          loadCves(selectedScanId);
          loadSecrets(selectedScanId);
          loadSast(selectedScanId);
          loadSbom(selectedScanId);
          return;
        }
        setLogs(prev => [...prev, parseLogLine(raw)]);
      };

      evtSource.onerror = () => {
        evtSource.close();
        eventSourceRef.current = null;
        setScanRunning(false);
        currentStatusRef.current = null;
        loadCves(selectedScanId);
        loadSecrets(selectedScanId);
        loadSast(selectedScanId);
        loadSbom(selectedScanId);
      };
    } else if (selectedScanStatus === 'COMPLETED' || selectedScanStatus === 'FAILED') {
      setScanRunning(false);
      setLogs([]);
      loadCves(selectedScanId);
      loadSecrets(selectedScanId);
      loadSast(selectedScanId);
      loadSbom(selectedScanId);
    }

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [selectedScanId, selectedScanStatus]);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Reload SBOM when user switches to sbom tab and data is missing
  useEffect(() => {
    if (activeTab === 'sbom' && selectedScanId && sbomComponents.length === 0 && !sbomLoading) {
      loadSbom(selectedScanId);
    }
  }, [activeTab, sbomComponents.length, sbomLoading, selectedScanId]);

  // Idée 2 — Load compliance data when user switches to compliance tab
  useEffect(() => {
    if (activeTab === 'compliance' && selectedScanId && !complianceData && !complianceLoading) {
      loadCompliance(selectedScanId);
    }
  }, [activeTab, selectedScanId, complianceData, complianceLoading]);

  const loadCves = async (scanId: number) => {
    setLoading(true);
    setAiSummary(null);
    setAiSummaryOpen(false);
    try {
      const res = await getCvesByScan(scanId);
      setCves(res.data);
      if (res.data.length > 0) setSelected(res.data[0]);
      else setSelected(null);
      // Load AI summary in background (Q1)
      if (res.data.length > 0) {
        setAiSummaryLoading(true);
        getAiSummary(scanId)
          .then(r => setAiSummary(r.data.summary || null))
          .catch(() => setAiSummary(null))
          .finally(() => setAiSummaryLoading(false));
      }
    } catch (err) {
      console.error('Failed to fetch CVEs', err);
      setCves([]);
    } finally {
      setLoading(false);
    }
  };

  const loadSecrets = async (scanId: number) => {
    setSecretsLoading(true);
    try {
      const res = await getSecretsByScan(scanId);
      setSecrets(res.data);
    } catch (err) {
      console.error('Failed to fetch secrets', err);
      setSecrets([]);
    } finally {
      setSecretsLoading(false);
    }
  };

  const loadSast = async (scanId: number) => {
    setSastLoading(true);
    try {
      const res = await getSastByScan(scanId);
      setSastFindings(res.data);
    } catch (err) {
      console.error('Failed to fetch SAST', err);
      setSastFindings([]);
    } finally {
      setSastLoading(false);
    }
  };

  const loadSbom = async (scanId: number) => {
    setSbomLoading(true);
    try {
      const res = await getSbomByScan(scanId);
      setSbomComponents(res.data);
    } catch (err) {
      console.error('Failed to fetch SBOM', err);
      setSbomComponents([]);
    } finally {
      setSbomLoading(false);
    }
  };

  // Idée 2 — Load OpenSCAP compliance results
  const loadCompliance = async (scanId: number) => {
    setComplianceLoading(true);
    try {
      const res = await getComplianceResults(scanId);
      setComplianceData(res.data);
    } catch (err) {
      console.error('Failed to fetch compliance results', err);
      setComplianceData(null);
    } finally {
      setComplianceLoading(false);
    }
  };

  const handleRequestFix = async (cve: CveDto) => {
    if (!currentScan) return;
    const provider = inferGitProvider(currentScan.repoUrl, currentScan.gitProvider);
    const repoFullName = extractRepoFullName(currentScan.repoUrl, provider);
    if (!repoFullName) {
      setFixError('Impossible de détecter le dépôt Git depuis l\'URL de scan.');
      return;
    }
    setFixLoading(true);
    setFixError(null);
    setFixPreview(null);
    setApplySuccess(null);
    try {
      // Compute group fix: pick the highest version that fixes ALL CVEs for this package+file
      const grpKey = cve.packageName && cve.fixedVersion
        ? `${cve.packageName}|${cve.packageVersion ?? ''}|${cve.filePath ?? ''}`
        : null;
      const group = grpKey ? (fixGroups.get(grpKey) ?? [cve]) : [cve];
      const allVersions = group
        .flatMap(c => (c.fixedVersion ?? '').split(/[,;]/).map((v: string) => v.trim()).filter(Boolean));
      const curMajor = (cve.packageVersion ?? '').split('.')[0];
      const sortedVersions = allVersions.sort((a, b) => {
        const ap = a.split('.').map(Number), bp = b.split('.').map(Number);
        for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
          const d = (bp[i] ?? 0) - (ap[i] ?? 0);
          if (d !== 0) return d;
        }
        return 0;
      });
      const fixedVer = sortedVersions.find((v: string) => v.split('.')[0] === curMajor) || sortedVersions[0] || '';

      // Pass filePath hint to backend — it will use GitHub Tree API to auto-discover the actual path
      const res = await requestFix({
        repoFullName,
        packageName: cve.packageName,
        currentVersion: cve.packageVersion,
        fixedVersion: fixedVer,
        cveId: cve.cveId,
        filePath: cve.filePath,
        source: cve.source,
        provider,
      });
      setFixPreview({ ...res.data, repoFullName });
    } catch (err: any) {
      let msg = err?.response?.data?.error || err?.message || 'Erreur lors de la génération du correctif.';
      setFixError(msg);
    } finally {
      setFixLoading(false);
    }
  };

  const handleApplyFix = async () => {
    if (!fixPreview || !selected) return;
    setApplyLoading(true);
    try {
      const provider = currentScan ? inferGitProvider(currentScan.repoUrl, currentScan.gitProvider) : 'GITHUB';
      // Compute fix group to build accurate commit message and mark all related CVEs fixed
      const grpKey = selected.packageName && selected.fixedVersion
        ? `${selected.packageName}|${selected.packageVersion ?? ''}|${selected.filePath ?? ''}`
        : null;
      const grp = grpKey ? (fixGroups.get(grpKey) ?? [selected]) : [selected];
      const allV = grp.flatMap(c => (c.fixedVersion ?? '').split(/[,;]/).map((v: string) => v.trim()).filter(Boolean));
      const maxFix = allV.sort((a, b) => {
        const ap = a.split('.').map(Number), bp = b.split('.').map(Number);
        for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
          const d = (bp[i] ?? 0) - (ap[i] ?? 0);
          if (d !== 0) return d;
        }
        return 0;
      })[0] || selected.fixedVersion || '';
      const cveLabel = grp.length > 1
        ? grp.map(c => c.cveId).filter(Boolean).join(', ')
        : (selected.cveId ?? '');
      const res = await applyFix({
        repoFullName: fixPreview.repoFullName,
        filePath: fixPreview.filePath,
        sha: fixPreview.sha,
        fixedContent: fixPreview.fixedContent,
        commitMessage: `fix: patch ${cveLabel} — update ${selected.packageName} to ${maxFix}`,
        provider,
        branch: currentScan?.branch ?? null,
        lockFilePath: fixPreview.lockFilePath ?? null,
        lockFileSha: fixPreview.lockFileSha ?? null,
        lockFileContent: fixPreview.lockFileContent ?? null,
      });
      setApplySuccess(res.data.commitUrl || 'Commit appliqué avec succès.');
      // Mark all CVEs in this group as fixed in the UI
      setFixedCveIds(prev => {
        const next = new Set(prev);
        grp.forEach(c => { if (c.id != null) next.add(c.id); });
        return next;
      });
    } catch (err: any) {
      const msg = err?.response?.data?.error || err?.message || 'Erreur lors de l\'application du correctif.';
      setFixError(msg);
    } finally {
      setApplyLoading(false);
    }
  };

  const handleScanSelect = (scanId: number) => {    setSelectedScanId(scanId);
    setSearchParams({ scanId: String(scanId) });
    setDropdownOpen(false);
    setFilter('ALL');
    setSearch('');
    setActiveTab('cve');
    setSecrets([]);
    setSastFindings([]);
    setSbomComponents([]);
    setSbomSelectedPkg(null);
    setSbomSearch('');
    setSbomFilter('all');
    setSbomEcosystem('');
    setExpandedSecret(null);
    setExpandedOwasp(null);
    // Idée 2 — Reset compliance data on scan change
    setComplianceData(null);
    setComplianceFilter('all');
  };

  const exportPdf = () => {
    const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });
    const repo = currentScan ? repoName(currentScan.repoUrl) : 'Unknown';
    const now = new Date().toLocaleString('fr-FR');

    // Title
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 30, 40);
    doc.text('Vulnerability Report', 14, 20);

    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 100, 120);
    doc.text(`Repository: ${repo}  |  Scan #${selectedScanId}  |  Generated: ${now}`, 14, 28);

    // Summary badges
    const summaryY = 36;
    const summaryItems: { label: string; count: number; color: [number, number, number] }[] = [
      { label: 'TOTAL', count: counts.ALL, color: [60, 60, 80] },
      { label: 'CRITICAL', count: counts.CRITICAL, color: [220, 38, 38] },
      { label: 'HIGH', count: counts.HIGH, color: [234, 88, 12] },
      { label: 'MEDIUM', count: counts.MEDIUM, color: [161, 130, 0] },
      { label: 'LOW', count: counts.LOW, color: [100, 116, 139] },
    ];
    let x = 14;
    summaryItems.forEach(item => {
      doc.setFillColor(...item.color);
      doc.roundedRect(x, summaryY, 42, 12, 2, 2, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(8.5);
      doc.setFont('helvetica', 'bold');
      doc.text(`${item.label}: ${item.count}`, x + 3, summaryY + 7.5);
      x += 48;
    });

    // Table
    const flagsByRow: Record<number, string[]> = {};

    const rows = filtered.map((cve, idx) => {
      const p = calcPriority(cve);
      const flags: string[] = [];
      if (cve.kevListed)        flags.push('CISA KEV');
      if (cve.exploitAvailable) flags.push('EXPLOIT');
      if (cve.confirmedBy >= 2) flags.push('CONFIRMÉ');
      flagsByRow[idx] = flags;
      return [
        cve.cveId || '\u2014',
        cve.severity,
        cve.cvssScore?.toFixed(1) || '\u2014',
        cve.epssScore != null ? `${(cve.epssScore * 100).toFixed(1)}%` : '\u2014',
        `${cve.packageName || '\u2014'}${cve.packageVersion ? ' @' + cve.packageVersion : ''}`,
        p.label,
        cve.source?.toUpperCase() || '\u2014',
        (cve.description || '').slice(0, 95) + ((cve.description?.length ?? 0) > 95 ? '\u2026' : ''),
      ];
    });

    const badgeDef: Record<string, { color: [number, number, number]; w: number }> = {
      'CISA KEV': { color: [245, 158,  11], w: 18 },
      'EXPLOIT':  { color: [220,  38,  38], w: 16 },
      'CONFIRMÉ': { color: [ 16, 185, 129], w: 19 },
    };

    autoTable(doc, {
      startY: summaryY + 18,
      head: [['CVE / ID', 'Severity', 'CVSS', 'EPSS', 'Package', 'Priority', 'Source', 'Description']],
      body: rows,
      styles: { fontSize: 7.5, cellPadding: 2.5, overflow: 'linebreak', minCellHeight: 18 },
      headStyles: { fillColor: [30, 30, 50], textColor: [255, 255, 255], fontStyle: 'bold', fontSize: 8 },
      columnStyles: {
        0: { cellWidth: 34, fontStyle: 'bold' },
        1: { cellWidth: 22, halign: 'center' },
        2: { cellWidth: 13, halign: 'center' },
        3: { cellWidth: 15, halign: 'center' },
        4: { cellWidth: 40 },
        5: { cellWidth: 18, halign: 'center' },
        6: { cellWidth: 18 },
        7: { cellWidth: 'auto' },
      },
      didParseCell: (data) => {
        if (data.section !== 'body') return;
        if (data.column.index === 1) {
          const val = data.cell.raw as string;
          if (val === 'CRITICAL') { data.cell.styles.textColor = [220, 38, 38]; data.cell.styles.fontStyle = 'bold'; }
          else if (val === 'HIGH')     { data.cell.styles.textColor = [234, 88, 12]; data.cell.styles.fontStyle = 'bold'; }
          else if (val === 'MEDIUM')   { data.cell.styles.textColor = [161, 130, 0]; }
          else if (val === 'LOW')      { data.cell.styles.textColor = [100, 116, 139]; }
        }
        if (data.column.index === 5) {
          const val = data.cell.raw as string;
          if (val === 'URGENT')        { data.cell.styles.textColor = [220, 38, 38]; data.cell.styles.fontStyle = 'bold'; }
          else if (val === '\u00c9LEV\u00c9') { data.cell.styles.textColor = [234, 88, 12]; data.cell.styles.fontStyle = 'bold'; }
          else if (val === 'MOYEN')    { data.cell.styles.textColor = [161, 130, 0]; }
          else if (val === 'FAIBLE')   { data.cell.styles.textColor = [100, 116, 139]; }
        }
      },
      didDrawCell: (data) => {
        if (data.section !== 'body' || data.column.index !== 0) return;
        const flags = flagsByRow[data.row.index] || [];
        if (flags.length === 0) return;

        const bh = 4.2;
        const rowH = bh + 2;
        const padding = data.cell.padding('left');
        const maxX = data.cell.x + data.cell.width - padding;

        // Text occupies ~5.5mm (font 7.5), badges start below it
        let bx = data.cell.x + padding;
        let by = data.cell.y + 7;

        flags.forEach(flag => {
          const def = badgeDef[flag];
          if (!def) return;

          // Wrap to next row if badge doesn't fit
          if (bx + def.w > maxX) {
            bx = data.cell.x + padding;
            by += rowH;
          }

          const [r, g, b] = def.color;
          doc.setFillColor(r, g, b);
          doc.roundedRect(bx, by, def.w, bh, 1.2, 1.2, 'F');
          doc.setTextColor(255, 255, 255);
          doc.setFontSize(5.4);
          doc.setFont('helvetica', 'bold');
          doc.text(flag, bx + def.w / 2, by + bh - 1.1, { align: 'center' });
          bx += def.w + 1.8;
        });

        // Reset state
        doc.setTextColor(30, 30, 50);
        doc.setFillColor(255, 255, 255);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
      },
      alternateRowStyles: { fillColor: [247, 247, 252] },
      margin: { left: 14, right: 14 },
    });

    // Footer on each page
    const pageCount = (doc as any).internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(7);
      doc.setTextColor(160, 160, 170);
      doc.setFont('helvetica', 'normal');
      doc.text(
        `Vulnix Security Scanner  —  ${repo}  —  Page ${i} / ${pageCount}`,
        doc.internal.pageSize.getWidth() / 2,
        doc.internal.pageSize.getHeight() - 7,
        { align: 'center' }
      );
    }

    doc.save(`vulnix-report-${repo}-scan${selectedScanId}.pdf`);
  };

  const PRIORITY_ORDER: Record<string, number> = { 'URGENT': 0, 'ÉLEVÉ': 1, 'MOYEN': 2, 'FAIBLE': 3 };
  const SEVERITY_ORDER: Record<string, number> = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };

  const filtered = cves
    .filter(c => {
      const matchFilter = filter === 'ALL' || c.severity === filter;
      const matchSearch = !search ||
        c.cveId?.toLowerCase().includes(search.toLowerCase()) ||
        c.packageName?.toLowerCase().includes(search.toLowerCase()) ||
        c.description?.toLowerCase().includes(search.toLowerCase());
      return matchFilter && matchSearch;
    })
    .sort((a, b) => {
      const pa = calcPriority(a);
      const pb = calcPriority(b);
      const pDiff = (PRIORITY_ORDER[pa.label] ?? 4) - (PRIORITY_ORDER[pb.label] ?? 4);
      if (pDiff !== 0) return pDiff;
      const sDiff = (SEVERITY_ORDER[a.severity ?? ''] ?? 4) - (SEVERITY_ORDER[b.severity ?? ''] ?? 4);
      if (sDiff !== 0) return sDiff;
      return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
    });

  const counts = {
    ALL: cves.length,
    CRITICAL: cves.filter(c => c.severity === 'CRITICAL').length,
    HIGH: cves.filter(c => c.severity === 'HIGH').length,
    MEDIUM: cves.filter(c => c.severity === 'MEDIUM').length,
    LOW: cves.filter(c => c.severity === 'LOW').length,
  };

  // AI priority distribution (Q1)
  const priorityCounts = React.useMemo(() => {
    let urgent = 0, eleve = 0, moyen = 0, faible = 0;
    cves.forEach(c => {
      const p = calcPriority(c);
      if (p.label === 'URGENT') urgent++;
      else if (p.label === 'ÉLEVÉ') eleve++;
      else if (p.label === 'MOYEN') moyen++;
      else faible++;
    });
    return { urgent, eleve, moyen, faible };
  }, [cves]);

  // Batch-fix group for the currently selected CVE
  const selectedGroup: CveDto[] = (() => {
    if (!selected?.packageName || !selected?.fixedVersion) return selected ? [selected] : [];
    const key = `${selected.packageName}|${selected.packageVersion ?? ''}|${selected.filePath ?? ''}`;
    return fixGroups.get(key) ?? [selected];
  })();
  const groupCount = selectedGroup.length;
  const groupMaxFix = (() => {
    const allV = selectedGroup.flatMap(c =>
      (c.fixedVersion ?? '').split(/[,;]/).map((v: string) => v.trim()).filter(Boolean)
    );
    if (!allV.length) return '';
    return allV.sort((a, b) => {
      const ap = a.split('.').map(Number), bp = b.split('.').map(Number);
      for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
        const d = (bp[i] ?? 0) - (ap[i] ?? 0);
        if (d !== 0) return d;
      }
      return 0;
    })[0];
  })();

  return (
    <div className="flex flex-col lg:flex-row lg:items-start -mx-8 min-h-screen">
      {/* Main Section */}
      <section className="flex-1 p-6 overflow-hidden">
        {/* Header with Scan Selector */}
        <header className="mb-8 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold font-headline text-on-surface tracking-tight mb-2">Vulnerability Matrix</h1>
            <p className="text-on-surface-variant text-sm max-w-2xl">
              {showLogs ? 'Scan in progress — streaming live output...' :
                loading ? 'Loading scan results...' :
                  `${cves.length} vulnerabilities identified. Prioritize remediation based on CVSS scoring.`}
            </p>
            {currentScan?.clientNames?.length ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {currentScan.clientNames.map((clientName) => (
                  <span key={`header-${clientName}`} className="rounded-full bg-primary/10 px-3 py-1 text-[11px] font-medium text-primary">
                    {clientName}
                  </span>
                ))}
              </div>
            ) : null}
          </div>

          {/* Scan Selector Dropdown */}
          <div className="relative shrink-0 space-y-2">
            <select value={scanClientFilter} onChange={(e) => setScanClientFilter(e.target.value)} className="w-full rounded-xl border border-outline-variant/[0.2] bg-surface-container-low px-3 py-2 text-sm text-on-surface">
              <option value="ALL">Tous les clients</option>
              {scanClientOptions.map((clientName) => (
                <option key={clientName} value={clientName}>{clientName}</option>
              ))}
            </select>
            <button
              onClick={() => setDropdownOpen(!dropdownOpen)}
              className="flex items-center gap-3 px-4 py-2.5 bg-surface-container-low rounded-xl border border-outline-variant/[0.15] hover:border-primary/40 transition-all glass-panel min-w-[280px]"
            >
              <span className="material-symbols-outlined text-primary text-lg">radar</span>
              <div className="flex-1 text-left">
                <p className="text-sm font-headline text-on-surface truncate">
                  {currentScan ? repoName(currentScan.repoUrl) : 'Select a scan'}
                </p>
                <p className="text-[10px] text-outline">
                  {currentScan ? `Scan #${currentScan.id} — ${currentScan.status}` : 'No scan selected'}
                </p>
              </div>
              <span className={`material-symbols-outlined text-outline text-lg transition-transform ${dropdownOpen ? 'rotate-180' : ''}`}>expand_more</span>
            </button>

            {dropdownOpen && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setDropdownOpen(false)}></div>
                <div className="absolute right-0 z-20 mt-2 w-[360px] max-h-80 overflow-y-auto rounded-2xl border border-outline-variant/[0.15] bg-surface-container-low glass-panel shadow-2xl shadow-primary/5 custom-scrollbar">
                  {visibleScans.length === 0 && (
                    <div className="px-5 py-6 text-center text-outline text-sm">No scans found</div>
                  )}
                  {visibleScans.map(scan => {
                    const isSelected = scan.id === selectedScanId;
                    const isRunning = scan.status === 'RUNNING';
                    const isFailed = scan.status === 'FAILED';
                    return (
                      <button
                        key={scan.id}
                        onClick={() => handleScanSelect(scan.id)}
                        className={`w-full flex items-center gap-3 px-5 py-3 text-left text-sm transition-all hover:bg-primary/10 ${isSelected ? 'bg-primary/[0.07]' : ''}`}
                      >
                        <span className={`material-symbols-outlined text-lg ${isRunning ? 'text-primary animate-spin' : isFailed ? 'text-error' : 'text-tertiary'}`}>
                          {isRunning ? 'progress_activity' : isFailed ? 'error' : 'check_circle'}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className={`font-headline truncate ${isSelected ? 'text-primary' : 'text-on-surface'}`}>
                            {repoName(scan.repoUrl)}
                          </p>
                          <p className="text-[10px] text-outline">
                            #{scan.id} — {scan.startedAt ? new Date(scan.startedAt).toLocaleString() : '—'} — {scan.cveCount} CVEs
                          </p>
                          {scan.clientNames?.length ? (
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {scan.clientNames.map((clientName) => (
                                <span key={`${scan.id}-${clientName}`} className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">
                                  {clientName}
                                </span>
                              ))}
                            </div>
                          ) : null}
                        </div>
                        {isSelected && <span className="material-symbols-outlined text-primary text-sm">check</span>}
                      </button>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        </header>

        {/* TAB BAR — shown when a scan is selected and not running */}
        {selectedScanId && !showLogs && (
          <div className="flex gap-1 mb-6 border-b border-outline-variant/[0.1] pb-0">
            {([
              { key: 'cve', icon: 'shield', label: 'Vulnérabilités', count: cves.length, danger: cves.filter(c => c.severity === 'CRITICAL').length > 0 },
              { key: 'findings', icon: 'security', label: 'Sécurité', count: secrets.length + sastFindings.length, danger: secrets.length > 0 },
              { key: 'sbom', icon: 'inventory_2', label: 'SBOM', count: sbomComponents.length, danger: false },
              { key: 'evolution', icon: 'trending_up', label: 'Évolution', count: 0, danger: false },
              { key: 'compliance', icon: 'verified_user', label: 'Conformité', count: 0, danger: false },
            ] as const).map(tab => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex items-center gap-2 px-5 py-3 text-sm font-headline rounded-t-xl border-b-2 transition-all ${
                  activeTab === tab.key
                    ? 'border-primary text-primary bg-primary/5'
                    : 'border-transparent text-on-surface-variant hover:text-on-surface hover:bg-surface-container'
                }`}
              >
                <span className="material-symbols-outlined text-base">{tab.icon}</span>
                {tab.label}
                {tab.count > 0 && (
                  <span className={`ml-1 px-2 py-0.5 rounded-full text-[10px] font-bold ${
                    tab.danger ? 'bg-error-container text-on-error-container' : 'bg-surface-container-high text-on-surface-variant'
                  }`}>{tab.count}</span>
                )}
              </button>
            ))}
          </div>
        )}

        {/* LIVE LOGS — shown when scan is running */}
        {showLogs && (
          <div className="glass-panel rounded-2xl border border-primary/[0.15] overflow-hidden shadow-2xl mb-6">
            <div className="bg-surface-container-highest/50 px-6 py-3 flex items-center justify-between border-b border-outline-variant/[0.1]">
              <div className="flex items-center gap-4">
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-[#FF5F56]"></div>
                  <div className="w-2.5 h-2.5 rounded-full bg-[#FFBD2E]"></div>
                  <div className="w-2.5 h-2.5 rounded-full bg-[#27C93F]"></div>
                </div>
                <span className="text-[10px] font-mono tracking-widest text-outline uppercase">
                  Active_Session // {currentScan ? repoName(currentScan.repoUrl) : 'scan'}.log
                </span>
              </div>
              <span className="text-[10px] font-mono text-primary flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse"></span> Scan in progress...
              </span>
            </div>
            <div className="p-6 font-mono text-xs leading-relaxed h-[400px] overflow-y-auto bg-surface-container-lowest/80 custom-scrollbar">
              {logs.length === 0 && (
                <div className="flex items-center gap-3 text-outline opacity-50">
                  <span className="material-symbols-outlined text-base animate-spin">progress_activity</span>
                  <span>Connecting to scan process...</span>
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
        )}

        {/* CVE TABLE — shown when scan is completed */}
        {!showLogs && activeTab === 'cve' && (
          <>
            {/* Filter Header */}
            <div className="mb-6 flex flex-col sm:flex-row gap-4 items-center justify-between bg-surface-container-low p-4 rounded-xl border border-outline-variant/[0.1]"
            >
              <div className="relative w-full sm:w-72">
                <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">search</span>
                <input
                  className="bg-surface-container-lowest border-none w-full pl-10 pr-4 py-2 text-sm rounded-lg focus:ring-1 focus:ring-primary text-on-surface"
                  placeholder="Filter vulnerabilities..."
                  type="text"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                />
              </div>
              <div className="flex items-center gap-3 w-full sm:w-auto flex-wrap">
                <div className="flex gap-2 overflow-x-auto pb-1 sm:pb-0">
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => {
                  const colorMap: Record<string, string> = {
                    ALL: filter === 'ALL' ? 'bg-primary-container text-on-primary-container' : 'bg-surface-container hover:bg-surface-container-high text-on-surface-variant',
                    CRITICAL: filter === 'CRITICAL' ? 'bg-error-container text-on-error-container' : 'bg-surface-container hover:bg-surface-container-high text-error border border-error/[0.2]',
                    HIGH: filter === 'HIGH' ? 'bg-secondary-container text-on-secondary-container' : 'bg-surface-container hover:bg-surface-container-high text-secondary border border-secondary/[0.2]',
                    MEDIUM: filter === 'MEDIUM' ? 'bg-surface-variant text-on-surface-variant' : 'bg-surface-container hover:bg-surface-container-high text-on-surface-variant border border-outline-variant/[0.2]',
                    LOW: filter === 'LOW' ? 'bg-tertiary-container text-on-tertiary-container' : 'bg-surface-container hover:bg-surface-container-high text-tertiary border border-tertiary/[0.2]',
                  };
                  return (
                    <button key={sev} onClick={() => setFilter(sev)}
                      className={`px-4 py-1.5 rounded-full text-xs font-bold ${colorMap[sev]}`}>
                      {sev} ({counts[sev]})
                    </button>
                  );
                })}
                </div>

                {/* Export PDF button */}
                <button
                  onClick={exportPdf}
                  disabled={filtered.length === 0}
                  title="Exporter les vulnérabilités en PDF"
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20 transition-all disabled:opacity-30 disabled:cursor-not-allowed shrink-0"
                >
                  <span className="material-symbols-outlined text-sm">download</span>
                  Export PDF
                </button>
              </div>
            </div>

            {/* ── Q1 · Expandable AI Summary Card ── */}
            {cves.length > 0 && (
              <div className="mb-4 rounded-2xl border border-primary/20 bg-surface-container-low overflow-hidden shadow-lg">
                <button
                  onClick={() => setAiSummaryOpen(o => !o)}
                  className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-primary/5 transition-all text-left"
                >
                  <span className="text-lg">🧠</span>
                  <span className="font-headline font-bold text-on-surface text-sm">Analyse IA — Résumé global Gemini</span>
                  {/* Priority pills */}
                  <div className="flex items-center gap-2 ml-2 flex-wrap">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500/15 border border-red-500/30 text-red-400">
                      🔴 URGENT <span className="font-mono">{priorityCounts.urgent}</span>
                    </span>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-orange-500/15 border border-orange-500/30 text-orange-400">
                      🟠 ÉLEVÉ <span className="font-mono">{priorityCounts.eleve}</span>
                    </span>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-yellow-500/15 border border-yellow-500/30 text-yellow-400">
                      🟡 MOYEN <span className="font-mono">{priorityCounts.moyen}</span>
                    </span>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-500/10 border border-slate-500/20 text-slate-400">
                      🟢 FAIBLE <span className="font-mono">{priorityCounts.faible}</span>
                    </span>
                  </div>
                  {aiSummaryLoading && (
                    <span className="ml-auto flex items-center gap-1.5 text-[10px] text-primary">
                      <span className="material-symbols-outlined text-xs animate-spin">progress_activity</span> Gemini analyse...
                    </span>
                  )}
                  <span className={`ml-auto material-symbols-outlined text-outline text-lg transition-transform shrink-0 ${aiSummaryOpen ? 'rotate-180' : ''} ${aiSummaryLoading ? 'ml-2' : ''}`}>expand_more</span>
                </button>
                {aiSummaryOpen && (
                  <div className="border-t border-primary/10 px-5 py-4 bg-surface-container-lowest/60">
                    {aiSummaryLoading ? (
                      <div className="flex items-center gap-2 text-outline text-sm">
                        <span className="material-symbols-outlined text-base animate-spin text-primary">progress_activity</span>
                        Gemini génère le résumé...
                      </div>
                    ) : aiSummary ? (
                      <p className="text-sm text-on-surface-variant leading-relaxed whitespace-pre-line">{aiSummary}</p>
                    ) : (
                      <p className="text-sm text-outline italic">
                        {priorityCounts.urgent > 0
                          ? `${priorityCounts.urgent} vulnérabilité(s) URGENTE(S) détectées nécessitant une action immédiate. ${counts.CRITICAL} CRITICAL, ${counts.HIGH} HIGH.`
                          : `${cves.length} vulnérabilités analysées — aucune ne nécessite une action immédiate selon le score de priorité IA.`}
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Table */}
            <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] overflow-hidden shadow-2xl">
              <table className="w-full text-left border-collapse table-fixed">
                  <thead>
                    <tr className="bg-surface-container-low/50 border-b border-outline-variant/[0.1]">
                      <th className="w-[38%] px-4 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest">Vulnerability</th>
                      <th className="w-[14%] px-2 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest text-center">Severity</th>
                      <th className="w-[10%] px-2 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest text-center">CVSS</th>
                      <th className="w-[10%] px-2 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest text-center">EPSS</th>
                      <th className="w-[18%] px-4 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest">Package</th>
                      <th className="w-[10%] px-2 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest">Source</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-outline-variant/[0.1]">
                    {loading && (
                      <tr><td colSpan={6} className="px-6 py-16 text-center text-outline-variant">
                        <span className="material-symbols-outlined text-4xl animate-spin mb-2">progress_activity</span>
                        <p className="text-sm">Loading vulnerabilities...</p>
                      </td></tr>
                    )}
                    {!loading && filtered.length === 0 && (
                      <tr><td colSpan={6} className="px-6 py-16 text-center text-outline-variant">
                        <span className="material-symbols-outlined text-4xl mb-2">verified_user</span>
                        <p className="text-sm">{cves.length === 0 ? 'No vulnerabilities found — your code is clean!' : 'No results match your filter.'}</p>
                      </td></tr>
                    )}
                    {filtered.map((cve, i) => (
                      <tr
                        key={cve.id}
                        onClick={() => setSelected(cve)}
                        className={`hover:bg-primary/5 transition-colors cursor-pointer group ${i % 2 === 1 ? 'bg-surface-container-low/20' : ''} ${selected?.id === cve.id ? 'bg-primary/10' : ''}`}
                      >
                        <td className="px-4 py-4">
                          <div className="flex flex-col">
                            <div className="flex items-center gap-2">
                              <span className="text-on-surface font-semibold text-sm group-hover:text-primary transition-colors truncate">{cve.cveId || 'N/A'}</span>
                              {(() => {
                                const p = calcPriority(cve);
                                // Build ordered list of all badges
                                const allBadges: React.ReactNode[] = [];
                                if (cve.exploitAvailable) allBadges.push(
                                  <a key="exploit"
                                    href={cve.exploitUrl || `https://www.exploit-db.com/search?cve=${cve.cveId}`}
                                    target="_blank" rel="noopener noreferrer"
                                    onClick={e => e.stopPropagation()}
                                    title="Exploit public disponible sur Exploit-DB"
                                    className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-error text-on-error shrink-0 hover:opacity-80 transition-opacity"
                                  ><span className="material-symbols-outlined text-[10px]">bug_report</span>EXPLOIT</a>
                                );
                                if (cve.kevListed) allBadges.push(
                                  <span key="kev"
                                    title={`CISA KEV — Exploité activement dans le monde réel${cve.kevRansomware ? ' · Lié à un ransomware' : ''}`}
                                    className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-500 text-white shrink-0"
                                  ><span className="material-symbols-outlined text-[10px]">warning</span>KEV</span>
                                );
                                allBadges.push(
                                  <span key="priority"
                                    title={`Priorité IA: ${p.label} (score: ${(p.score * 100).toFixed(0)}%) | CVSS×45% + EPSS×30% + Exploit×20%${(cve.confirmedBy ?? 1) >= 2 ? ` + ${(cve.confirmedBy ?? 1) >= 3 ? '+15%' : '+10%'} (${cve.confirmedBy} outils)` : ''}`}
                                    className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold shrink-0 ${p.bgClass} ${p.color}`}
                                  >{p.emoji} {p.label}</span>
                                );
                                // Badge détection fusionné : CONFIRMÉ + sources → un seul badge compact
                                {
                                  const srcList = cve.sources ? cve.sources.split(',').map(s => s.trim()).filter(Boolean) : [];
                                  const count = cve.confirmedBy ?? srcList.length;
                                  if (count >= 2) {
                                    allBadges.push(
                                      <span key="confirmed"
                                        title={`Confirmé par ${count} outils indépendants: ${srcList.join(', ')}`}
                                        className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold shrink-0 ${count >= 3 ? 'bg-emerald-700 text-white' : 'bg-emerald-600 text-white'}`}
                                      ><span className="material-symbols-outlined text-[10px]">verified</span>{count}×</span>
                                    );
                                  } else if (srcList.length === 1) {
                                    allBadges.push(
                                      <span key="confirmed"
                                        title={`Détecté par: ${srcList[0]}`}
                                        className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-600 text-white shrink-0"
                                      ><span className="material-symbols-outlined text-[10px]">sensors</span>1×</span>
                                    );
                                  }
                                }
                                // Idée 3 — OS badge (🐧 Linux / 🪟 Windows / 🌐)
                                if (cve.affectedOs === 'LINUX') allBadges.push(
                                  <span key="os"
                                    title="CVE spécifique Linux"
                                    className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-green-800 text-white shrink-0"
                                  >🐧 Linux</span>
                                );
                                else if (cve.affectedOs === 'WINDOWS') allBadges.push(
                                  <span key="os"
                                    title="CVE spécifique Windows"
                                    className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-blue-700 text-white shrink-0"
                                  >🪟 Windows</span>
                                );
                                if (fixedCveIds.has(cve.id)) allBadges.push(
                                  <span key="fixed"
                                    title="Correctif appliqué via commit GitHub"
                                    className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-teal-600 text-white shrink-0"
                                  ><span className="material-symbols-outlined text-[10px]">check_circle</span>CORRIGÉ</span>
                                );
                                const MAX = 3;
                                const visible = allBadges.slice(0, MAX);
                                const hidden = allBadges.length - MAX;
                                return (
                                  <>
                                    {visible}
                                    {hidden > 0 && (
                                      <span
                                        title="Cliquez pour voir tous les badges dans le détail →"
                                        className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-surface-container-highest text-outline shrink-0 cursor-default"
                                      >+{hidden}</span>
                                    )}
                                  </>
                                );
                              })()}
                            </div>
                            <span className="text-xs text-slate-500 truncate">{cve.description?.slice(0, 55) || '—'}...</span>
                          </div>
                        </td>
                        <td className="px-2 py-4 text-center">
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-[10px] font-bold ${severityBadge(cve.severity)}`}>{cve.severity}</span>
                        </td>
                        <td className="px-2 py-4 text-center">
                          <div className={`inline-flex items-center justify-center w-10 h-10 rounded-lg bg-surface-container-highest border ${severityBorder(cve.severity)} font-bold font-headline text-sm`}>
                            {cve.cvssScore?.toFixed(1) || '—'}
                          </div>
                        </td>
                        <td className="px-2 py-4 text-center">
                          {cve.epssScore != null ? (
                            <div className="flex flex-col items-center gap-1">
                              <span className={`text-[11px] font-bold font-headline ${epssInfo(cve.epssScore).text}`}>
                                {(cve.epssScore * 100).toFixed(1)}%
                              </span>
                              <div className="w-10 h-1 rounded-full bg-surface-container-highest overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${epssInfo(cve.epssScore).bar}`}
                                  style={{ width: `${Math.min(cve.epssScore * 100, 100)}%` }}
                                />
                              </div>
                            </div>
                          ) : (
                            <span className="text-xs text-slate-400">—</span>
                          )}
                        </td>
                        <td className="px-4 py-4">
                          <span className="text-xs font-mono text-on-surface-variant truncate block">{cve.packageName || '—'}</span>
                          {cve.packageVersion && <span className="text-xs text-slate-500">@{cve.packageVersion}</span>}
                        </td>
                        <td className="px-2 py-4">
                          <span className="text-xs text-slate-500 uppercase">{cve.source}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
            </div>
          </>
        )}

        {/* ── SÉCURITÉ : Secrets & SAST (merged) TAB ── */}
        {!showLogs && activeTab === 'findings' && (
          <div className="space-y-6">
            {/* ── Secrets section ── */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <span className="material-symbols-outlined text-error text-lg">key_off</span>
                <h2 className="font-headline font-bold text-on-surface text-base">Secrets & Fuites</h2>
                {secrets.length > 0 && <span className="ml-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-error-container text-on-error-container">{secrets.length}</span>}
              </div>
              {secretsLoading ? (
                <div className="flex items-center gap-3 text-outline py-8 justify-center">
                  <span className="material-symbols-outlined animate-spin">progress_activity</span> Chargement des secrets...
                </div>
              ) : secrets.length === 0 ? (
                <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-8 text-center">
                  <span className="material-symbols-outlined text-3xl text-tertiary mb-3 block">shield_lock</span>
                  <p className="text-on-surface font-headline font-bold mb-1">Aucun secret détecté</p>
                  <p className="text-outline text-sm">Gitleaks n'a trouvé aucun secret exposé dans ce dépôt.</p>
                </div>
              ) : (
                <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] overflow-hidden shadow-2xl">
                  <div className="px-6 py-4 border-b border-outline-variant/[0.1] bg-surface-container-low/50 flex items-center gap-3">
                    <span className="material-symbols-outlined text-error">key_off</span>
                    <span className="font-headline font-bold text-on-surface">{secrets.length} secret{secrets.length > 1 ? 's' : ''} exposé{secrets.length > 1 ? 's' : ''}</span>
                    <span className="text-[10px] text-outline ml-auto">Valeurs masquées — cliquez pour développer</span>
                  </div>
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-surface-container-low/30 border-b border-outline-variant/[0.1]">
                        <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[12%]">Gravité</th>
                        <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[20%]">Type</th>
                        <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[28%]">Fichier</th>
                        <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[8%] text-center">Ligne</th>
                        <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[18%]">Commit</th>
                        <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[14%]">Secret</th>
                      </tr>
                    </thead>
                    <tbody>
                      {secrets.map((s, idx) => {
                        const sev = secretSeverity(s.ruleId);
                        const isExpanded = expandedSecret === idx;
                        return (
                          <React.Fragment key={s.id ?? idx}>
                            <tr
                              className={`border-b border-outline-variant/[0.07] cursor-pointer transition-all hover:bg-primary/5 ${isExpanded ? 'bg-primary/[0.04]' : ''}`}
                              onClick={() => setExpandedSecret(isExpanded ? null : idx)}
                            >
                              <td className="px-4 py-3">
                                <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold ${SECRET_SEVERITY_BADGE[sev]}`}>
                                  <span className={`w-1.5 h-1.5 rounded-full ${SECRET_SEVERITY_DOT[sev]}`}></span>
                                  {sev}
                                </span>
                              </td>
                              <td className="px-4 py-3 text-sm text-on-surface font-headline">{s.ruleId || '—'}</td>
                              <td className="px-4 py-3 text-xs text-on-surface-variant font-mono truncate max-w-0">
                                <span title={s.file}>{s.file ? s.file.split('/').slice(-2).join('/') : '—'}</span>
                              </td>
                              <td className="px-4 py-3 text-xs text-center text-outline">{s.startLine ?? '—'}</td>
                              <td className="px-4 py-3 text-xs text-outline font-mono">{s.commit ? s.commit.substring(0, 7) : '—'}</td>
                              <td className="px-4 py-3 text-xs font-mono text-error truncate max-w-0">
                                <span title="Valeur masquée pour des raisons de sécurité">{s.maskedMatch ?? '••••••••'}</span>
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr className="bg-surface-container/40 border-b border-outline-variant/[0.07]">
                                <td colSpan={6} className="px-6 py-4">
                                  <div className="grid grid-cols-2 gap-4 text-sm">
                                    <div>
                                      <p className="text-[10px] text-outline uppercase font-bold mb-1">Description</p>
                                      <p className="text-on-surface-variant">{s.description || 'Aucune description'}</p>
                                    </div>
                                    <div>
                                      <p className="text-[10px] text-outline uppercase font-bold mb-1">Chemin complet</p>
                                      <p className="font-mono text-on-surface-variant break-all">{s.file || '—'}</p>
                                    </div>
                                    <div>
                                      <p className="text-[10px] text-outline uppercase font-bold mb-1">Auteur</p>
                                      <p className="text-on-surface-variant">{s.author || '—'}</p>
                                    </div>
                                    <div>
                                      <p className="text-[10px] text-outline uppercase font-bold mb-1">Date</p>
                                      <p className="text-on-surface-variant">{s.date ? new Date(s.date).toLocaleString('fr-FR') : '—'}</p>
                                    </div>
                                  </div>
                                  <div className="mt-3 p-3 rounded-lg bg-error/5 border border-error/20">
                                    <p className="text-[10px] text-error uppercase font-bold mb-1">Valeur masquée du secret</p>
                                    <p className="font-mono text-sm text-error">{s.maskedMatch ?? '••••••••'}</p>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* ── Divider ── */}
            <div className="flex items-center gap-4">
              <div className="flex-1 h-px bg-outline-variant/[0.15]"></div>
              <span className="text-[10px] text-outline uppercase tracking-widest font-bold px-3">SAST / OWASP</span>
              <div className="flex-1 h-px bg-outline-variant/[0.15]"></div>
            </div>

            {/* ── SAST section ── */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <span className="material-symbols-outlined text-secondary text-lg">bug_report</span>
                <h2 className="font-headline font-bold text-on-surface text-base">Analyse SAST / OWASP</h2>
                {sastFindings.length > 0 && <span className="ml-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-surface-container-high text-on-surface-variant">{sastFindings.length}</span>}
              </div>
              {sastLoading ? (
                <div className="flex items-center gap-3 text-outline py-8 justify-center">
                  <span className="material-symbols-outlined animate-spin">progress_activity</span> Chargement de l'analyse SAST...
                </div>
              ) : sastFindings.length === 0 ? (
                <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-8 text-center">
                  <span className="material-symbols-outlined text-3xl text-tertiary mb-3 block">verified_user</span>
                  <p className="text-on-surface font-headline font-bold mb-1">Aucune finding SAST</p>
                  <p className="text-outline text-sm">Semgrep OWASP n'a détecté aucune vulnérabilité de code dans ce dépôt.</p>
                </div>
              ) : (() => {
                const grouped = sastFindings.reduce<Record<string, SastDto[]>>((acc, f) => {
                  const cat = f.owaspCategory || 'Other';
                  if (!acc[cat]) acc[cat] = [];
                  acc[cat].push(f);
                  return acc;
                }, {});
                return (
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 mb-4">
                      <span className="material-symbols-outlined text-secondary">bug_report</span>
                      <span className="font-headline font-bold text-on-surface">{sastFindings.length} finding{sastFindings.length > 1 ? 's' : ''} SAST</span>
                      <span className="text-outline text-sm">— {Object.keys(grouped).length} catégorie{Object.keys(grouped).length > 1 ? 's' : ''} OWASP</span>
                    </div>
                    {Object.entries(grouped).map(([category, items]) => {
                      const isOpen = expandedOwasp === category;
                      const color = owaspColor(category);
                      return (
                        <div key={category} className="glass-panel rounded-2xl border border-outline-variant/[0.15] overflow-hidden">
                          <button
                            className="w-full flex items-center gap-4 px-6 py-4 hover:bg-surface-container/30 transition-all"
                            onClick={() => setExpandedOwasp(isOpen ? null : category)}
                          >
                            <span className={`px-3 py-1 rounded-lg text-xs font-bold border ${color}`}>{category}</span>
                            <span className="font-headline text-on-surface flex-1 text-left">{items.length} finding{items.length > 1 ? 's' : ''}</span>
                            <span className={`material-symbols-outlined text-outline transition-transform ${isOpen ? 'rotate-180' : ''}`}>expand_more</span>
                          </button>
                          {isOpen && (
                            <div className="border-t border-outline-variant/[0.1]">
                              <table className="w-full text-left border-collapse">
                                <thead>
                                  <tr className="bg-surface-container-low/30">
                                    <th className="px-4 py-2.5 text-[10px] font-bold text-outline uppercase tracking-widest w-[22%]">Règle</th>
                                    <th className="px-4 py-2.5 text-[10px] font-bold text-outline uppercase tracking-widest w-[30%]">Fichier</th>
                                    <th className="px-4 py-2.5 text-[10px] font-bold text-outline uppercase tracking-widest w-[8%] text-center">Ligne</th>
                                    <th className="px-4 py-2.5 text-[10px] font-bold text-outline uppercase tracking-widest w-[10%] text-center">Sévérité</th>
                                    <th className="px-4 py-2.5 text-[10px] font-bold text-outline uppercase tracking-widest">Message</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {items.map((f, i) => (
                                    <tr key={i} className="border-t border-outline-variant/[0.07] hover:bg-primary/5 transition-all">
                                      <td className="px-4 py-3 text-xs font-mono text-primary truncate max-w-0">
                                        <span title={f.checkId}>{f.checkId?.split('.').slice(-2).join('.') || '—'}</span>
                                      </td>
                                      <td className="px-4 py-3 text-xs font-mono text-on-surface-variant truncate max-w-0">
                                        <span title={f.file}>{f.file ? f.file.replace('/workspace/repo/', '').split('/').slice(-2).join('/') : '—'}</span>
                                      </td>
                                      <td className="px-4 py-3 text-xs text-center text-outline">{f.line ?? '—'}</td>
                                      <td className="px-4 py-3 text-center">
                                        <span className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-bold ${severityBadge(f.severity)}`}>{f.severity}</span>
                                      </td>
                                      <td className="px-4 py-3 text-xs text-on-surface-variant">{f.message || '—'}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                );
              })()}
            </div>
          </div>
        )}

        {/* ── SBOM TAB ── */}
        {!showLogs && activeTab === 'sbom' && (() => {
          const ecosystems = Array.from(new Set(sbomComponents.map(c => c.type).filter(Boolean))).sort();
          const filteredSbom = sbomComponents.filter(c => {
            const hasCve = cves.some(v => v.packageName?.toLowerCase() === c.name.toLowerCase());
            if (sbomFilter === 'with-cve' && !hasCve) return false;
            if (sbomFilter === 'without-cve' && hasCve) return false;
            if (sbomEcosystem && c.type !== sbomEcosystem) return false;
            if (sbomSearch) {
              const q = sbomSearch.toLowerCase();
              return c.name.toLowerCase().includes(q) || c.version?.toLowerCase().includes(q) || c.type?.toLowerCase().includes(q) || c.license?.toLowerCase().includes(q);
            }
            return true;
          });

          if (sbomLoading) return (
            <div className="flex items-center gap-3 text-outline py-12 justify-center">
              <span className="material-symbols-outlined animate-spin">progress_activity</span> Chargement du SBOM...
            </div>
          );

          if (sbomComponents.length === 0) return (
            <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-12 text-center">
              <span className="material-symbols-outlined text-4xl text-outline mb-4 block">inventory_2</span>
              <p className="text-on-surface font-headline font-bold mb-1">Aucun composant SBOM</p>
              <p className="text-outline text-sm">Le SBOM n'a pas encore été généré pour ce scan.</p>
            </div>
          );

          const withCveCount = sbomComponents.filter(c => cves.some(v => v.packageName?.toLowerCase() === c.name.toLowerCase())).length;

          return (
            <div>
              {/* Stats bar */}
              <div className="flex flex-wrap gap-3 mb-5">
                <div className="glass-panel rounded-xl border border-outline-variant/[0.15] px-5 py-3 flex items-center gap-3">
                  <span className="material-symbols-outlined text-primary text-lg">inventory_2</span>
                  <div><p className="text-[10px] text-outline uppercase font-bold">Total</p><p className="text-xl font-bold text-on-surface">{sbomComponents.length}</p></div>
                </div>
                <div className="glass-panel rounded-xl border border-error/30 px-5 py-3 flex items-center gap-3">
                  <span className="material-symbols-outlined text-error text-lg">warning</span>
                  <div><p className="text-[10px] text-outline uppercase font-bold">Avec CVE</p><p className="text-xl font-bold text-error">{withCveCount}</p></div>
                </div>
                <div className="glass-panel rounded-xl border border-tertiary/30 px-5 py-3 flex items-center gap-3">
                  <span className="material-symbols-outlined text-tertiary text-lg">verified</span>
                  <div><p className="text-[10px] text-outline uppercase font-bold">Sans CVE</p><p className="text-xl font-bold text-tertiary">{sbomComponents.length - withCveCount}</p></div>
                </div>
                <div className="glass-panel rounded-xl border border-outline-variant/[0.15] px-5 py-3 flex items-center gap-3">
                  <span className="material-symbols-outlined text-secondary text-lg">category</span>
                  <div><p className="text-[10px] text-outline uppercase font-bold">Écosystèmes</p><p className="text-xl font-bold text-on-surface">{ecosystems.length}</p></div>
                </div>
              </div>

              {/* Filter bar */}
              <div className="flex flex-wrap gap-2 mb-4 items-center">
                <div className="relative flex-1 min-w-[200px]">
                  <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-sm">search</span>
                  <input
                    className="w-full bg-surface-container border border-outline-variant/[0.2] rounded-xl pl-9 pr-4 py-2 text-sm text-on-surface placeholder-outline focus:outline-none focus:border-primary/60 transition-colors"
                    placeholder="Rechercher un composant…"
                    value={sbomSearch}
                    onChange={e => setSbomSearch(e.target.value)}
                  />
                </div>
                {(['all', 'with-cve', 'without-cve'] as const).map(f => (
                  <button
                    key={f}
                    onClick={() => setSbomFilter(f)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-all ${sbomFilter === f ? 'bg-primary/10 border-primary/40 text-primary' : 'border-outline-variant/[0.2] text-outline hover:border-primary/30'}`}
                  >
                    {f === 'all' ? 'Tous' : f === 'with-cve' ? 'Avec CVE' : 'Sans CVE'}
                  </button>
                ))}
                <select
                  className="bg-surface-container border border-outline-variant/[0.2] rounded-xl px-3 py-1.5 text-xs text-on-surface focus:outline-none focus:border-primary/60 transition-colors"
                  value={sbomEcosystem}
                  onChange={e => setSbomEcosystem(e.target.value)}
                >
                  <option value="">Tous les écosystèmes</option>
                  {ecosystems.map(e => <option key={e} value={e}>{e}</option>)}
                </select>
                <span className="text-xs text-outline ml-auto">{filteredSbom.length} / {sbomComponents.length} composants</span>
              </div>

              {/* Components table */}
              <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] overflow-hidden shadow-2xl">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-surface-container-low/30 border-b border-outline-variant/[0.1]">
                      <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[28%]">Composant</th>
                      <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[14%]">Version</th>
                      <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[14%]">Type</th>
                      <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[18%]">Licence</th>
                      <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[14%]">CVEs</th>
                      <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest">Localisation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredSbom.map((pkg, idx) => {
                      const pkgCves = cves.filter(v => v.packageName?.toLowerCase() === pkg.name.toLowerCase());
                      const hasCritical = pkgCves.some(v => v.severity === 'CRITICAL');
                      const hasAnyCve = pkgCves.length > 0;
                      const isSelected = sbomSelectedPkg?.id === pkg.id;
                      const rowBorder = hasCritical ? 'border-l-2 border-l-error' : hasAnyCve ? 'border-l-2 border-l-warning' : '';
                      return (
                        <React.Fragment key={pkg.id ?? idx}>
                          <tr
                            className={`border-b border-outline-variant/[0.07] cursor-pointer transition-all hover:bg-primary/5 ${isSelected ? 'bg-primary/[0.04]' : ''} ${rowBorder}`}
                            onClick={() => setSbomSelectedPkg(isSelected ? null : pkg)}
                          >
                            <td className="px-4 py-3">
                              <span className="text-sm font-headline text-on-surface">{pkg.name}</span>
                            </td>
                            <td className="px-4 py-3 text-xs font-mono text-on-surface-variant">{pkg.version || '—'}</td>
                            <td className="px-4 py-3">
                              <span className="px-2 py-0.5 rounded-md text-[10px] font-bold bg-surface-container-high text-on-surface-variant border border-outline-variant/[0.2]">{pkg.type || '—'}</span>
                            </td>
                            <td className="px-4 py-3 text-xs text-on-surface-variant">{pkg.license || '—'}</td>
                            <td className="px-4 py-3">
                              {pkgCves.length === 0 ? (
                                <span className="text-xs text-tertiary flex items-center gap-1"><span className="material-symbols-outlined text-sm">verified</span>Aucun</span>
                              ) : (
                                <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold ${hasCritical ? 'bg-error-container text-on-error-container' : 'bg-warning-container/60 text-on-surface-variant'}`}>
                                  <span className="material-symbols-outlined text-[12px]">warning</span>
                                  {pkgCves.length} CVE{pkgCves.length > 1 ? 's' : ''}
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3 text-xs text-outline font-mono truncate max-w-0">
                              <span title={pkg.location}>{pkg.location ? pkg.location.split('/').slice(-2).join('/') : '—'}</span>
                            </td>
                          </tr>
                          {isSelected && (
                            <tr className="bg-surface-container/40 border-b border-outline-variant/[0.07]">
                              <td colSpan={6} className="px-6 py-4">
                                <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
                                  <div>
                                    <p className="text-[10px] text-outline uppercase font-bold mb-1">PURL</p>
                                    <p className="font-mono text-xs text-on-surface-variant break-all">{pkg.purl || '—'}</p>
                                  </div>
                                  <div>
                                    <p className="text-[10px] text-outline uppercase font-bold mb-1">Localisation complète</p>
                                    <p className="font-mono text-xs text-on-surface-variant break-all">{pkg.location || '—'}</p>
                                  </div>
                                </div>
                                {pkgCves.length > 0 && (
                                  <div>
                                    <p className="text-[10px] text-outline uppercase font-bold mb-2">CVEs liées ({pkgCves.length})</p>
                                    <div className="space-y-1.5">
                                      {pkgCves.map((v, vi) => (
                                        <div key={vi} className={`flex items-center gap-3 px-3 py-2 rounded-lg border text-xs ${v.severity === 'CRITICAL' ? 'bg-error/5 border-error/20' : 'bg-surface-container border-outline-variant/[0.1]'}`}>
                                          <span className={`px-2 py-0.5 rounded-full font-bold text-[10px] ${severityBadge(v.severity)}`}>{v.severity}</span>
                                          <span className="font-mono text-primary">{v.cveId || '—'}</span>
                                          {v.cvssScore != null && <span className="text-outline">CVSS {v.cvssScore.toFixed(1)}</span>}
                                          <span className="text-on-surface-variant flex-1 truncate">{v.description?.slice(0, 100) || '—'}</span>
                                          {v.fixedVersion && <span className="text-tertiary text-[10px] font-bold">Fix: {v.fixedVersion}</span>}
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          );
        })()}

        {/* ── ÉVOLUTION TAB ── */}
        {!showLogs && activeTab === 'evolution' && (() => {
          const repoScans = allScans
            .filter(s => s.repoUrl === currentScan?.repoUrl && s.status === 'COMPLETED')
            .sort((a, b) => new Date(a.startedAt).getTime() - new Date(b.startedAt).getTime());

          if (repoScans.length === 0) return (
            <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-12 text-center">
              <span className="material-symbols-outlined text-4xl text-outline mb-4 block">bar_chart</span>
              <p className="text-on-surface font-headline font-bold mb-1">Aucune donnée d'évolution</p>
              <p className="text-outline text-sm">Lancez plusieurs scans pour visualiser la tendance de sécurité dans le temps.</p>
            </div>
          );

          const maxCve = Math.max(...repoScans.map(s => s.cveCount ?? 0), 1);
          const W = 720, H = 160, PAD = 32;
          const pts = repoScans.map((s, i) => {
            const x = repoScans.length === 1 ? W / 2 : PAD + (i / (repoScans.length - 1)) * (W - PAD * 2);
            const y = PAD + (1 - (s.cveCount ?? 0) / maxCve) * (H - PAD * 2);
            return { x, y, scan: s };
          });
          const polyline = pts.map(p => `${p.x},${p.y}`).join(' ');
          const areaPath = `M ${pts[0].x},${H} ` + pts.map(p => `L ${p.x},${p.y}`).join(' ') + ` L ${pts[pts.length - 1].x},${H} Z`;

          const first = repoScans[0].cveCount ?? 0;
          const last = repoScans[repoScans.length - 1].cveCount ?? 0;
          const delta = last - first;
          const improving = delta < 0;
          const stable = delta === 0;

          const bestScan = repoScans.reduce((a, b) => (a.cveCount ?? 0) <= (b.cveCount ?? 0) ? a : b);
          const worstScan = repoScans.reduce((a, b) => (a.cveCount ?? 0) >= (b.cveCount ?? 0) ? a : b);
          const avgCve = Math.round(repoScans.reduce((s, sc) => s + (sc.cveCount ?? 0), 0) / repoScans.length);

          // Security score: 100 if 0 CVEs, proportional decrease
          const secScore = (s: typeof repoScans[0]) => Math.max(0, Math.round(100 - ((s.cveCount ?? 0) / Math.max(worstScan.cveCount ?? 1, 1)) * 80));

          const trendColor = improving ? 'text-tertiary' : stable ? 'text-primary' : 'text-error';
          const trendIcon = improving ? 'trending_down' : stable ? 'trending_flat' : 'trending_up';
          const trendLabel = improving ? 'En amélioration 🎉' : stable ? 'Stable' : 'En régression ⚠️';

          return (
            <div className="space-y-5">
              {/* Header metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  {
                    icon: 'history', label: 'Scans analysés', value: repoScans.length,
                    sub: `depuis ${new Date(repoScans[0].startedAt).toLocaleDateString('fr-FR')}`,
                    color: 'text-primary', bg: 'bg-primary/8 border-primary/20',
                  },
                  {
                    icon: trendIcon, label: 'Tendance globale', value: trendLabel,
                    sub: `${first} → ${last} CVEs`, color: trendColor, bg: improving ? 'bg-tertiary/8 border-tertiary/20' : stable ? 'bg-primary/8 border-primary/20' : 'bg-error/8 border-error/20',
                  },
                  {
                    icon: 'bolt', label: 'Réduction totale', value: delta > 0 ? `+${delta}` : delta === 0 ? '±0' : `${delta}`,
                    sub: `${Math.abs(Math.round(delta / Math.max(first, 1) * 100))}% ${improving ? 'de moins' : 'de plus'}`,
                    color: improving ? 'text-tertiary' : delta === 0 ? 'text-primary' : 'text-error',
                    bg: improving ? 'bg-tertiary/8 border-tertiary/20' : 'bg-error/8 border-error/20',
                  },
                  {
                    icon: 'shield_check', label: 'Score sécurité actuel', value: `${secScore(repoScans[repoScans.length - 1])}/100`,
                    sub: `moy. ${avgCve} CVEs/scan`, color: 'text-secondary', bg: 'bg-secondary/8 border-secondary/20',
                  },
                ].map((m, i) => (
                  <div key={i} className={`glass-panel rounded-2xl border p-4 ${m.bg}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`material-symbols-outlined text-base ${m.color}`}>{m.icon}</span>
                      <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{m.label}</p>
                    </div>
                    <p className={`text-xl font-headline font-bold ${m.color}`}>{m.value}</p>
                    <p className="text-[11px] text-outline mt-0.5">{m.sub}</p>
                  </div>
                ))}
              </div>

              {/* SVG trend chart */}
              <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-primary text-lg">area_chart</span>
                    <h3 className="font-headline font-bold text-on-surface">Évolution des CVEs dans le temps</h3>
                  </div>
                  <span className={`text-xs font-bold px-3 py-1 rounded-full ${improving ? 'bg-tertiary/15 text-tertiary' : stable ? 'bg-primary/15 text-primary' : 'bg-error/15 text-error'}`}>
                    {trendLabel}
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <svg viewBox={`0 0 ${W} ${H + 40}`} className="w-full min-w-[320px]" style={{ height: 220 }}>
                    <defs>
                      <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={improving ? '#00fc92' : '#a4e6ff'} stopOpacity="0.25" />
                        <stop offset="100%" stopColor={improving ? '#00fc92' : '#a4e6ff'} stopOpacity="0.01" />
                      </linearGradient>
                    </defs>
                    {/* Y-axis grid lines */}
                    {[0, 0.25, 0.5, 0.75, 1].map((frac, i) => {
                      const yv = PAD + frac * (H - PAD * 2);
                      const label = Math.round(maxCve * (1 - frac));
                      return (
                        <g key={i}>
                          <line x1={PAD} y1={yv} x2={W - PAD} y2={yv} stroke="#ffffff10" strokeWidth="1" />
                          <text x={PAD - 6} y={yv + 4} textAnchor="end" fill="#64748b" fontSize="10">{label}</text>
                        </g>
                      );
                    })}
                    {/* Area fill */}
                    <path d={areaPath} fill="url(#areaGrad)" />
                    {/* Line */}
                    <polyline points={polyline} fill="none" stroke={improving ? '#00fc92' : '#a4e6ff'} strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />
                    {/* Data points + labels */}
                    {pts.map((p, i) => (
                      <g key={i}>
                        <circle cx={p.x} cy={p.y} r="5" fill={improving ? '#00fc92' : '#a4e6ff'} stroke="#0f172a" strokeWidth="2" />
                        <text x={p.x} y={p.y - 10} textAnchor="middle" fill={improving ? '#00fc92' : '#a4e6ff'} fontSize="11" fontWeight="700">{p.scan.cveCount ?? 0}</text>
                        <text x={p.x} y={H + 20} textAnchor="middle" fill="#64748b" fontSize="9">
                          {new Date(p.scan.startedAt).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short' })}
                        </text>
                        <text x={p.x} y={H + 32} textAnchor="middle" fill="#475569" fontSize="9">#{p.scan.id}</text>
                      </g>
                    ))}
                  </svg>
                </div>
              </div>

              {/* Delta between consecutive scans */}
              {repoScans.length >= 2 && (
                <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-5">
                  <div className="flex items-center gap-2 mb-4">
                    <span className="material-symbols-outlined text-secondary text-lg">compare_arrows</span>
                    <h3 className="font-headline font-bold text-on-surface">Comparaison entre scans</h3>
                  </div>
                  <div className="space-y-2">
                    {repoScans.slice(1).map((scan, i) => {
                      const prev = repoScans[i];
                      const d = (scan.cveCount ?? 0) - (prev.cveCount ?? 0);
                      const pct = prev.cveCount ? Math.round(Math.abs(d) / prev.cveCount * 100) : 0;
                      const up = d > 0;
                      const eq = d === 0;
                      return (
                        <div key={scan.id} className={`flex items-center gap-3 px-4 py-3 rounded-xl border ${up ? 'bg-error/5 border-error/20' : eq ? 'bg-primary/5 border-primary/15' : 'bg-tertiary/5 border-tertiary/20'}`}>
                          <div className="flex items-center gap-1.5 text-xs text-outline shrink-0 w-36">
                            <span className="font-mono">Scan #{prev.id}</span>
                            <span className="material-symbols-outlined text-sm text-outline">arrow_forward</span>
                            <span className="font-mono">Scan #{scan.id}</span>
                          </div>
                          <div className="flex-1 text-xs text-outline truncate">
                            {new Date(scan.startedAt).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: '2-digit' })}
                          </div>
                          <div className={`flex items-center gap-1.5 font-bold text-sm shrink-0 ${up ? 'text-error' : eq ? 'text-primary' : 'text-tertiary'}`}>
                            <span className="material-symbols-outlined text-base">{up ? 'arrow_upward' : eq ? 'remove' : 'arrow_downward'}</span>
                            {eq ? '±0' : `${up ? '+' : ''}${d}`} CVEs
                            {!eq && <span className="text-[10px] font-normal opacity-70">({pct}%)</span>}
                          </div>
                          <div className="text-[11px] text-outline shrink-0">
                            {prev.cveCount ?? 0} → <span className="font-bold text-on-surface">{scan.cveCount ?? 0}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Best / Worst / Security score table */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="glass-panel rounded-2xl border border-tertiary/20 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="material-symbols-outlined text-tertiary text-sm">emoji_events</span>
                    <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Meilleur scan</p>
                  </div>
                  <p className="font-headline font-bold text-tertiary text-lg">Scan #{bestScan.id}</p>
                  <p className="text-xs text-outline">{bestScan.cveCount ?? 0} CVEs — {new Date(bestScan.startedAt).toLocaleDateString('fr-FR')}</p>
                  <p className="text-[11px] text-tertiary mt-1 font-semibold">Score : {secScore(bestScan)}/100</p>
                </div>
                <div className="glass-panel rounded-2xl border border-error/20 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="material-symbols-outlined text-error text-sm">warning</span>
                    <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Pire scan</p>
                  </div>
                  <p className="font-headline font-bold text-error text-lg">Scan #{worstScan.id}</p>
                  <p className="text-xs text-outline">{worstScan.cveCount ?? 0} CVEs — {new Date(worstScan.startedAt).toLocaleDateString('fr-FR')}</p>
                  <p className="text-[11px] text-error mt-1 font-semibold">Score : {secScore(worstScan)}/100</p>
                </div>
                <div className="glass-panel rounded-2xl border border-secondary/20 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="material-symbols-outlined text-secondary text-sm">analytics</span>
                    <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Statistiques</p>
                  </div>
                  <p className="font-headline font-bold text-secondary text-lg">{avgCve} CVEs moy.</p>
                  <p className="text-xs text-outline">{repoScans.length} scans — {repoScans[0] && Math.round((new Date(repoScans[repoScans.length - 1].startedAt).getTime() - new Date(repoScans[0].startedAt).getTime()) / 86400000)}j de suivi</p>
                  <p className={`text-[11px] mt-1 font-semibold ${trendColor}`}>{trendLabel}</p>
                </div>
              </div>
            </div>
          );
        })()}

        {/* ── COMPLIANCE TAB ── */}
        {!showLogs && activeTab === 'compliance' && (() => {
          // ─── helpers ───────────────────────────────────────────────────
          const owaspCategories = Array.from(new Set(sastFindings.map(f => f.owaspCategory).filter(Boolean)));
          const criticalCves    = cves.filter(c => c.severity === 'CRITICAL');
          const kevCves         = cves.filter(c => c.kevListed);
          const exploitCves     = cves.filter(c => c.exploitAvailable);
          const highEpssCves    = cves.filter(c => (c.epssScore ?? 0) >= 0.5);
          const sensitiveSecrets = secrets.filter(s =>
            /email|token|key|password|secret|credential|api[_-]?key|private/i.test((s.ruleId || '') + (s.description || ''))
          );
          const cvss7plus = cves.filter(c => (c.cvssScore ?? 0) >= 7);

          const owaspTop10Keys = ['A01','A02','A03','A04','A05','A06','A07','A08','A09','A10'];
          const owaspHit = owaspTop10Keys.filter(k => owaspCategories.some(cat => cat.includes(k)));
          const owaspOk = owaspHit.length === 0;

          const isoIssues: string[] = [];
          if (criticalCves.length > 0) isoIssues.push(`${criticalCves.length} CVE(s) CRITICAL non corrigée(s)`);
          if (secrets.length > 0)      isoIssues.push(`${secrets.length} secret(s) exposé(s) dans le code`);
          if (highEpssCves.length > 0) isoIssues.push(`${highEpssCves.length} CVE(s) avec probabilité d'exploitation EPSS ≥ 50%`);
          const isoOk = isoIssues.length === 0;

          const rgpdIssues: string[] = [];
          if (sensitiveSecrets.length > 0) rgpdIssues.push(`${sensitiveSecrets.length} donnée(s) sensible(s) exposée(s) (token/email/key)`);
          if (exploitCves.length > 0)      rgpdIssues.push(`${exploitCves.length} CVE(s) avec exploit public — risque d'exfiltration`);
          if (kevCves.length > 0)          rgpdIssues.push(`${kevCves.length} CVE(s) CISA KEV — exploitation active confirmée`);
          const rgpdOk = rgpdIssues.length === 0;

          const pciIssues: string[] = [];
          if (cvss7plus.length > 0)    pciIssues.push(`${cvss7plus.length} CVE(s) avec CVSS ≥ 7.0`);
          if (exploitCves.length > 0)  pciIssues.push(`${exploitCves.length} CVE(s) exploitables publiquement`);
          if (kevCves.length > 0)      pciIssues.push(`${kevCves.length} vulnérabilité(s) activement exploitée(s) (CISA KEV)`);
          const pciOk = pciIssues.length === 0;

          const nistIssues: string[] = [];
          if (kevCves.length > 0)         nistIssues.push(`Identify — ${kevCves.length} actif(s) exposé(s) à des menaces confirmées`);
          if (criticalCves.length > 0)    nistIssues.push(`Protect — ${criticalCves.length} vulnérabilité(s) critique(s) sans correctif`);
          if (exploitCves.length > 0)     nistIssues.push(`Detect — ${exploitCves.length} CVE(s) avec exploit connu non traitée(s)`);
          if (sastFindings.length > 0)    nistIssues.push(`Respond — ${sastFindings.length} finding(s) SAST non résolue(s)`);
          const nistOk = nistIssues.length === 0;

          const frameworks = [
            {
              id: 'owasp', label: 'OWASP Top 10', icon: 'security', ok: owaspOk,
              description: 'Les 10 risques de sécurité web les plus critiques selon OWASP.',
              issues: owaspHit.map(k => `Catégorie ${k} détectée dans les findings SAST`),
              color: owaspOk ? 'border-tertiary/30 bg-tertiary/5' : 'border-error/30 bg-error/5',
              iconColor: owaspOk ? 'text-tertiary' : 'text-error',
            },
            {
              id: 'iso', label: 'ISO 27001', icon: 'gpp_maybe', ok: isoOk,
              description: 'Norme internationale de gestion de la sécurité de l\'information.',
              issues: isoIssues,
              color: isoOk ? 'border-tertiary/30 bg-tertiary/5' : 'border-error/30 bg-error/5',
              iconColor: isoOk ? 'text-tertiary' : 'text-error',
            },
            {
              id: 'rgpd', label: 'RGPD', icon: 'person_alert', ok: rgpdOk,
              description: 'Règlement Général sur la Protection des Données (UE 2016/679).',
              issues: rgpdIssues,
              color: rgpdOk ? 'border-tertiary/30 bg-tertiary/5' : 'border-amber-500/30 bg-amber-500/5',
              iconColor: rgpdOk ? 'text-tertiary' : 'text-amber-400',
            },
            {
              id: 'pci', label: 'PCI-DSS', icon: 'credit_card', ok: pciOk,
              description: 'Standard de sécurité des données pour les cartes de paiement.',
              issues: pciIssues,
              color: pciOk ? 'border-tertiary/30 bg-tertiary/5' : 'border-error/30 bg-error/5',
              iconColor: pciOk ? 'text-tertiary' : 'text-error',
            },
            {
              id: 'nist', label: 'NIST CSF', icon: 'policy', ok: nistOk,
              description: 'Cadre de cybersécurité NIST (Identify, Protect, Detect, Respond, Recover).',
              issues: nistIssues,
              color: nistOk ? 'border-tertiary/30 bg-tertiary/5' : 'border-error/30 bg-error/5',
              iconColor: nistOk ? 'text-tertiary' : 'text-error',
            },
          ];

          const conformCount = frameworks.filter(f => f.ok).length;
          const total = frameworks.length;
          const globalScore = Math.round((conformCount / total) * 100);
          const globalOk = conformCount === total;

          // PDF export
          const exportCompliancePDF = () => {
            const { jsPDF } = require('jspdf');
            const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
            const repo = currentScan?.repoUrl?.split('/').slice(-2).join('/') ?? 'repo';
            const date = new Date().toLocaleDateString('fr-FR');
            doc.setFillColor(15, 23, 42); doc.rect(0, 0, 210, 297, 'F');
            doc.setTextColor(164, 230, 255); doc.setFontSize(20); doc.setFont('helvetica','bold');
            doc.text('Rapport de Conformité', 20, 25);
            doc.setTextColor(200,200,200); doc.setFontSize(10); doc.setFont('helvetica','normal');
            doc.text(`Dépôt : ${repo}`, 20, 35);
            doc.text(`Scan #${selectedScanId} — Généré le ${date}`, 20, 41);
            doc.text(`Score global : ${conformCount}/${total} référentiels conformes (${globalScore}%)`, 20, 47);
            let y = 60;
            frameworks.forEach(fw => {
              doc.setFont('helvetica','bold');
              doc.setTextColor(fw.ok ? 0 : 220, fw.ok ? 200 : 50, fw.ok ? 80 : 50);
              doc.text(`${fw.ok ? '✔' : '✖'} ${fw.label}`, 20, y); y += 7;
              doc.setFont('helvetica','normal');
              doc.setTextColor(160,160,160);
              doc.text(fw.description, 25, y, { maxWidth: 160 }); y += 7;
              if (!fw.ok) {
                fw.issues.forEach(issue => {
                  doc.setTextColor(255, 100, 100);
                  doc.text(`  • ${issue}`, 25, y, { maxWidth: 155 }); y += 6;
                });
              }
              y += 4;
            });
            doc.save(`vulnix-compliance-scan${selectedScanId}.pdf`);
          };

          return (
            <div className="space-y-5">

              {/* ── Idée 2: OpenSCAP Real Data Panel ── */}
              {complianceLoading && (
                <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-6 flex items-center gap-3">
                  <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  <span className="text-sm text-outline">Chargement des résultats OpenSCAP...</span>
                </div>
              )}
              {!complianceLoading && complianceData?.available && complianceData.findings.length > 0 && (() => {
                const s = complianceData.summary;
                const scoreColor = s.score >= 80 ? 'text-tertiary' : s.score >= 50 ? 'text-amber-400' : 'text-error';
                const filteredFindings = complianceData.findings.filter(f =>
                  complianceFilter === 'all' ? true : f.result === complianceFilter
                );
                return (
                  <div className="glass-panel rounded-2xl border border-primary/20 bg-primary/5 p-5 space-y-4">
                    {/* Header */}
                    <div className="flex items-center gap-3">
                      <span className="material-symbols-outlined text-primary text-xl">shield_with_heart</span>
                      <div className="flex-1">
                        <h3 className="font-headline font-bold text-on-surface">Audit OpenSCAP — {complianceData.profile}</h3>
                        <p className="text-[10px] text-outline">Résultats réels du scan de conformité exécuté dans le conteneur</p>
                      </div>
                      <div className="text-right">
                        <div className={`text-2xl font-headline font-bold ${scoreColor}`}>{s.score}%</div>
                        <div className="text-[10px] text-outline">{s.pass} pass / {s.fail} fail</div>
                      </div>
                    </div>

                    {/* Stats bar */}
                    <div className="h-2 rounded-full bg-surface-container-low overflow-hidden">
                      <div className="h-full bg-tertiary rounded-full transition-all duration-500"
                        style={{ width: `${s.score}%` }} />
                    </div>
                    <div className="flex gap-4 text-[11px]">
                      <span className="text-error font-semibold">⛔ {s.highFail} HIGH fail</span>
                      <span className="text-amber-400 font-semibold">⚠️ {s.mediumFail} MEDIUM fail</span>
                      <span className="text-tertiary font-semibold">✅ {s.pass} pass</span>
                    </div>

                    {/* Filter buttons */}
                    <div className="flex gap-2">
                      {(['all', 'fail', 'pass'] as const).map(f => (
                        <button key={f} onClick={() => setComplianceFilter(f)}
                          className={`px-3 py-1 rounded-full text-[11px] font-semibold border transition-all ${
                            complianceFilter === f
                              ? 'bg-primary text-on-primary border-primary'
                              : 'bg-surface-container border-outline-variant/20 text-outline hover:text-on-surface'
                          }`}>
                          {f === 'all' ? `Tous (${s.totalRules})` : f === 'fail' ? `Fail (${s.fail})` : `Pass (${s.pass})`}
                        </button>
                      ))}
                    </div>

                    {/* Rules table */}
                    <div className="max-h-80 overflow-y-auto space-y-1.5 pr-1">
                      {filteredFindings.slice(0, 100).map((finding, i) => (
                        <div key={i} className={`flex items-start gap-3 px-3 py-2 rounded-xl border text-xs ${
                          finding.result === 'fail'
                            ? 'bg-error/5 border-error/20'
                            : finding.result === 'pass'
                            ? 'bg-tertiary/5 border-tertiary/15'
                            : 'bg-surface-container border-outline-variant/10'
                        }`}>
                          <span className={`material-symbols-outlined text-sm mt-0.5 shrink-0 ${
                            finding.result === 'fail' ? 'text-error' : finding.result === 'pass' ? 'text-tertiary' : 'text-outline'
                          }`}>{finding.result === 'fail' ? 'cancel' : finding.result === 'pass' ? 'check_circle' : 'help'}</span>
                          <div className="flex-1 min-w-0">
                            <p className="font-semibold text-on-surface truncate" title={finding.title}>{finding.title || finding.ruleId}</p>
                            {finding.description && (
                              <p className="text-outline mt-0.5 line-clamp-2">{finding.description}</p>
                            )}
                          </div>
                          <span className={`shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            finding.severity === 'high' ? 'bg-error text-on-error' :
                            finding.severity === 'medium' ? 'bg-amber-500 text-white' :
                            'bg-outline/20 text-outline'
                          }`}>{finding.severity.toUpperCase()}</span>
                        </div>
                      ))}
                      {filteredFindings.length > 100 && (
                        <p className="text-center text-xs text-outline py-2">... et {filteredFindings.length - 100} règles supplémentaires</p>
                      )}
                    </div>
                  </div>
                );
              })()}
              {!complianceLoading && complianceData && !complianceData.available && (
                <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-5 text-sm text-outline flex items-center gap-3">
                  <span className="material-symbols-outlined text-outline">info</span>
                  <div>
                    <p className="font-semibold text-on-surface">Audit OpenSCAP non disponible pour ce scan</p>
                    <p className="text-xs mt-0.5">Relancez un scan avec un profil de conformité (CIS_L1, NIST_800-53, PCI_DSS) pour obtenir des résultats OpenSCAP réels.</p>
                  </div>
                </div>
              )}

              {/* ── Existing simulated frameworks analysis ── */}
              <div className={`glass-panel rounded-2xl border p-5 flex flex-col sm:flex-row items-center gap-5 ${globalOk ? 'border-tertiary/30 bg-tertiary/5' : 'border-error/20 bg-error/5'}`}>
                <div className="relative shrink-0">
                  <svg viewBox="0 0 80 80" width="80" height="80">
                    <circle cx="40" cy="40" r="34" fill="none" stroke="#ffffff10" strokeWidth="8"/>
                    <circle cx="40" cy="40" r="34" fill="none"
                      stroke={globalOk ? '#00fc92' : globalScore >= 60 ? '#a4e6ff' : '#ffb4ab'}
                      strokeWidth="8" strokeLinecap="round"
                      strokeDasharray={`${2 * Math.PI * 34}`}
                      strokeDashoffset={`${2 * Math.PI * 34 * (1 - globalScore / 100)}`}
                      transform="rotate(-90 40 40)"
                    />
                    <text x="40" y="44" textAnchor="middle" fill={globalOk ? '#00fc92' : '#a4e6ff'} fontSize="18" fontWeight="700">{globalScore}%</text>
                  </svg>
                </div>
                <div className="flex-1">
                  <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Score de conformité global</p>
                  <p className={`text-2xl font-headline font-bold ${globalOk ? 'text-tertiary' : 'text-on-surface'}`}>
                    {conformCount}/{total} référentiels conformes
                  </p>
                  <p className="text-sm text-outline mt-1">
                    {globalOk ? '✔ Ce dépôt est conforme à tous les référentiels sélectionnés.' : `✖ ${total - conformCount} référentiel(s) non conforme(s) — actions requises.`}
                  </p>
                </div>
                <button
                  onClick={exportCompliancePDF}
                  className="shrink-0 flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary/10 border border-primary/20 text-primary text-sm font-semibold hover:bg-primary/20 transition-all"
                >
                  <span className="material-symbols-outlined text-base">download</span>
                  Exporter PDF
                </button>
              </div>

              {/* Framework cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
                {frameworks.map(fw => (
                  <div key={fw.id} className={`glass-panel rounded-2xl border p-5 flex flex-col gap-3 ${fw.color}`}>
                    <div className="flex items-center gap-3">
                      <span className={`material-symbols-outlined text-2xl ${fw.iconColor}`}>{fw.icon}</span>
                      <div className="flex-1">
                        <p className="font-headline font-bold text-on-surface text-sm">{fw.label}</p>
                        <p className="text-[10px] text-outline">{fw.description}</p>
                      </div>
                      <span className={`shrink-0 flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold border ${
                        fw.ok ? 'bg-tertiary/15 border-tertiary/40 text-tertiary' : 'bg-error/15 border-error/40 text-error'
                      }`}>
                        <span className="material-symbols-outlined text-xs">{fw.ok ? 'check_circle' : 'cancel'}</span>
                        {fw.ok ? 'Conforme' : 'Non conforme'}
                      </span>
                    </div>
                    {fw.ok ? (
                      <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-tertiary/10 border border-tertiary/20">
                        <span className="material-symbols-outlined text-tertiary text-sm">verified</span>
                        <p className="text-xs text-tertiary font-semibold">Aucun point bloquant détecté</p>
                      </div>
                    ) : (
                      <ul className="space-y-1.5">
                        {fw.issues.map((issue, i) => (
                          <li key={i} className="flex items-start gap-2 text-xs text-on-surface-variant">
                            <span className="material-symbols-outlined text-error text-xs mt-0.5 shrink-0">error</span>
                            {issue}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
              </div>

              {/* Bloc synthèse actions requises */}
              {frameworks.some(f => !f.ok) && (
                <div className="glass-panel rounded-2xl border border-amber-500/20 bg-amber-500/5 p-5">
                  <div className="flex items-center gap-2 mb-4">
                    <span className="material-symbols-outlined text-amber-400 text-lg">assignment_late</span>
                    <h3 className="font-headline font-bold text-on-surface">Actions requises pour mise en conformité</h3>
                  </div>
                  <div className="space-y-2">
                    {criticalCves.length > 0 && (
                      <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-error/5 border border-error/15">
                        <span className="material-symbols-outlined text-error text-sm mt-0.5 shrink-0">priority_high</span>
                        <p className="text-xs text-on-surface-variant"><span className="font-semibold text-error">URGENT</span> — Corriger les {criticalCves.length} CVE(s) CRITICAL : elles bloquent ISO 27001, PCI-DSS et NIST.</p>
                      </div>
                    )}
                    {secrets.length > 0 && (
                      <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-amber-500/5 border border-amber-500/15">
                        <span className="material-symbols-outlined text-amber-400 text-sm mt-0.5 shrink-0">key</span>
                        <p className="text-xs text-on-surface-variant">Supprimer les {secrets.length} secret(s) du code source et les déplacer dans un vault sécurisé (ISO 27001, RGPD).</p>
                      </div>
                    )}
                    {owaspHit.length > 0 && (
                      <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-primary/5 border border-primary/15">
                        <span className="material-symbols-outlined text-primary text-sm mt-0.5 shrink-0">bug_report</span>
                        <p className="text-xs text-on-surface-variant">Corriger les findings SAST OWASP : {owaspHit.join(', ')} — impact sur la conformité OWASP Top 10.</p>
                      </div>
                    )}
                    {kevCves.length > 0 && (
                      <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-error/5 border border-error/15">
                        <span className="material-symbols-outlined text-error text-sm mt-0.5 shrink-0">warning</span>
                        <p className="text-xs text-on-surface-variant">{kevCves.length} CVE(s) CISA KEV — exploitation active dans le monde réel, correctif obligatoire immédiat (PCI-DSS, NIST).</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })()}
      </section>

      {/* Floating Intelligence Card — only on CVE tab when a row is selected */}
      {!showLogs && activeTab === 'cve' && selected && (() => {
        const type = findingType(selected);
        const cat = findingCategory(type);
        const isPackageBased = type === 'CVE' || type === 'GHSA';
        return (
          <aside className="hidden lg:block w-[380px] shrink-0 p-4 self-start sticky top-24">
            <div className="glass-panel rounded-2xl border border-outline-variant/[0.2] shadow-2xl shadow-primary/10 overflow-hidden backdrop-blur-xl">

              {/* Card header */}
              <div className={`px-5 pt-5 pb-4 border-b border-outline-variant/[0.1] bg-surface-container-highest/30`}>
                <div className="flex items-center gap-2 mb-3 flex-wrap">
                  <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold border border-outline-variant/[0.15] ${cat.color}`}>
                    <span className="material-symbols-outlined text-xs">{cat.icon}</span>
                    {cat.label}
                  </span>
                  <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-bold ${severityBadge(selected.severity)}`}>
                    {selected.severity}
                  </span>
                  <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-bold bg-surface-container-highest text-outline border border-outline-variant/[0.15] uppercase">
                    {selected.source}
                  </span>
                  {selected.exploitAvailable && (
                    <a
                      href={selected.exploitUrl || `https://www.exploit-db.com/search?cve=${selected.cveId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-error text-on-error hover:opacity-80 transition-opacity"
                      title="Exploit public disponible"
                    >
                      <span className="material-symbols-outlined text-xs">bug_report</span>
                      Exploit Public
                    </a>
                  )}
                  {selected.kevListed && (
                    <span
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-amber-500 text-white"
                      title="Répertorié dans le catalogue CISA KEV (exploité activement)"
                    >
                      <span className="material-symbols-outlined text-xs">warning</span>
                      CISA KEV
                    </span>
                  )}
                  {selected.kevRansomware && (
                    <span
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-red-900 text-red-200"
                      title="Lié à une campagne ransomware connue"
                    >
                      <span className="material-symbols-outlined text-xs">coronavirus</span>
                      Ransomware
                    </span>
                  )}
                  {(() => {
                    const p = calcPriority(selected);
                    return (
                      <span
                        title={`Priorité IA: ${p.label} (score ${(p.score * 100).toFixed(0)}%)`}
                        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold border ${p.bgClass} ${p.color}`}
                      >{p.emoji} {p.label}</span>
                    );
                  })()}
                  {(() => {
                    const srcList = selected.sources ? selected.sources.split(',').map((s: string) => s.trim()).filter(Boolean) : [];
                    const count = selected.confirmedBy ?? srcList.length;
                    if (count >= 2) return (
                      <span
                        title={`Confirmé par ${count} outils: ${srcList.join(', ')}`}
                        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold ${count >= 3 ? 'bg-emerald-700 text-white' : 'bg-emerald-600 text-white'}`}
                      ><span className="material-symbols-outlined text-xs">verified</span>{count} outils</span>
                    );
                    if (srcList.length === 1) return (
                      <span
                        title={`Détecté par: ${srcList[0]}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-slate-600 text-white"
                      ><span className="material-symbols-outlined text-xs">sensors</span>1 outil</span>
                    );
                    return null;
                  })()}
                  {selected.affectedOs === 'LINUX' && (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-green-800 text-white" title="CVE spécifique Linux">
                      🐧 Linux
                    </span>
                  )}
                  {selected.affectedOs === 'WINDOWS' && (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-blue-700 text-white" title="CVE spécifique Windows">
                      🪟 Windows
                    </span>
                  )}
                  {fixedCveIds.has(selected.id) && (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-teal-600 text-white" title="Correctif appliqué via commit GitHub">
                      <span className="material-symbols-outlined text-xs">check_circle</span>CORRIGÉ
                    </span>
                  )}
                </div>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <h3 className="text-lg font-bold font-headline text-on-surface leading-tight break-all">{selected.cveId || 'Unknown'}</h3>
                    {selected.packageName && (
                      <p className="text-[10px] text-slate-500 mt-1 font-mono truncate" title={selected.packageName}>{selected.packageName}</p>
                    )}
                  </div>
                  {isPackageBased && (
                    <div className="text-right shrink-0">
                      <span className={`text-2xl font-bold font-headline ${severityLabel(selected.severity).color}`}>
                        {selected.cvssScore?.toFixed(1) || '—'}
                      </span>
                      <p className="text-[10px] text-slate-500">CVSS</p>
                      {selected.epssScore != null && (
                        <div className="mt-1">
                          <span className={`text-base font-bold font-headline ${epssInfo(selected.epssScore).text}`}>
                            {(selected.epssScore * 100).toFixed(1)}%
                          </span>
                          <p className="text-[10px] text-slate-500">EPSS</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Scrollable card body */}
              <div className="overflow-y-auto custom-scrollbar max-h-[calc(100vh-18rem)] flex flex-col gap-5 p-5">

                {/* Detail rows — Q2: Version → Fixed In → Source → Priorité → Temps estimé */}
                <div className={`rounded-xl border ${detailBorderColor(selected.severity)} bg-surface-container-highest/30 p-4 space-y-3`}>
                  {isPackageBased ? (
                    <>
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-500">Version</span>
                        <span className="text-on-surface font-mono">{selected.packageVersion || '—'}</span>
                      </div>
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-500">Fixed In</span>
                        <span className={`font-mono font-semibold ${selected.fixedVersion ? 'text-tertiary' : 'text-error'}`}>
                          {selected.fixedVersion || 'No fix available'}
                        </span>
                      </div>
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-500">Source</span>
                        <span className="text-on-surface font-semibold uppercase tracking-wide">{selected.source}</span>
                      </div>
                      {selected.confirmedBy >= 2 && (
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-500">Confirmation</span>
                          <span className="text-emerald-400 font-semibold">Détecté par {selected.confirmedBy} outils ({selected.sources})</span>
                        </div>
                      )}
                      {(() => {
                        const p = calcPriority(selected);
                        return (
                          <div className="flex justify-between items-center text-xs">
                            <span className="text-slate-500">Priorité IA</span>
                            <span className={`font-bold ${p.color} flex items-center gap-1`}>
                              {p.emoji} {p.label}
                              <span className="text-slate-500 font-normal">({(p.score * 100).toFixed(0)}%)</span>
                            </span>
                          </div>
                        );
                      })()}
                      <div className="flex justify-between items-center text-xs pt-1 border-t border-outline-variant/[0.1]">
                        <span className="text-slate-500 flex items-center gap-1">
                          <span className="material-symbols-outlined text-[12px]">schedule</span>
                          Temps estimé correction
                        </span>
                        <span className="font-semibold text-primary">{estimatedFixTime(selected)}</span>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-500">Rule</span>
                        <span className="text-on-surface font-mono truncate ml-4 text-right max-w-[180px]" title={selected.packageName || ''}>
                          {selected.packageName ? (selected.packageName.length > 38 ? '...' + selected.packageName.slice(-35) : selected.packageName) : '—'}
                        </span>
                      </div>
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-500">Severity</span>
                        <span className={`font-bold ${severityLabel(selected.severity).color}`}>{selected.severity}</span>
                      </div>
                      {selected.filePath && (
                        <div className="text-xs">
                          <span className="text-slate-500 block mb-1">Location</span>
                          <span className="text-primary font-mono text-[11px] break-all leading-relaxed" title={selected.filePath}>
                            {(() => {
                              const parts = selected.filePath.split('/');
                              const fileName = parts.pop() || '';
                              const short = parts.length > 3
                                ? parts.slice(0, 1).join('/') + '/.../' + parts.slice(-1).join('/') + '/' + fileName
                                : selected.filePath;
                              return short + (selected.lineNumber ? `:${selected.lineNumber}` : '');
                            })()}
                          </span>
                        </div>
                      )}
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-500">Source</span>
                        <span className="text-on-surface uppercase">{selected.source}</span>
                      </div>
                    </>
                  )}
                </div>

                {/* Q3 — Description simplifiée (first 3 sentences) + full toggle */}
                {(() => {
                  const desc = selected.description || '';
                  const sentences = desc.match(/[^.!?]+[.!?]+/g) || [];
                  const simplified = sentences.slice(0, 3).join(' ').trim() || desc.slice(0, 250);
                  const isTruncated = simplified.length < desc.length;
                  return (
                    <div className="space-y-2">
                      <h4 className="text-[10px] font-bold font-headline text-slate-400 uppercase tracking-widest">Description</h4>
                      <p className="text-sm text-on-surface-variant leading-relaxed">
                        {simplified || 'No description available.'}
                        {isTruncated && <span className="text-slate-600">…</span>}
                      </p>
                    </div>
                  );
                })()}

                {/* Q3 — Action Recommandée pour TOUS les CVEs */}
                <div className="space-y-2 rounded-xl bg-primary/5 border border-primary/15 p-3">
                  <h4 className="text-[10px] font-bold font-headline text-primary/70 uppercase tracking-widest flex items-center gap-1">
                    <span className="material-symbols-outlined text-xs">bolt</span>
                    Action Recommandée
                  </h4>
                  <p className="text-sm text-on-surface-variant leading-relaxed">
                    {isPackageBased ? (
                      selected.fixedVersion
                        ? `Mettre à jour ${selected.packageName || 'ce package'} vers la version ${selected.fixedVersion.split(/[,;]/)[0].trim()} pour corriger cette vulnérabilité.`
                        : `Aucune version corrigée disponible. Envisagez de remplacer ${selected.packageName || 'cette dépendance'} ou d'isoler ce composant en attendant un correctif officiel.`
                    ) : (() => {
                      const cwe = selected.cveId || '';
                      const rule = selected.packageName || '';
                      if (cwe.startsWith('CWE-798') || rule.includes('secret') || rule.includes('credential') || rule.includes('password'))
                        return 'Supprimez les secrets codés en dur et utilisez des variables d\'environnement ou un gestionnaire de secrets sécurisé.';
                      if (cwe.startsWith('CWE-330') || rule.includes('weak-random'))
                        return 'Utilisez des générateurs de nombres aléatoires cryptographiquement sécurisés (ex: SecureRandom).';
                      if (cwe.startsWith('CWE-79') || rule.includes('xss'))
                        return 'Assainissez et échappez toutes les entrées utilisateur avant de les afficher en HTML pour prévenir les attaques XSS.';
                      if (cwe.startsWith('CWE-89') || rule.includes('sql-injection'))
                        return 'Utilisez des requêtes paramétrées ou des prepared statements pour prévenir les injections SQL.';
                      if (cwe.startsWith('CWE-22') || rule.includes('path-traversal'))
                        return 'Validez et assainissez les chemins de fichiers. Utilisez des listes blanches et des vérifications de chemin canonique.';
                      if (cwe.startsWith('CWE-502') || rule.includes('deserialization'))
                        return 'Évitez de désérialiser des données non fiables. Utilisez des alternatives sûres ou un filtrage strict des types.';
                      if (cwe.startsWith('CWE-327') || rule.includes('weak-crypto') || rule.includes('cipher'))
                        return 'Remplacez les algorithmes cryptographiques faibles (MD5, SHA1, DES) par des alternatives modernes (SHA-256, AES-256).';
                      if (cwe.startsWith('CWE-611') || rule.includes('xxe'))
                        return 'Désactivez le traitement des entités externes dans les parseurs XML pour prévenir les injections XXE.';
                      if (cwe.startsWith('CWE-918') || rule.includes('ssrf'))
                        return 'Validez et restreignez les URLs sortantes. Utilisez des listes blanches pour prévenir le SSRF.';
                      if (cwe.startsWith('CWE-352') || rule.includes('csrf'))
                        return 'Implémentez des tokens CSRF pour toutes les requêtes modifiant l\'état.';
                      return 'Examinez le code signalé et appliquez le correctif recommandé par la documentation de la règle.';
                    })()}
                  </p>
                </div>

                {/* Reference */}
                {(selected.dataSource || isPackageBased) && (
                  <div className="space-y-2">
                    <h4 className="text-[10px] font-bold font-headline text-slate-400 uppercase tracking-widest">Reference</h4>
                    {selected.dataSource ? (
                      <a
                        href={selected.dataSource.startsWith('http') ? selected.dataSource : `https://nvd.nist.gov/vuln/detail/${selected.cveId}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-primary hover:underline break-all"
                      >
                        {selected.dataSource}
                      </a>
                    ) : (
                      <span className="text-xs text-slate-500">—</span>
                    )}
                  </div>
                )}

                {/* Exploit-DB */}
                {selected.exploitAvailable && (
                  <div className="space-y-2">
                    <h4 className="text-[10px] font-bold font-headline text-slate-400 uppercase tracking-widest">Exploit Public</h4>
                    <a
                      href={selected.exploitUrl || `https://www.exploit-db.com/search?cve=${selected.cveId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-error/10 border border-error/20 text-error text-xs font-semibold hover:bg-error/20 transition-colors w-full"
                    >
                      <span className="material-symbols-outlined text-sm">bug_report</span>
                      Voir l'exploit sur Exploit-DB
                      <span className="material-symbols-outlined text-xs ml-auto">open_in_new</span>
                    </a>
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                      Un code d'exploitation public existe pour cette vulnérabilité. Le risque est concret et immédiat — priorisez ce correctif.
                    </p>
                  </div>
                )}

                {/* CISA KEV */}
                {selected.kevListed && (
                  <div className="space-y-2">
                    <h4 className="text-[10px] font-bold font-headline text-slate-400 uppercase tracking-widest">CISA KEV</h4>
                    <div className="flex items-start gap-3 px-3 py-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20">
                      <span className="material-symbols-outlined text-amber-500 text-base mt-0.5">warning</span>
                      <div className="flex-1">
                        <p className="text-xs font-semibold text-amber-700">Exploitée activement dans le monde réel</p>
                        {selected.kevDateAdded && (
                          <p className="text-[11px] text-slate-500 mt-0.5">Ajoutée au catalogue CISA : {selected.kevDateAdded}</p>
                        )}
                        {selected.kevRansomware && (
                          <p className="text-[11px] text-red-500 font-semibold mt-0.5">⚠️ Liée à des campagnes ransomware connues</p>
                        )}
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                      Cette CVE figure dans le catalogue officiel CISA KEV — des attaquants réels l'utilisent activement. Correctif obligatoire en urgence.
                    </p>
                  </div>
                )}

                {/* EPSS Score */}
                {selected.epssScore != null && (
                  <div className="space-y-2">
                    <h4 className="text-[10px] font-bold font-headline text-slate-400 uppercase tracking-widest">Score EPSS</h4>
                    <div className="px-3 py-2.5 rounded-lg bg-surface-container-highest border border-outline-variant/[0.15]">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs text-slate-500">Probabilité d'exploitation (30j)</span>
                        <span className={`text-sm font-bold font-headline ${epssInfo(selected.epssScore).text}`}>
                          {(selected.epssScore * 100).toFixed(2)}%
                        </span>
                      </div>
                      <div className="w-full h-2 rounded-full bg-surface-container overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${epssInfo(selected.epssScore).bar}`}
                          style={{ width: `${Math.min(selected.epssScore * 100, 100)}%` }}
                        />
                      </div>
                      {selected.epssPercentile != null && (
                        <p className="text-[11px] text-slate-500 mt-2">
                          Percentile : <span className={`font-semibold ${epssInfo(selected.epssScore).text}`}>
                            top {((1 - selected.epssPercentile) * 100).toFixed(1)}%
                          </span> — plus dangereuse que {(selected.epssPercentile * 100).toFixed(1)}% des CVEs connues
                        </p>
                      )}
                      <p className={`text-[11px] font-semibold mt-1 ${epssInfo(selected.epssScore).text}`}>
                        Niveau : {epssInfo(selected.epssScore).label}
                      </p>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                      L'EPSS (FIRST.org) prédit la probabilité qu'un attaquant exploite cette CVE dans les 30 prochains jours, basé sur des données de threat intelligence réelles.
                    </p>
                  </div>
                )}

                {/* ── Auto-fix button ── only for dependency CVEs with a known fix */}
                {isPackageBased && selected.fixedVersion && extractRepoFullName(currentScan?.repoUrl ?? '', currentScan?.gitProvider) && (
                  <div className="space-y-2 pt-1">
                    <h4 className="text-[10px] font-bold font-headline text-slate-400 uppercase tracking-widest">Correctif automatique</h4>
                    {groupCount > 1 && (
                      <div className="flex items-start gap-2 px-3 py-2.5 rounded-lg bg-primary/10 border border-primary/20 text-xs">
                        <span className="material-symbols-outlined text-sm text-primary shrink-0 mt-0.5">auto_awesome</span>
                        <div>
                          <p className="font-semibold text-primary">Correctif groupé — {groupCount} CVEs résolus</p>
                          <p className="text-slate-500 mt-0.5 leading-relaxed">
                            Aussi : {selectedGroup.filter(c => c.id !== selected.id).map(c => c.cveId).join(', ')}
                          </p>
                        </div>
                      </div>
                    )}
                    {fixError && (
                      <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-error/10 border border-error/20 text-error text-xs">
                        <span className="material-symbols-outlined text-sm shrink-0 mt-0.5">error</span>
                        <span className="break-words">{fixError}</span>
                      </div>
                    )}
                    {fixedCveIds.has(selected.id) ? (
                      /* ── Already fixed state ── */
                      <div className="flex flex-col gap-2">
                        <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-teal-500/10 border border-teal-500/30 text-teal-400 text-sm font-semibold">
                          <span className="material-symbols-outlined text-base">check_circle</span>
                          {groupCount > 1 ? `${groupCount} CVEs déjà corrigés` : 'Déjà corrigé'}
                        </div>
                        {applySuccess?.startsWith('http') && (
                          <a
                            href={applySuccess}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center justify-center gap-2 w-full px-4 py-2 rounded-xl bg-primary/10 border border-primary/20 text-primary text-xs font-semibold hover:bg-primary/20 transition-all"
                          >
                            <span className="material-symbols-outlined text-sm">open_in_new</span>
                            Voir le commit sur GitHub
                          </a>
                        )}
                        <p className="text-[10px] text-slate-500 text-center">
                          {selected.packageName} a été mis à jour vers {groupMaxFix || (selected.fixedVersion ?? '').split(/[,;]/)[0].trim()} via commit
                        </p>
                      </div>
                    ) : (
                      /* ── Normal fix button ── */
                      <>
                        <button
                          onClick={() => handleRequestFix(selected)}
                          disabled={fixLoading}
                          className="flex items-center justify-center gap-2 w-full px-4 py-2.5 rounded-xl bg-primary/10 border border-primary/30 text-primary text-sm font-semibold hover:bg-primary/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {fixLoading
                            ? <><span className="material-symbols-outlined text-base animate-spin">progress_activity</span> Génération du correctif...</>
                            : <><span className="material-symbols-outlined text-base">auto_fix_high</span> {groupCount > 1 ? `Corriger automatiquement ${groupCount} CVEs` : 'Corriger automatiquement'}</>
                          }
                        </button>
                        <p className="text-[10px] text-slate-500 text-center">
                          Génère un diff pour mettre à jour {selected.packageName} vers {groupMaxFix || (selected.fixedVersion ?? '').split(/[,;]/)[0].trim()}
                        </p>
                      </>
                    )}
                  </div>
                )}

              </div>
            </div>
          </aside>
        );
      })()}

      {/* ── Auto-fix Diff Modal ─────────────────────────────────────────────── */}
      {fixPreview && (() => {
        const diff = computeDiff(fixPreview.originalLines, fixPreview.fixedLines);
        const changedCount = diff.filter(l => l.type !== 'unchanged').length;
        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <div className="w-full max-w-4xl max-h-[90vh] flex flex-col glass-panel rounded-2xl border border-outline-variant/[0.2] shadow-2xl overflow-hidden">

              {/* Modal header */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-outline-variant/[0.1] bg-surface-container-highest/40 shrink-0">
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-primary">auto_fix_high</span>
                  <div>
                    <p className="font-bold font-headline text-on-surface text-sm">Correctif automatique — {fixPreview.filePath}</p>
                    <p className="text-[10px] text-slate-500">{changedCount} ligne(s) modifiée(s) · {fixPreview.repoFullName}</p>
                  </div>
                </div>
                <button
                  onClick={() => { setFixPreview(null); setApplySuccess(null); setFixError(null); }}
                  className="p-1.5 rounded-lg hover:bg-surface-container-high transition-colors text-outline hover:text-on-surface"
                >
                  <span className="material-symbols-outlined text-lg">close</span>
                </button>
              </div>

              {/* Diff legend */}
              <div className="flex items-center gap-4 px-6 py-2 border-b border-outline-variant/[0.08] bg-surface-container-lowest/60 shrink-0">
                <div className="flex gap-1.5 items-center text-[10px] text-red-400"><span className="w-3 h-3 rounded-sm bg-red-500/20 border border-red-500/40 inline-block" /> Supprimé</div>
                <div className="flex gap-1.5 items-center text-[10px] text-emerald-400"><span className="w-3 h-3 rounded-sm bg-emerald-500/20 border border-emerald-500/40 inline-block" /> Ajouté</div>
                <div className="flex gap-1.5 items-center text-[10px] text-slate-500"><span className="w-3 h-3 rounded-sm bg-surface-container-highest inline-block border border-outline-variant/20" /> Inchangé</div>
                <span className="ml-auto text-[10px] text-slate-500">{diff.filter(l => l.type === 'removed').length} suppression(s) · {diff.filter(l => l.type === 'added').length} ajout(s)</span>
              </div>
              {fixPreview.lockFilePath && (
                <div className="flex items-center gap-2 px-6 py-2 border-b border-outline-variant/[0.08] bg-teal-500/5 shrink-0">
                  <span className="material-symbols-outlined text-teal-400 text-sm">lock</span>
                  <p className="text-[10px] text-teal-300">
                    <span className="font-semibold">Lock file automatiquement patché :</span>{' '}
                    <span className="font-mono">{fixPreview.lockFilePath}</span> sera aussi mis à jour — le prochain scan ne détectera plus ce CVE.
                  </p>
                </div>
              )}

              {/* Diff viewer */}
              <div className="flex-1 overflow-y-auto custom-scrollbar font-mono text-xs bg-surface-container-lowest/80">
                {diff.map((line, i) => (
                  <div
                    key={i}
                    className={`flex items-start gap-0 border-b border-outline-variant/[0.04] ${
                      line.type === 'removed' ? 'bg-red-500/[0.08]' :
                      line.type === 'added'   ? 'bg-emerald-500/[0.08]' : ''
                    }`}
                  >
                    {/* Gutter: line number + sign */}
                    <span className="shrink-0 w-10 py-1 px-2 text-right text-slate-600 text-[10px] select-none border-r border-outline-variant/[0.08]">
                      {line.lineNo}
                    </span>
                    <span className={`shrink-0 w-6 py-1 text-center select-none font-bold text-sm ${
                      line.type === 'removed' ? 'text-red-400' :
                      line.type === 'added'   ? 'text-emerald-400' : 'text-slate-700'
                    }`}>
                      {line.type === 'removed' ? '−' : line.type === 'added' ? '+' : ' '}
                    </span>
                    {/* Line content */}
                    <span className={`flex-1 py-1 pl-2 pr-4 whitespace-pre-wrap break-all leading-relaxed ${
                      line.type === 'removed' ? 'text-red-300' :
                      line.type === 'added'   ? 'text-emerald-300' : 'text-on-surface-variant'
                    }`}>
                      {line.line}
                    </span>
                  </div>
                ))}
              </div>

              {/* Modal footer */}
              <div className="flex items-center gap-3 px-6 py-4 border-t border-outline-variant/[0.1] bg-surface-container-highest/40 shrink-0">
                {applySuccess ? (
                  <>
                    <div className="flex flex-col flex-1 min-w-0">
                      <div className="flex items-center gap-2 text-tertiary text-sm font-semibold">
                        <span className="material-symbols-outlined text-base">check_circle</span>
                        {groupCount > 1 ? `${groupCount} CVEs résolus — Commit poussé !` : 'Commit poussé sur GitHub !'}
                      </div>
                      {groupCount > 1 && (
                        <p className="text-[10px] text-slate-500 mt-0.5 ml-6">
                          {selectedGroup.map(c => c.cveId).join(', ')}
                        </p>
                      )}
                    </div>
                    <button
                      onClick={() => { setFixPreview(null); setApplySuccess(null); setFixError(null); }}
                      className="px-4 py-2 rounded-xl text-sm text-outline hover:text-on-surface hover:bg-surface-container-high transition-all"
                    >
                      Fermer
                    </button>
                    {applySuccess.startsWith('http') && (
                      <a
                        href={applySuccess}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 px-5 py-2 rounded-xl bg-primary text-on-primary text-sm font-bold hover:opacity-90 transition-all"
                      >
                        <span className="material-symbols-outlined text-sm">open_in_new</span>
                        Voir sur GitHub
                      </a>
                    )}
                  </>
                ) : (
                  <>
                    <button
                      onClick={() => { setFixPreview(null); setFixError(null); }}
                      className="px-4 py-2 rounded-xl text-sm text-outline hover:text-on-surface hover:bg-surface-container-high transition-all"
                    >
                      Annuler
                    </button>
                    <div className="flex-1 text-xs text-slate-500 text-center">
                      Fichier : <span className="text-primary font-mono">{fixPreview.filePath}</span> · Dépôt : <span className="text-primary">{fixPreview.repoFullName}</span>
                    </div>
                    <button
                      onClick={handleApplyFix}
                      disabled={applyLoading || changedCount === 0}
                      className="flex items-center gap-2 px-5 py-2 rounded-xl bg-tertiary text-on-tertiary text-sm font-bold hover:opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {applyLoading
                        ? <><span className="material-symbols-outlined text-sm animate-spin">progress_activity</span> Application...</>
                        : <><span className="material-symbols-outlined text-sm">commit</span> Appliquer le commit</>
                      }
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
};

export default Vulnerabilities;

