import React, { useRef, useState, useEffect } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { startSslScan, getSslResult, getAllScans, deleteScan, createScheduledScan, SslResultDto, ScanResultDto, getSslAiAnalysis, apiUrl } from '../services/api';
import type { ScheduleType, TlsProtocolDetailDto, TlsCipherSuiteDto, TlsProtocolStatus } from '../services/api';
import CertificateDetailSection from '../components/CertificateDetailSection';
import SslVulnerabilitiesSection from '../components/SslVulnerabilitiesSection';
import SslSecurityHeadersSection from '../components/SslSecurityHeadersSection';
import { computeHttpHeadersCategoryScore, computeHeadersSummary, badgeLabel } from '../components/sslHeaderModel';
import { buildVulnPresentations, statusLabel, severityLabel, confidenceLabel, buildSectionConclusion } from '../components/sslVulnModel';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

/* ═══════════════════════════════════════════════════════════════════════
   Types
═══════════════════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════════════════
   Vuln status & confidence helpers
═══════════════════════════════════════════════════════════════════════ */
type SourceValue    = boolean | null | undefined | 'timeout' | 'error';
export type VulnStatus     = 'confirmed' | 'to_confirm' | 'secure' | 'indeterminate' | 'not_tested';
export type ConfidenceLevel = 'Haute' | 'Moyenne' | 'Faible';

function getVulnStatus(sources: SourceValue[]): VulnStatus {
  const tested   = sources.filter(s => s === true || s === false);
  const positive = tested.filter(s => s === true);
  const failed   = sources.filter(s => s === 'timeout' || s === 'error');
  if (tested.length === 0 && failed.length > 0) return 'indeterminate';
  if (tested.length === 0) return 'not_tested';
  if (positive.length >= 2) return 'confirmed';
  if (positive.length === 1) return 'to_confirm';
  return 'secure';
}

interface LogLine { ts: string; level: 'INFO' | 'WARN' | 'ERROR' | 'plain'; text: string; }

function parseLog(raw: string): LogLine {
  const m = raw.match(/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+(.*)/);
  if (!m) return { ts: '', level: 'plain', text: raw };
  const msg = m[2];
  const level = msg.startsWith('[ERROR]') ? 'ERROR'
    : msg.startsWith('[WARN]') ? 'WARN'
    : 'INFO';
  return { ts: m[1], level, text: msg };
}

/* ═══════════════════════════════════════════════════════════════════════
   Grade helpers
═══════════════════════════════════════════════════════════════════════ */
function gradeColor(g: string) {
  if (g === 'A+') return { ring: '#00fc92', text: '#00fc92', bg: 'rgba(0,252,146,.08)' };
  if (g === 'A')  return { ring: '#a4e6ff', text: '#a4e6ff', bg: 'rgba(164,230,255,.08)' };
  if (g === 'B')  return { ring: '#ffe066', text: '#ffe066', bg: 'rgba(255,224,102,.08)' };
  if (g === 'C')  return { ring: '#ffaa40', text: '#ffaa40', bg: 'rgba(255,170,64,.08)' };
  if (g === 'D')  return { ring: '#ff7b54', text: '#ff7b54', bg: 'rgba(255,123,84,.08)' };
  return           { ring: '#ffb4ab', text: '#ffb4ab', bg: 'rgba(255,180,171,.08)' };
}

function gradeLabel(g: string) {
  if (g === 'A+') return 'Excellente sécurité';
  if (g === 'A')  return 'Bonne sécurité';
  if (g === 'B')  return 'Protocoles dépréciés';
  if (g === 'C')  return 'Chiffrement faible';
  if (g === 'D')  return 'Certificat problématique';
  if (g === 'F')  return 'Vulnérabilité critique';
  return 'En cours...';
}

/* ═══════════════════════════════════════════════════════════════════════
   Extended types: Risk, Source, Score breakdown
═══════════════════════════════════════════════════════════════════════ */
export type RiskLevel   = 'Critique' | 'Élevé' | 'Moyen' | 'Faible';
type SourceName  = 'kali' | 'ssllabs' | 'censys' | 'sslyze' | 'openssl' | 'headers';

export type ScoreBreakdown = {
  tls:             number;  // /25
  certificate:     number;  // /25
  vulnerabilities: number;  // /30
  headers:         number;  // /20
  total:           number;  // /100
  grade:           string;
  riskLevel:       RiskLevel;
  confidence:      ConfidenceLevel;
  consensus:       { level: 'Fort' | 'Moyen' | 'Faible'; pct: number };
  hblStatus:       VulnStatus;
  penalties: Array<{
    label:    string;
    points:   number;
    category: 'tls' | 'certificate' | 'vulnerabilities' | 'headers';
  }>;
};

/* ═══════════════════════════════════════════════════════════════════════
   getGrade — A+ to F with E
═══════════════════════════════════════════════════════════════════════ */
function getGrade(score: number): string {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  if (score >= 50) return 'E';
  return 'F';
}

/* ═══════════════════════════════════════════════════════════════════════
   calculateRiskLevel — niveau de risque indépendant du grade technique
═══════════════════════════════════════════════════════════════════════ */
function calculateRiskLevel(score: number, hblStatus: VulnStatus, critVulnStatuses: VulnStatus[]): RiskLevel {
  if (hblStatus === 'confirmed' || critVulnStatuses.some(s => s === 'confirmed')) return 'Critique';
  if (hblStatus === 'to_confirm' || critVulnStatuses.some(s => s === 'to_confirm')) return 'Élevé';
  if (score < 60) return 'Élevé';
  if (score < 80) return 'Moyen';
  return 'Faible';
}

/* ═══════════════════════════════════════════════════════════════════════
   calculateSourceConsensus — accord inter-sources sur les checks multi-sources
═══════════════════════════════════════════════════════════════════════ */
function calculateSourceConsensus(result: SslResultDto): { level: 'Fort' | 'Moyen' | 'Faible'; pct: number } {
  const multiSourceChecks: SourceValue[][] = [
    [result.heartbleed ?? undefined, result.sslyzeHeartbleed ?? undefined],
    [result.robot      ?? undefined, result.sslyzeRobot       ?? undefined],
    [result.crime      ?? undefined, result.sslyzeCompression ?? undefined],
    [result.drown      ?? undefined, result.ssllabsDrown      ?? undefined],
  ];
  let agreeing = 0, total = 0;
  for (const srcs of multiSourceChecks) {
    const tested = srcs.filter(s => s === true || s === false);
    if (tested.length >= 2) {
      total++;
      if (tested.every(s => s === tested[0])) agreeing++;
    }
  }
  if (total === 0) return { level: 'Faible', pct: 0 };
  const pct = agreeing / total;
  return { level: pct >= 0.8 ? 'Fort' : pct >= 0.55 ? 'Moyen' : 'Faible', pct: Math.round(pct * 100) };
}

/* ═══════════════════════════════════════════════════════════════════════
   computeScoreBreakdown — calcul centralisé du score par catégories
   TLS (25pts earned) + Cert (25pts earned) + Vulns (30pts deduction) + Headers (20pts earned)
═══════════════════════════════════════════════════════════════════════ */
export function computeScoreBreakdown(result: SslResultDto): ScoreBreakdown {
  const penalties: ScoreBreakdown['penalties'] = [];

  // ── TLS et protocoles — 25 pts (points gagnés)
  let tls = 0;
  if (result.tls13 || result.sslyzeSupportsTLS13)            tls += 8;
  else penalties.push({ label: 'TLS 1.3 absent',                              points: 8, category: 'tls' });
  if (result.tls12 || result.sslyzeSupportsTLS12)            tls += 5;
  else penalties.push({ label: 'TLS 1.2 absent',                              points: 5, category: 'tls' });
  if (!result.tls10 && !result.sslyzeSupportsTLS10)          tls += 4;
  else penalties.push({ label: 'TLS 1.0 encore actif',                        points: 4, category: 'tls' });
  if (!result.tls11 && !result.sslyzeSupportsTLS11)          tls += 4;
  else penalties.push({ label: 'TLS 1.1 encore actif',                        points: 4, category: 'tls' });
  if (!result.has3des && !result.rc4)                        tls += 4;
  else penalties.push({ label: 'Ciphers faibles actifs (3DES/RC4)',            points: 4, category: 'tls' });
  tls = Math.min(25, Math.max(0, tls));

  // ── Certificat — 25 pts (points gagnés)
  let cert = 0;
  if (!result.certExpired)                                   cert += 8;
  else penalties.push({ label: 'Certificat expiré',                           points: 8,  category: 'certificate' });
  if (result.chainComplete || result.sslyzeChainTrusted)     cert += 5;
  else penalties.push({ label: 'Chaîne de confiance incomplète',              points: 5,  category: 'certificate' });
  cert += 4; // Domain/SAN match — assumé si le certificat n'est pas expiré
  if (result.chainComplete || result.sslyzeChainTrusted)     cert += 3;
  if (result.certDaysLeft > 30)                              cert += 3;
  else if (result.certDaysLeft >= 0)
    penalties.push({ label: `Certificat expire dans ${result.certDaysLeft}j`,  points: 3,  category: 'certificate' });
  // OCSP Stapling compte dans le certificat (plus dans les en-têtes HTTP)
  if (result.ocspStapling || result.sslyzeOcspStapling
      || result.certificateDetail?.ocspStaplingStatus === 'CONFORME') {
    cert += 2;
  } else {
    penalties.push({ label: 'OCSP Stapling non détecté', points: 2, category: 'certificate' });
  }
  cert = Math.min(25, Math.max(0, cert));

  // ── Vulnérabilités — 30 pts (déductions) — aligné sur la section vulnérabilités
  let vuln = 30;

  const hblSrcs: SourceValue[] = [result.heartbleed ?? undefined, result.sslyzeHeartbleed ?? undefined];
  const hblSt = getVulnStatus(hblSrcs);
  if      (hblSt === 'confirmed')    { vuln -= 12; penalties.push({ label: 'Heartbleed confirmé (≥2 sources)',           points: 12, category: 'vulnerabilities' }); }
  else if (hblSt === 'to_confirm')   { vuln -= 7;  penalties.push({ label: 'Heartbleed à confirmer (1 source)',          points: 7,  category: 'vulnerabilities' }); }
  else if (hblSt === 'indeterminate'){ vuln -= 2;  penalties.push({ label: 'Heartbleed indéterminé (timeout/erreur)',    points: 2,  category: 'vulnerabilities' }); }

  if (result.poodle === true)        { vuln -= 12; penalties.push({ label: 'POODLE confirmé (SSL 3.0 actif)',            points: 12, category: 'vulnerabilities' }); }

  const drownSrcs: SourceValue[] = [result.drown ?? undefined, result.ssllabsDrown ?? undefined];
  const drownSt = getVulnStatus(drownSrcs);
  if      (drownSt === 'confirmed')  { vuln -= 12; penalties.push({ label: 'DROWN confirmé',                            points: 12, category: 'vulnerabilities' }); }
  else if (drownSt === 'to_confirm') { vuln -= 7;  penalties.push({ label: 'DROWN à confirmer',                         points: 7,  category: 'vulnerabilities' }); }

  const robotSrcs: SourceValue[] = [result.robot ?? undefined, result.sslyzeRobot ?? undefined];
  const robotSt = getVulnStatus(robotSrcs);
  if      (robotSt === 'confirmed')  { vuln -= 6;  penalties.push({ label: 'ROBOT confirmé',                            points: 6,  category: 'vulnerabilities' }); }
  else if (robotSt === 'to_confirm') { vuln -= 3;  penalties.push({ label: 'ROBOT à confirmer',                         points: 3,  category: 'vulnerabilities' }); }

  if (result.sweet32)                { vuln -= 3;  penalties.push({ label: 'SWEET32 détecté',                          points: 3,  category: 'vulnerabilities' }); }
  const crimeSrcs: SourceValue[] = [result.crime ?? undefined, result.sslyzeCompression ?? undefined];
  const crimeSt = getVulnStatus(crimeSrcs);
  if (crimeSt === 'confirmed' || crimeSt === 'to_confirm')
                                     { vuln -= 3;  penalties.push({ label: 'CRIME détecté',                            points: 3,  category: 'vulnerabilities' }); }
  if (result.beast)                  { vuln -= 1;  penalties.push({ label: 'BEAST détecté',                            points: 1,  category: 'vulnerabilities' }); }
  if (result.freak)                  { vuln -= 2;  penalties.push({ label: 'FREAK détecté',                            points: 2,  category: 'vulnerabilities' }); }
  if (result.logjam)                 { vuln -= 2;  penalties.push({ label: 'Logjam détecté',                           points: 2,  category: 'vulnerabilities' }); }
  if (result.rc4)                    { vuln -= 3;  penalties.push({ label: 'RC4 détecté',                              points: 3,  category: 'vulnerabilities' }); }
  if (result.has3des)                { vuln -= 2;  penalties.push({ label: 'Chiffrement 3DES accepté',                  points: 2,  category: 'vulnerabilities' }); }
  vuln = Math.max(0, vuln);

  // ── En-têtes HTTP — 20 pts (protections principales uniquement ; pas OCSP / COOP / CORP / COEP)
  const headersScore = computeHttpHeadersCategoryScore(result);
  const headers = headersScore.score;
  penalties.push(...headersScore.penalties);

  const total     = tls + cert + vuln + headers;
  const grade     = getGrade(total);
  const consensus = calculateSourceConsensus(result);

  const sourcesUp = [result.sslyzeStatus, result.ssllabsStatus, result.censysStatus].filter(s => s === 'READY').length;
  const confidence: ConfidenceLevel = sourcesUp >= 3 && consensus.level === 'Fort' ? 'Haute'
    : sourcesUp >= 2 ? 'Moyenne' : 'Faible';

  const riskLevel = calculateRiskLevel(total, hblSt, [
    getVulnStatus([result.poodle ?? undefined]),
    drownSt,
  ]);

  return { tls, certificate: cert, vulnerabilities: vuln, headers, total, grade, riskLevel, confidence, consensus, hblStatus: hblSt, penalties };
}

/* ═══════════════════════════════════════════════════════════════════════
   TLS protocol section helpers
═══════════════════════════════════════════════════════════════════════ */
const TLS_PROTO_ORDER = ['tls13', 'tls12', 'tls11', 'tls10', 'ssl30', 'ssl20'] as const;
const TLS_PROTO_LABELS: Record<string, string> = {
  tls13: 'TLS 1.3', tls12: 'TLS 1.2', tls11: 'TLS 1.1', tls10: 'TLS 1.0',
  ssl30: 'SSL 3.0', ssl20: 'SSL 2.0',
};
const MODERN_PROTO_IDS = new Set(['tls13', 'tls12']);
const OBSOLETE_PROTO_IDS = new Set(['tls11', 'tls10', 'ssl30', 'ssl20']);

function protocolStatusLabel(status: TlsProtocolStatus | string): string {
  switch (status) {
    case 'ENABLED': return 'Activé';
    case 'DISABLED': return 'Désactivé';
    case 'INCONCLUSIVE': return 'Résultat inconclusif';
    default: return 'Non testé';
  }
}

function protocolStatusMeta(status: TlsProtocolStatus | string, obsolete: boolean) {
  if (status === 'ENABLED' && obsolete) {
    return { icon: 'dangerous', color: 'text-error', border: 'border-error/40', bg: 'bg-error/[0.06]', badge: 'bg-error/15 text-error' };
  }
  if (status === 'ENABLED') {
    return { icon: 'check_circle', color: 'text-[#a4e6ff]', border: 'border-[#a4e6ff]/40', bg: 'bg-[#a4e6ff]/[0.06]', badge: 'bg-[#a4e6ff]/15 text-[#a4e6ff]' };
  }
  if (status === 'DISABLED') {
    return { icon: 'block', color: 'text-tertiary', border: 'border-tertiary/30', bg: 'bg-tertiary/[0.04]', badge: 'bg-tertiary/15 text-tertiary' };
  }
  if (status === 'INCONCLUSIVE') {
    return { icon: 'help', color: 'text-[#ffaa40]', border: 'border-[#ffaa40]/30', bg: 'bg-[#ffaa40]/[0.05]', badge: 'bg-[#ffaa40]/15 text-[#ffaa40]' };
  }
  return { icon: 'pending', color: 'text-outline', border: 'border-outline-variant/30', bg: 'bg-surface-container-highest/40', badge: 'bg-outline/15 text-outline' };
}

function protocolVerdicts(p: TlsProtocolDetailDto): string[] {
  const obsolete = OBSOLETE_PROTO_IDS.has(p.id);
  if (p.status === 'ENABLED') {
    if (p.id === 'tls13') return ['Protocole préféré', 'Recommandé'];
    if (p.id === 'tls12') return ['Compatibilité sécurisée'];
    if (obsolete) return ['Protocole obsolète activé', 'Correction urgente'];
  }
  if (p.status === 'DISABLED' && obsolete) return ['Protocole obsolète', 'Désactivation conforme'];
  if (p.status === 'NOT_TESTED') return ['Non testé'];
  if (p.status === 'INCONCLUSIVE') return ['Résultat inconclusif'];
  if (p.status === 'DISABLED') return ['Désactivé'];
  return [];
}

function ensureTlsProtocols(result: SslResultDto): TlsProtocolDetailDto[] {
  if (result.tlsProtocols && result.tlsProtocols.length > 0) {
    const byId = new Map(result.tlsProtocols.map(p => [p.id, p]));
    return TLS_PROTO_ORDER.map(id => byId.get(id) || {
      id, label: TLS_PROTO_LABELS[id], status: 'NOT_TESTED' as TlsProtocolStatus, ciphers: [],
    });
  }
  // Client fallback — never invent DISABLED
  const kali = (on: boolean): TlsProtocolStatus => (on ? 'ENABLED' : 'NOT_TESTED');
  return [
    { id: 'tls13', label: 'TLS 1.3', status: kali(!!(result.tls13 || result.sslyzeSupportsTLS13)), ciphers: [] },
    { id: 'tls12', label: 'TLS 1.2', status: kali(!!(result.tls12 || result.sslyzeSupportsTLS12)), ciphers: [] },
    { id: 'tls11', label: 'TLS 1.1', status: kali(!!(result.tls11 || result.sslyzeSupportsTLS11)), ciphers: [] },
    { id: 'tls10', label: 'TLS 1.0', status: kali(!!(result.tls10 || result.sslyzeSupportsTLS10)), ciphers: [] },
    { id: 'ssl30', label: 'SSL 3.0', status: result.sslyzeStatus === 'READY' ? (result.sslyzeSupportsSSL30 ? 'ENABLED' : 'DISABLED') : 'NOT_TESTED', ciphers: [] },
    { id: 'ssl20', label: 'SSL 2.0', status: result.sslyzeStatus === 'READY' ? (result.sslyzeSupportsSSL20 ? 'ENABLED' : 'DISABLED') : 'NOT_TESTED', ciphers: [] },
  ];
}

function tlsRangeLabel(protocols: TlsProtocolDetailDto[]): string {
  const order = ['ssl20', 'ssl30', 'tls10', 'tls11', 'tls12', 'tls13'];
  const enabled = protocols.filter(p => p.status === 'ENABLED');
  if (enabled.length === 0) return 'Aucune version TLS activée détectée';
  const sorted = [...enabled].sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));
  const min = sorted[0].label;
  const max = sorted[sorted.length - 1].label;
  return min === max ? min : `${min} à ${max}`;
}

function tlsComplianceLabel(protocols: TlsProtocolDetailDto[]): { text: string; tone: 'ok' | 'warn' | 'bad' } {
  const obsoleteOn = protocols.some(p => OBSOLETE_PROTO_IDS.has(p.id) && p.status === 'ENABLED');
  if (obsoleteOn) return { text: 'Non conforme', tone: 'bad' };
  const tls13 = protocols.find(p => p.id === 'tls13');
  const tls12 = protocols.find(p => p.id === 'tls12');
  const allObsoleteDisabled = protocols.filter(p => OBSOLETE_PROTO_IDS.has(p.id)).every(p => p.status === 'DISABLED');
  if (tls13?.status === 'ENABLED' && tls12?.status === 'ENABLED' && allObsoleteDisabled) {
    return { text: 'Configuration moderne', tone: 'ok' };
  }
  return { text: 'Partielle', tone: 'warn' };
}

function tlsSectionConclusion(protocols: TlsProtocolDetailDto[]): string {
  const obsoleteOn = protocols.filter(p => OBSOLETE_PROTO_IDS.has(p.id) && p.status === 'ENABLED');
  const tls13 = protocols.find(p => p.id === 'tls13');
  const tls12 = protocols.find(p => p.id === 'tls12');
  const obsoleteDisabled = protocols.filter(p => OBSOLETE_PROTO_IDS.has(p.id) && p.status === 'DISABLED');
  const allObsoleteDisabled = protocols.filter(p => OBSOLETE_PROTO_IDS.has(p.id)).every(p => p.status === 'DISABLED');

  if (obsoleteOn.length > 0) {
    return `${obsoleteOn.map(p => p.label).join(', ')} ${obsoleteOn.length > 1 ? 'sont activés' : 'est activé'} alors que ce protocole est obsolète. Désactivez-le immédiatement. Une correction urgente est nécessaire dans cette section.`;
  }
  if (allObsoleteDisabled && tls12?.status === 'ENABLED' && tls13?.status === 'ENABLED') {
    return 'Aucun protocole SSL ou TLS obsolète n’est activé. Le serveur autorise uniquement TLS 1.2 et TLS 1.3. TLS 1.3 est utilisé en priorité lorsque le client le prend en charge. Aucune correction urgente n’est nécessaire dans cette section.';
  }
  if (allObsoleteDisabled && tls12?.status === 'ENABLED' && tls13?.status !== 'ENABLED') {
    return 'Aucun protocole obsolète n’est activé. Le serveur autorise TLS 1.2, mais TLS 1.3 n’est pas détecté. L’activation de TLS 1.3 est fortement recommandée. Aucune correction urgente n’est nécessaire pour les protocoles obsolètes.';
  }
  if (obsoleteDisabled.length > 0) {
    return `${obsoleteDisabled.length} protocole(s) obsolète(s) désactivé(s) conformément aux bonnes pratiques. Vérifiez les protocoles marqués « Non testé » ou « Résultat inconclusif » avant de conclure.`;
  }
  return 'Les tests de protocoles sont incomplets. Relancez le scan avec SSLyze pour obtenir un verdict fiable sur SSL 2.0/3.0 et le détail des suites cryptographiques.';
}

function formatScanDate(iso?: string | null): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString('fr-FR');
  } catch {
    return iso;
  }
}

function cipherStrengthLabel(s: string): string {
  if (s === 'FORBIDDEN') return 'Interdite';
  if (s === 'WEAK') return 'Faible';
  return 'Forte';
}

/* ═══════════════════════════════════════════════════════════════════════
   Component
═══════════════════════════════════════════════════════════════════════ */
export interface SSLAnalysisProps {
  embeddedScanId?: number;
  initialDomain?: string;
}

const SSLAnalysis: React.FC<SSLAnalysisProps> = ({ embeddedScanId, initialDomain }) => {
  const navigate = useNavigate();
  const { scanId: scanIdParam } = useParams<{ scanId?: string }>();
  const [searchParams] = useSearchParams();
  const paramScanId = scanIdParam ? Number(scanIdParam) : NaN;
  const queryScanId = Number(searchParams.get('scanId') || NaN);
  const detailScanId = embeddedScanId
    ?? (Number.isFinite(paramScanId) && paramScanId > 0 ? paramScanId : null)
    ?? (Number.isFinite(queryScanId) && queryScanId > 0 ? queryScanId : null);
  const isDetailPage = !embeddedScanId && detailScanId != null;

  const [domain, setDomain]     = useState(initialDomain ?? '');
  const [scanning, setScanning] = useState(false);
  const [done, setDone]         = useState(false);
  const [logs, setLogs]         = useState<LogLine[]>([]);
  const [result, setResult]     = useState<SslResultDto | null>(null);
  const [error, setError]       = useState<string | null>(null);
  const [expanded, setExpanded]       = useState<string | null>(null);
  const [expandedTool, setExpandedTool] = useState<string | null>(null);
  const [cipherModalProto, setCipherModalProto] = useState<TlsProtocolDetailDto | null>(null);
  const [aiAnalysis, setAiAnalysis]   = useState<{ summary: string; keyRisks: string[]; recommendations: string[] } | null>(null);
  const [aiLoading, setAiLoading]     = useState(false);
  const [aiOpen, setAiOpen]           = useState(false);
  const evtRef                  = useRef<EventSource | null>(null);
  const logRef                  = useRef<HTMLDivElement>(null);

  // ── Schedule modal state ─────────────────────────────────────────
  const [scheduleModalOpen, setScheduleModalOpen] = useState(false);
  const [scheduleDate, setScheduleDate]           = useState('');
  const [scheduleHour, setScheduleHour]           = useState('09');
  const [scheduleMinute, setScheduleMinute]       = useState('00');
  const [scheduleFrequency, setScheduleFrequency] = useState<ScheduleType>('ONCE');
  const [scheduleSubmitting, setScheduleSubmitting] = useState(false);
  const [scheduleError, setScheduleError]         = useState('');
  const [scheduleSuccess, setScheduleSuccess]     = useState('');
  const [howtoOpen, setHowtoOpen]                 = useState(false);

  // ── SSL scan history ────────────────────────────────────────────
  const [history, setHistory]               = useState<ScanResultDto[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(detailScanId);

  // Legacy ?scanId= → /ssl-analysis/:scanId
  useEffect(() => {
    if (embeddedScanId) return;
    if (!scanIdParam && Number.isFinite(queryScanId) && queryScanId > 0) {
      navigate(`/ssl-analysis/${queryScanId}`, { replace: true });
    }
  }, [embeddedScanId, scanIdParam, queryScanId, navigate]);

  useEffect(() => {
    if (embeddedScanId || isDetailPage) return;
    setLoadingHistory(true);
    getAllScans()
      .then(res => {
        const sslScans = res.data.filter(s => s.scanMode === 'ssl-only');
        setHistory(sslScans);
      })
      .catch(() => {})
      .finally(() => setLoadingHistory(false));
  }, [embeddedScanId, isDetailPage]);

  useEffect(() => {
    if (embeddedScanId) {
      loadHistoryScan({ id: embeddedScanId, targetDomain: initialDomain ?? domain, repoUrl: '' } as ScanResultDto);
      return;
    }
    if (detailScanId != null) {
      loadHistoryScan({ id: detailScanId, targetDomain: '', repoUrl: '' } as ScanResultDto);
    }
  }, [embeddedScanId, detailScanId]);

  // ── SSL Scheduling handler ────────────────────────────────────────
  const handleOpenScheduleModal = () => {
    setScheduleModalOpen(true);
    setScheduleError('');
    setScheduleSuccess('');
    // Default date = tomorrow
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    setScheduleDate(tomorrow.toISOString().slice(0, 10));
  };

  const handleCreateSslSchedule = async () => {
    const d = domain.trim();
    if (!d) return;
    if (!scheduleDate || !scheduleHour || !scheduleMinute) {
      setScheduleError('Veuillez choisir une date et une heure.');
      return;
    }
    setScheduleSubmitting(true);
    setScheduleError('');
    setScheduleSuccess('');
    try {
      await createScheduledScan({
        repositoryName: d,
        repoUrl: `ssl://${d}`,
        scanMode: 'ssl-only',
        targetDomain: d,
        scheduleType: scheduleFrequency,
        startAt: `${scheduleDate}T${scheduleHour}:${scheduleMinute}:00`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      });
      setScheduleSuccess(`Scan SSL planifié pour ${d} !`);
    } catch (err: any) {
      setScheduleError(
        err?.response?.data?.message ||
        err?.response?.data ||
        'Erreur lors de la planification.'
      );
    } finally {
      setScheduleSubmitting(false);
    }
  };

  const isSslScanSettled = (r: SslResultDto) => {
    const kaliDone = r.scanStatus === 'COMPLETED' || r.scanStatus === 'FAILED';
    const sourcesSettled =
      (r.ssllabsStatus ?? 'PENDING') !== 'PENDING'
      && (r.censysStatus ?? 'PENDING') !== 'PENDING'
      && (r.sslyzeStatus ?? 'PENDING') !== 'PENDING';
    return kaliDone && sourcesSettled;
  };

  const loadHistoryScan = async (scan: ScanResultDto) => {
    setSelectedScanId(scan.id);
    const label = scan.targetDomain || (scan.repoUrl ? scan.repoUrl.replace('ssl://', '') : '');
    if (label) setDomain(label);
    setDone(false); setResult(null); setLogs([]); setError(null);
    setAiAnalysis(null); setAiOpen(false); setExpandedTool(null);
    try {
      const r = await getSslResult(scan.id);
      setResult(r.data);
      if (!label && r.data.domain) setDomain(r.data.domain);
      const kaliDone = r.data.scanStatus === 'COMPLETED' || r.data.scanStatus === 'FAILED';
      setDone(kaliDone);
      // Keep polling until Kali status is final AND async sources left PENDING
      if (!isSslScanSettled(r.data)) {
        startExternalPoller(scan.id);
      }
    } catch {
      setError('Impossible de charger ce résultat.');
    }
  };

  const openScanDetail = (scanId: number) => {
    navigate(`/ssl-analysis/${scanId}`);
  };

  // ── Poller: refresh until Kali scanStatus is final AND no source is still PENDING ─
  const labsPollerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startExternalPoller = (scanId: number) => {
    if (labsPollerRef.current) clearInterval(labsPollerRef.current);
    const tick = async () => {
      try {
        const r = await getSslResult(scanId);
        setResult(r.data);
        const kaliDone = r.data.scanStatus === 'COMPLETED' || r.data.scanStatus === 'FAILED';
        setDone(kaliDone);
        if (isSslScanSettled(r.data)) {
          if (labsPollerRef.current) {
            clearInterval(labsPollerRef.current);
            labsPollerRef.current = null;
          }
        }
      } catch { /* ignore */ }
    };
    // Immediate refresh (handles race: navigated before backend saved COMPLETED)
    void tick();
    labsPollerRef.current = setInterval(tick, 5_000);
  };
  useEffect(() => () => { if (labsPollerRef.current) clearInterval(labsPollerRef.current); }, []);

  const handleAiAnalysis = async () => {
    setAiOpen(o => !o);
    if (aiAnalysis || aiLoading || !result) return;
    setAiLoading(true);

    const detectedVulns = [
      result.heartbleed && 'Heartbleed',
      result.poodle && 'POODLE',
      result.robot && 'ROBOT',
      result.drown && 'DROWN',
      result.sweet32 && 'SWEET32',
      result.crime && 'CRIME',
      result.has3des && '3DES',
      result.beast && 'BEAST',
      result.freak && 'FREAK',
      result.logjam && 'LOGJAM',
      result.rc4 && 'RC4',
    ].filter(Boolean).join(', ') || 'aucune';

    const activeProtocols = [
      result.sslyzeSupportsSSL20 && 'SSL 2.0',
      result.sslyzeSupportsSSL30 && 'SSL 3.0',
      (result.tls10 || result.sslyzeSupportsTLS10) && 'TLS 1.0',
      (result.tls11 || result.sslyzeSupportsTLS11) && 'TLS 1.1',
      (result.tls12 || result.sslyzeSupportsTLS12) && 'TLS 1.2',
      (result.tls13 || result.sslyzeSupportsTLS13) && 'TLS 1.3',
    ].filter(Boolean).join(', ') || 'inconnus';

    const headers = [
      result.hsts && 'HSTS',
      result.contentSecurityPolicy && 'CSP',
      !result.contentSecurityPolicy && result.cspReportOnly && 'CSP-Report-Only',
      result.xFrameOptions && 'X-Frame-Options',
      result.xContentTypeOptions && 'X-Content-Type-Options',
      result.referrerPolicy && 'Referrer-Policy',
      result.permissionsPolicy && 'Permissions-Policy',
      result.crossOriginOpenerPolicy && 'COOP (contextuel)',
      result.crossOriginResourcePolicy && 'CORP (contextuel)',
      result.crossOriginEmbedderPolicy && 'COEP (contextuel)',
    ].filter(Boolean).join(', ') || 'aucun';

    try {
      const r = await getSslAiAnalysis({
        domain: result.domain,
        kaliGrade: result.grade ?? '?',
        ssllabsGrade: result.ssllabsStatus === 'READY' ? (result.ssllabsGrade ?? '?') : 'N/A',
        censysGrade:  result.censysStatus  === 'READY' ? (result.censysGrade  ?? '?') : 'N/A',
        sslyzeGrade:  result.sslyzeStatus  === 'READY' ? (result.sslyzeGrade  ?? '?') : 'N/A',
        detectedVulns,
        activeProtocols,
        certValid: !result.certExpired,
        certDaysLeft: result.certDaysLeft,
        headers,
      });
      setAiAnalysis(r.data);
    } catch {
      setAiAnalysis({ summary: 'Erreur lors de la connexion à Gemini. Vérifiez que le backend est en cours d\'exécution.', keyRisks: [], recommendations: [] });
    } finally {
      setAiLoading(false);
    }
  };

  const handleAnalyze = async () => {
    const d = domain.trim();
    if (!d) return;
    setScanning(true); setDone(false); setLogs([]); setResult(null); setError(null);
    setSelectedScanId(null);
    setAiAnalysis(null); setAiOpen(false); setExpandedTool(null);

    try {
      const { data } = await startSslScan(d);
      const scanId = data.scanId;

      const es = new EventSource(apiUrl(`/api/ssl/scan/${scanId}/logs`), {
        withCredentials: true,
      });
      evtRef.current = es;

      es.onmessage = (e) => {
        if (e.data === '%%SCAN_COMPLETE%%') {
          es.close(); evtRef.current = null;
          setScanning(false);
          setDone(true);
          navigate(`/ssl-analysis/${scanId}`);
          return;
        }
        const line = parseLog(e.data);
        setLogs(prev => [...prev, line]);
        setTimeout(() => logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: 'smooth' }), 50);
      };

      es.onerror = () => {
        es.close(); evtRef.current = null;
        setDone(true); setScanning(false);
        navigate(`/ssl-analysis/${scanId}`);
      };

    } catch {
      setError('Impossible de démarrer le scan. Le backend est-il en cours d\'exécution ?');
      setScanning(false);
    }
  };

  const handleExportPDF = () => {
    if (!result) return;
    const bd = computeScoreBreakdown(result);
    const protocols = ensureTlsProtocols(result);
    const vulns = buildVulnPresentations(result);
    const headersSummary = computeHeadersSummary(result);
    const cert = result.certificateDetail;
    const riskLabel = {
      Critique: 'Vulnérabilité critique confirmée',
      Élevé:    'Risque élevé — correction prioritaire',
      Moyen:    'Configuration à améliorer',
      Faible:   'Bonne sécurité générale',
    }[bd.riskLevel];
    const tlsComp = tlsComplianceLabel(protocols);

    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 14;
    const cW = pageW - margin * 2;
    let y = 0;

    const navy:     [number,number,number] = [13, 17, 23];
    const teal:     [number,number,number] = [0, 200, 120];
    const blue:     [number,number,number] = [100, 180, 230];
    const red:      [number,number,number] = [220, 80, 80];
    const white:    [number,number,number] = [255, 255, 255];
    const offWhite: [number,number,number] = [245, 248, 252];
    const midGray:  [number,number,number] = [110, 120, 140];
    const darkText: [number,number,number] = [20, 30, 48];
    const rowAlt:   [number,number,number] = [238, 243, 250];

    const gcPdf = (g: string): [number,number,number] => {
      if (g === 'A+') return [0, 190, 110];
      if (g === 'A')  return [60, 160, 220];
      if (g === 'B')  return [200, 160, 30];
      if (g === 'C')  return [220, 120, 40];
      if (g === 'D')  return [210, 80, 50];
      return [200, 60, 60];
    };

    const pageNum = { v: 1 };

    const drawHeader = (n: number) => {
      doc.setFillColor(...navy);
      doc.rect(0, 0, pageW, 16, 'F');
      doc.setFillColor(...teal);
      doc.rect(0, 16, pageW, 1.5, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(...blue);
      doc.text('VULNIX', margin, 11);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(...white);
      doc.text('Rapport SSL / TLS — même contenu que l’écran d’analyse', margin + 20, 11);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(...teal);
      doc.text(result!.domain, pageW - margin, 7.5, { align: 'right' });
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(...midGray);
      const scanTag = detailScanId != null ? `Scan #${detailScanId}  ·  ` : '';
      doc.text(`${scanTag}Page ${n}  ·  ${new Date().toLocaleDateString('fr-FR')}`, pageW - margin, 13.5, { align: 'right' });
    };

    const drawFooter = () => {
      doc.setFillColor(...navy);
      doc.rect(0, pageH - 9, pageW, 9, 'F');
      doc.setFillColor(...teal);
      doc.rect(0, pageH - 9, pageW, 1, 'F');
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(...blue);
      doc.text('VULNIX — Rapport SSL/TLS confidentiel', margin, pageH - 3.5);
      doc.setTextColor(...midGray);
      doc.text(`Généré le ${new Date().toLocaleString('fr-FR')}`, pageW - margin, pageH - 3.5, { align: 'right' });
    };

    const newPage = () => {
      drawFooter();
      doc.addPage();
      pageNum.v++;
      drawHeader(pageNum.v);
      y = 24;
    };

    const guard = (need: number) => { if (y + need > pageH - 14) newPage(); };

    const sectionTitle = (title: string) => {
      guard(14);
      doc.setFillColor(...navy);
      doc.roundedRect(margin, y, cW, 8, 1.5, 1.5, 'F');
      doc.setFillColor(...teal);
      doc.roundedRect(margin, y, 3, 8, 1, 1, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(...white);
      doc.text(title, margin + 6, y + 5.5);
      y += 12;
    };

    const para = (text: string, color: [number, number, number] = darkText) => {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(...color);
      const lines = doc.splitTextToSize(text, cW - 4);
      lines.forEach((l: string) => { guard(5); doc.text(l, margin + 2, y); y += 4.5; });
      y += 2;
    };

    drawHeader(1);
    y = 24;

    // Cover
    doc.setFillColor(...offWhite);
    doc.roundedRect(margin, y, cW, 26, 3, 3, 'F');
    doc.setFillColor(...teal);
    doc.roundedRect(margin, y, 4, 26, 2, 2, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(18);
    doc.setTextColor(...darkText);
    doc.text(result.domain, margin + 9, y + 11);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(...midGray);
    doc.text('Rapport d’analyse SSL/TLS — identique à la page de détail', margin + 9, y + 18.5);
    doc.setFontSize(7);
    const srcLine = `${result.sourcesReady ?? '?'}/${result.sourcesTotal ?? 4} sources prêtes`
      + (detailScanId != null ? `  ·  Scan #${detailScanId}` : '')
      + `  ·  Statut Kali ${result.scanStatus ?? '—'}`;
    doc.text(`Généré le ${new Date().toLocaleString('fr-FR')}  ·  ${srcLine}`, margin + 9, y + 23.5);
    y += 32;

    // Verdict agrégé (same as page banner)
    const cgc = gcPdf(bd.grade);
    doc.setFillColor(...cgc);
    doc.roundedRect(margin, y, 34, 38, 3, 3, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(bd.grade.length > 1 ? 18 : 24);
    doc.setTextColor(...navy);
    doc.text(bd.grade, margin + 17, y + 18, { align: 'center' });
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(...navy);
    doc.text(`${bd.total}/100`, margin + 17, y + 32, { align: 'center' });

    doc.setFillColor(...offWhite);
    doc.roundedRect(margin + 37, y, cW - 37, 38, 3, 3, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...darkText);
    doc.text('Verdict final agrégé — score par catégories', margin + 42, y + 8);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(...darkText);
    doc.text(riskLabel, margin + 42, y + 15);
    doc.setFontSize(7.5);
    doc.setTextColor(...midGray);
    doc.text(
      `Score ${bd.total}/100  ·  Risque ${bd.riskLevel}  ·  Confiance ${bd.confidence}  ·  Consensus ${bd.consensus.level}`
        + (bd.consensus.pct > 0 ? ` (${bd.consensus.pct} %)` : ''),
      margin + 42, y + 22,
    );
    doc.text(
      `TLS ${bd.tls}/25  ·  Certificat ${bd.certificate}/25  ·  Vulnérabilités ${bd.vulnerabilities}/30  ·  En-têtes ${bd.headers}/20`,
      margin + 42, y + 29,
    );
    doc.setFontSize(7);
    doc.text('Le grade n’est pas la moyenne des notes sources. Il est calculé par catégories (TLS, certificat, vulnérabilités, en-têtes).', margin + 42, y + 35);
    y += 44;

    sectionTitle('SOURCES D’ANALYSE');
    const kaliStatus = (result.scanStatus === 'COMPLETED' || result.scanStatus === 'FAILED')
      ? (result.grade !== '?' ? 'PRÊT' : 'ERREUR') : 'EN COURS';
    const srcStatus = (s?: string | null) =>
      s === 'READY' ? 'PRÊT' : s === 'PENDING' ? 'EN COURS' : (s || '—');

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Source', 'Poids', 'Note', 'Statut', 'IP / Infos']],
      body: [
        ['Kali Linux (scan interne)', '20 %', result.grade ?? '?', kaliStatus, result.sslyzeIpAddress || '—'],
        ['SSL Labs (Qualys)', '30 %', result.ssllabsGrade ?? '?', srcStatus(result.ssllabsStatus), result.ssllabsIpAddress || '—'],
        ['Censys', '30 %', result.censysGrade ?? '?', srcStatus(result.censysStatus), result.censysIpAddress || '—'],
        ['SSLyze', '20 %', result.sslyzeGrade ?? '?', srcStatus(result.sslyzeStatus), result.sslyzeIpAddress || '—'],
      ],
      styles: { fontSize: 8, cellPadding: 3.5, textColor: darkText },
      headStyles: { fillColor: navy, textColor: white, fontStyle: 'bold', fontSize: 8 },
      alternateRowStyles: { fillColor: rowAlt },
      columnStyles: {
        0: { cellWidth: 58 },
        1: { cellWidth: 16, halign: 'center' },
        2: { cellWidth: 14, halign: 'center', fontStyle: 'bold' },
        3: { cellWidth: 22, halign: 'center' },
        4: { cellWidth: 'auto' },
      },
      didParseCell: (d) => {
        if (d.section === 'body' && d.column.index === 2) {
          d.cell.styles.textColor = gcPdf(d.cell.text[0]);
        }
        if (d.section === 'body' && d.column.index === 3) {
          const s = d.cell.text[0];
          d.cell.styles.textColor = s === 'PRÊT' ? [0, 160, 80] : s === 'EN COURS' ? [60, 120, 200] : [200, 60, 60];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    if (aiAnalysis && (aiAnalysis.summary || aiAnalysis.keyRisks.length > 0 || aiAnalysis.recommendations.length > 0)) {
      sectionTitle('ANALYSE IA — GEMINI SSL ASSESSMENT');
      if (aiAnalysis.summary) {
        doc.setFont('helvetica', 'italic');
        para(aiAnalysis.summary);
      }
      if (aiAnalysis.keyRisks.length > 0) {
        guard(8);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(...red);
        doc.text('Risques identifiés', margin + 2, y);
        y += 5;
        aiAnalysis.keyRisks.forEach(r => para(`• ${r}`));
      }
      if (aiAnalysis.recommendations.length > 0) {
        guard(8);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(...teal);
        doc.text('Recommandations prioritaires', margin + 2, y);
        y += 5;
        aiAnalysis.recommendations.forEach(r => para(`→ ${r}`));
      }
    }

    sectionTitle('PROTOCOLES TLS / SSL');
    para(`Plage détectée : ${tlsRangeLabel(protocols)}  ·  Conformité : ${tlsComp.text}`);
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Protocole', 'État (page)', 'Verdict', 'Ciphers', 'Outil']],
      body: protocols.map(p => [
          p.label,
          protocolStatusLabel(p.status),
          protocolVerdicts(p).join(' · ') || '—',
          String(p.acceptedCount ?? p.ciphers?.length ?? '—'),
          p.tool || '—',
        ]),
      styles: { fontSize: 8, cellPadding: 3.2, textColor: darkText },
      headStyles: { fillColor: navy, textColor: white, fontStyle: 'bold', fontSize: 8 },
      alternateRowStyles: { fillColor: rowAlt },
      didParseCell: (d) => {
        if (d.section !== 'body' || d.column.index !== 1) return;
        const s = d.cell.text[0];
        if (s === 'Activé') d.cell.styles.textColor = [30, 120, 200];
        else if (s === 'Désactivé') d.cell.styles.textColor = [0, 150, 80];
        else if (s === 'Résultat inconclusif') d.cell.styles.textColor = [180, 100, 0];
        else d.cell.styles.textColor = [120, 120, 120];
      },
    });
    y = (doc as any).lastAutoTable.finalY + 6;
    para(tlsSectionConclusion(protocols));

    sectionTitle('CERTIFICAT SSL');
    const daysLeft = cert?.daysRemaining ?? (result.certDaysLeft >= 0 ? result.certDaysLeft : null);
    const expired = cert?.expired ?? result.certExpired;
    const validityTxt = expired
      ? 'EXPIRÉ'
      : daysLeft != null
        ? `Valide — ${daysLeft} jour(s) restant(s)`
        : (cert?.validityStatus || 'Inconnu');
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      body: [
        ['Sujet / CN', cert?.commonName || result.certSubject || result.sslyzeCertSubject || '—'],
        ['Hôte testé', cert?.testedHostname || result.domain || '—'],
        ['Correspondance nom', cert?.hostnameMatch || '—'],
        ['Émetteur', result.certIssuer || result.sslyzeCertIssuer || '—'],
        ['Validité', validityTxt],
        ['Du', cert?.notBefore || result.certNotBefore || '—'],
        ['Au', cert?.notAfter || result.certNotAfterStr || '—'],
        ['Renouvellement conseillé', cert?.recommendedRenewalDate || '—'],
        ['Algorithme de signature', cert?.signatureAlgorithm || result.certSignatureAlg || '—'],
        ['Clé publique', cert?.keyType
          ? `${cert.keyType}${cert.keySize ? ` ${cert.keySize} bits` : ''}${cert.curveName ? ` (${cert.curveName})` : ''}`
          : (result.certKeySize ? `${result.certKeySize} bits` : (result.sslyzeKeySize ? `${result.sslyzeKeySize} bits` : '—'))],
        ['Niveau crypto', cert?.securityLevel || '—'],
        ['Wildcard', (cert?.wildcard ?? result.certWildcard) ? 'Oui' : 'Non'],
        ['Nombre de SAN', String(cert?.sans?.length ?? result.certSansCount ?? result.censysSansCount ?? '—')],
        ['Chaîne de confiance', (cert?.chainComplete ?? (result.chainComplete || result.sslyzeChainTrusted)) ? 'Complète' : 'Incomplète'],
        ['Racine reconnue', cert?.rootRecognized == null ? '—' : (cert.rootRecognized ? 'Oui' : 'Non')],
        ['OCSP Stapling', cert?.ocspStaplingStatus
          || ((result.ocspStapling || result.sslyzeOcspStapling) ? 'Actif' : 'Non détecté')],
        ['Certificate Transparency', cert?.transparencyStatus
          || ((result.certTransparency || result.censysCtPresent) ? 'Présent' : 'Non détecté')],
        ['N° de série', cert?.serialNumber || result.certSerialNumber || '—'],
        ['Empreinte SHA-256', cert?.sha256Fingerprint || '—'],
        ['Outil / confiance', [cert?.tool, cert?.confidence].filter(Boolean).join(' · ') || '—'],
      ],
      styles: { fontSize: 8, cellPadding: 3.2, textColor: darkText },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 58, fillColor: [230, 236, 248] as [number, number, number] },
      },
      alternateRowStyles: { fillColor: rowAlt },
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    sectionTitle('VULNÉRABILITÉS SSL / TLS');
    para(buildSectionConclusion(vulns));
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Vulnérabilité', 'CVE', 'Résultat', 'Sévérité', 'Confiance', 'Sources']],
      body: vulns.map(v => [
        v.name,
        v.cve || '—',
        statusLabel(v.status),
        severityLabel(v.theoreticalSeverity),
        confidenceLabel(v.confidence).replace('Confiance ', ''),
        v.sourcesLabel,
      ]),
      styles: { fontSize: 7.2, cellPadding: 2.8, textColor: darkText },
      headStyles: { fillColor: navy, textColor: white, fontStyle: 'bold', fontSize: 7.5 },
      alternateRowStyles: { fillColor: rowAlt },
      didParseCell: (d) => {
        if (d.section !== 'body' || d.column.index !== 2) return;
        const s = d.cell.text[0];
        if (s === 'Détectée') d.cell.styles.textColor = [200, 40, 40];
        else if (s === 'Non détectée') d.cell.styles.textColor = [0, 150, 80];
        else if (s === 'Résultat inconclusif' || s === 'Erreur de test') d.cell.styles.textColor = [180, 100, 0];
        else d.cell.styles.textColor = [120, 120, 120];
        d.cell.styles.fontStyle = 'bold';
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    sectionTitle('EN-TÊTES DE SÉCURITÉ HTTP');
    para(`Score protections principales : ${headersSummary.mainScore}/100  ·  ${headersSummary.conformes} conforme(s), ${headersSummary.partielles} partiel(s), ${headersSummary.nonTestees} non testé(s).`);
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['En-tête', 'Statut (page)', 'Priorité', 'Valeur observée']],
      body: headersSummary.items.map(h => [
        h.name,
        badgeLabel(h.badge),
        h.priority === 'critique' ? 'Critique'
          : h.priority === 'haute' ? 'Haute'
          : h.priority === 'moyenne' ? 'Moyenne'
          : h.priority === 'basse' ? 'Basse'
          : 'Contextuelle',
        h.shortValue || h.observedValue || '—',
      ]),
      styles: { fontSize: 7.2, cellPadding: 2.8, textColor: darkText },
      headStyles: { fillColor: navy, textColor: white, fontStyle: 'bold', fontSize: 7.5 },
      alternateRowStyles: { fillColor: rowAlt },
      columnStyles: {
        0: { cellWidth: 58 },
        1: { cellWidth: 38 },
        2: { cellWidth: 26, halign: 'center' },
        3: { cellWidth: 'auto' },
      },
      didParseCell: (d) => {
        if (d.section !== 'body' || d.column.index !== 1) return;
        const s = d.cell.text[0];
        if (s === 'Conforme' || s === 'Non requis') d.cell.styles.textColor = [0, 150, 80];
        else if (s === 'À corriger') d.cell.styles.textColor = [200, 40, 40];
        else if (s === 'Partiel' || s === 'Présence non confirmée') d.cell.styles.textColor = [180, 100, 0];
        else d.cell.styles.textColor = [90, 110, 140];
        d.cell.styles.fontStyle = 'bold';
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    if (bd.penalties.length > 0) {
      sectionTitle('CE QUI BAISSE LE SCORE');
      autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        head: [['Catégorie', 'Motif', 'Points']],
        body: bd.penalties.map(p => [
          p.category === 'tls' ? 'TLS'
            : p.category === 'certificate' ? 'Certificat'
            : p.category === 'vulnerabilities' ? 'Vulnérabilités'
            : 'En-têtes',
          p.label,
          `−${p.points}`,
        ]),
        styles: { fontSize: 8, cellPadding: 3, textColor: darkText },
        headStyles: { fillColor: navy, textColor: white, fontStyle: 'bold', fontSize: 8 },
        alternateRowStyles: { fillColor: rowAlt },
        columnStyles: {
          0: { cellWidth: 32 },
          2: { cellWidth: 22, halign: 'center', fontStyle: 'bold', textColor: red },
        },
      });
      y = (doc as any).lastAutoTable.finalY + 8;
    }

    const total = (doc as any).internal.getNumberOfPages();
    for (let p = 1; p <= total; p++) {
      doc.setPage(p);
      drawFooter();
    }

    const slug = (result.domain || 'scan').replace(/[^a-zA-Z0-9.-]+/g, '_');
    const idPart = detailScanId != null ? `-${detailScanId}` : '';
    doc.save(`rapport-ssl-${slug}${idPart}-${new Date().toISOString().slice(0, 10)}.pdf`);
  };

  // List page: no inline result panel (details live on /ssl-analysis/:scanId)
  const showResults = !!result && (isDetailPage || !!embeddedScanId);

  return (
    <div className="max-w-6xl mx-auto print:max-w-none">
      {/* ── Header ──────────────────────────────────────────────────── */}
      {!embeddedScanId && (
        <div className="mb-8 flex flex-col md:flex-row md:items-end justify-between gap-6 print:hidden">
          <div>
            {isDetailPage && (
              <button
                type="button"
                onClick={() => navigate('/ssl-analysis')}
                className="mb-3 inline-flex items-center gap-1.5 text-xs font-bold text-outline hover:text-primary transition-colors"
              >
                <span className="material-symbols-outlined text-base">arrow_back</span>
                Retour aux scans SSL
              </button>
            )}
            <h1 className="text-4xl font-headline font-bold tracking-tight text-on-surface mb-1">
              {isDetailPage
                ? (result?.domain || domain || `Scan #${detailScanId}`)
                : 'SSL / TLS Analysis'}
            </h1>
            <p className="text-on-surface-variant text-sm max-w-lg">
              {isDetailPage
                ? `Détail du scan SSL #${detailScanId} — certificat, protocoles, vulnérabilités et en-têtes.`
                : 'Inspection complète du certificat, des protocoles et des vulnérabilités connues d\'un domaine.'}
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setHowtoOpen(true)}
              className="flex items-center gap-2 px-5 py-3 rounded-xl bg-surface-container border border-outline-variant/20 text-on-surface-variant hover:text-primary hover:border-primary/40 transition-all text-sm font-headline font-semibold"
            >
              <span className="material-symbols-outlined text-base">info</span>
              Comment ça marche
            </button>
            {showResults && (
              <button onClick={handleExportPDF}
                className="flex items-center gap-2 px-5 py-3 rounded-xl bg-surface-container border border-outline-variant/20 text-on-surface-variant hover:text-on-surface hover:border-primary/40 transition-all text-sm font-headline font-semibold">
                <span className="material-symbols-outlined text-base">picture_as_pdf</span>
                Exporter PDF
              </button>
            )}
          </div>
        </div>
      )}

      {/* ── Domain Input ─────────────────────────────────────────────── */}
      {!embeddedScanId && !isDetailPage && (
        <div className="mb-8 print:hidden">
          <div className="relative flex gap-3">
            <div className="relative flex-1">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 material-symbols-outlined text-primary/60">language</span>
              <input
                value={domain}
                onChange={e => setDomain(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && !scanning && handleAnalyze()}
                disabled={scanning}
                placeholder="exemple.com  ou  exemple.com:8443"
                className="w-full bg-surface-container-highest border border-outline-variant/20 rounded-xl py-4 pl-12 pr-4 text-on-surface focus:ring-1 focus:ring-primary focus:bg-surface-bright transition-all placeholder:text-outline/40 font-body disabled:opacity-50"
              />
            </div>
            <button
              onClick={handleAnalyze}
              disabled={scanning || !domain.trim()}
              className="px-8 py-4 bg-gradient-to-br from-primary to-on-primary-fixed-variant text-on-primary rounded-xl font-headline font-bold text-sm tracking-wide hover:shadow-[0_0_20px_rgba(164,230,255,0.35)] disabled:opacity-40 disabled:cursor-not-allowed transition-all active:scale-95 whitespace-nowrap"
            >
              {scanning ? (
                <span className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-base animate-spin">progress_activity</span>
                  Analyse…
                </span>
              ) : 'ANALYSER'}
            </button>
            <button
              onClick={handleOpenScheduleModal}
              disabled={!domain.trim() || scanning}
              title="Planifier ce scan SSL"
              className="flex items-center gap-2 px-5 py-4 rounded-xl border border-violet-500/30 bg-violet-500/10 text-violet-300 font-headline font-bold text-sm hover:bg-violet-500/20 hover:border-violet-500/50 hover:shadow-[0_0_16px_rgba(167,139,250,0.25)] disabled:opacity-30 disabled:cursor-not-allowed transition-all active:scale-95 whitespace-nowrap"
            >
              <span className="material-symbols-outlined text-base" style={{ fontVariationSettings: "'FILL' 1" }}>calendar_clock</span>
              Planifier
            </button>
          </div>
          {error && (
            <div className="mt-3 flex items-center gap-3 px-4 py-3 rounded-xl bg-error/10 border border-error/20">
              <span className="material-symbols-outlined text-error text-base">error</span>
              <p className="text-sm text-error">{error}</p>
            </div>
          )}
        </div>
      )}

      {isDetailPage && error && (
        <div className="mb-6 flex items-center gap-3 px-4 py-3 rounded-xl bg-error/10 border border-error/20 print:hidden">
          <span className="material-symbols-outlined text-error text-base">error</span>
          <p className="text-sm text-error">{error}</p>
        </div>
      )}

      {isDetailPage && !result && !error && (
        <div className="mb-8 flex items-center gap-3 text-outline text-sm print:hidden">
          <span className="material-symbols-outlined animate-spin text-primary">progress_activity</span>
          Chargement du détail du scan…
        </div>
      )}

      {/* ── Scan History ──────────────────────────────────────────────── */}
      {!embeddedScanId && !isDetailPage && !scanning && (
        <div className="mb-8 print:hidden">
          <h2 className="text-sm font-headline font-bold uppercase tracking-[0.15em] text-outline mb-4 flex items-center gap-2">
            <span className="material-symbols-outlined text-base">history</span>
            Scans SSL précédents
            {loadingHistory && <span className="material-symbols-outlined text-sm animate-spin text-primary">progress_activity</span>}
          </h2>
          {!loadingHistory && history.length === 0 && (
            <p className="text-xs text-outline italic">Aucun scan SSL précédent.</p>
          )}
          {history.length > 0 && (
            <div className="glass-panel rounded-2xl border border-outline-variant/[0.1] overflow-hidden">
              {history.map((s, idx) => {
                const domainLabel = s.targetDomain || s.repoUrl.replace('ssl://', '');
                const isSelected  = selectedScanId === s.id;
                const isCompleted = s.status === 'COMPLETED';
                const isFailed    = s.status === 'FAILED';
                return (
                  <div
                    key={s.id}
                    className={`flex items-center gap-4 px-5 py-3 transition-all cursor-pointer ${
                      idx !== 0 ? 'border-t border-outline-variant/[0.08]' : ''
                    } ${
                      isSelected
                        ? 'bg-primary/10'
                        : 'hover:bg-surface-container'
                    }`}
                    onClick={() => openScanDetail(s.id)}
                  >
                    {/* Status icon */}
                    <span
                      className={`material-symbols-outlined text-lg shrink-0 ${
                        isCompleted ? 'text-tertiary' : isFailed ? 'text-error' : 'text-primary animate-spin'
                      }`}
                      style={{ fontVariationSettings: "'FILL' 1" }}
                    >
                      {isCompleted ? 'check_circle' : isFailed ? 'error' : 'progress_activity'}
                    </span>

                    {/* Domain */}
                    <div className="flex-1 min-w-0">
                      <p className="font-bold text-sm text-on-surface truncate">{domainLabel}</p>
                      <p className="text-[10px] text-outline">
                        #{s.id} · {new Date(s.startedAt).toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' })}
                      </p>
                    </div>

                    {/* Status badge */}
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                      isCompleted ? 'text-tertiary bg-tertiary/10 border-tertiary/20' :
                      isFailed    ? 'text-error bg-error/10 border-error/20' :
                                    'text-primary bg-primary/10 border-primary/20'
                    }`}>
                      {isCompleted ? 'Complété' : isFailed ? 'Échoué' : 'En cours'}
                    </span>

                    {/* Delete button */}
                    <button
                      onClick={async (e) => {
                        e.stopPropagation();
                        try {
                          await deleteScan(s.id);
                          setHistory(prev => prev.filter(h => h.id !== s.id));
                          if (selectedScanId === s.id) { setSelectedScanId(null); }
                        } catch { /* ignore */ }
                      }}
                      title="Supprimer ce scan"
                      className="w-8 h-8 rounded-lg border border-outline-variant/20 flex items-center justify-center hover:bg-error/10 hover:border-error/20 transition-colors shrink-0"
                    >
                      <span className="material-symbols-outlined text-outline hover:text-error text-sm">delete</span>
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ── Live Logs ────────────────────────────────────────────────── */}
      {!isDetailPage && (scanning || logs.length > 0) && (
        <div className="mb-8 bg-[#0d1117] rounded-2xl border border-outline-variant/[0.12] overflow-hidden print:hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-outline-variant/[0.1] bg-surface-container/50">
            <div className="w-3 h-3 rounded-full bg-error/70" />
            <div className="w-3 h-3 rounded-full bg-[#ffe066]/70" />
            <div className="w-3 h-3 rounded-full bg-tertiary/70" />
            <span className="ml-2 text-[10px] font-mono text-outline uppercase tracking-widest">ssl-scanner.log</span>
            {scanning && <span className="ml-auto flex items-center gap-1.5 text-[10px] text-tertiary font-bold uppercase tracking-widest"><span className="w-1.5 h-1.5 rounded-full bg-tertiary animate-pulse" />Live</span>}
            {done && <span className="ml-auto text-[10px] text-outline font-bold uppercase tracking-widest">Terminé</span>}
          </div>
          <div ref={logRef} className="h-52 overflow-y-auto p-4 font-mono text-[11px] space-y-1">
            {logs.map((l, i) => (
              <div key={i} className="flex gap-3 leading-relaxed">
                {l.ts && <span className="text-outline/50 shrink-0">{l.ts}</span>}
                <span className={
                  l.level === 'ERROR' ? 'text-[#ffb4ab]' :
                  l.level === 'WARN'  ? 'text-[#ffe066]' :
                  'text-[#8b949e]'
                }>{l.text}</span>
              </div>
            ))}
            {scanning && <div className="flex gap-3"><span className="text-primary/60 animate-pulse">▋</span></div>}
          </div>
        </div>
      )}

      {/* ── Results (dedicated detail page / embedded only) ───────────── */}
      {showResults && (
        <div className="space-y-6">

          {/* ── Grade Banner — Verdict agrégé (full-width, most prominent) ── */}
          {(() => {
            const bd  = computeScoreBreakdown(result);
            const cgc = gradeColor(bd.grade);
            const riskColor = bd.riskLevel === 'Critique' ? '#ffb4ab' : bd.riskLevel === 'Élevé' ? '#ffaa40' : bd.riskLevel === 'Moyen' ? '#ffe066' : '#00fc92';
            const riskLabel = {
              Critique: 'Vulnérabilité critique confirmée',
              Élevé:    'Risque élevé — correction prioritaire',
              Moyen:    'Configuration à améliorer',
              Faible:   'Bonne sécurité générale',
            }[bd.riskLevel];
            return (
              <div className="relative rounded-2xl overflow-hidden p-8 flex flex-col md:flex-row items-center gap-6"
                style={{ background: cgc.bg, border: `1px solid ${cgc.ring}33` }}>
                <div className="absolute inset-0 pointer-events-none"
                  style={{ background: `radial-gradient(ellipse at 50% 0%, ${cgc.ring}11 0%, transparent 70%)` }} />
                {/* Grade circle */}
                <div className="w-32 h-32 rounded-full flex items-center justify-center flex-shrink-0"
                  style={{ border: `5px solid ${cgc.ring}55`, boxShadow: `0 0 40px ${cgc.ring}33` }}>
                  <span className="text-7xl font-headline font-extrabold"
                    style={{ color: cgc.ring, filter: `drop-shadow(0 0 14px ${cgc.ring}88)` }}>
                    {bd.grade}
                  </span>
                </div>
                {/* Text */}
                <div className="flex-1 text-center md:text-left">
                  <div className="text-[10px] font-headline font-bold uppercase tracking-[0.25em] text-outline mb-1 flex items-center gap-1.5 justify-center md:justify-start">
                    <span className="material-symbols-outlined text-[13px]">verified_user</span>
                    Verdict final agrégé — Score par catégories
                  </div>
                  <h2 className="text-3xl font-headline font-extrabold text-on-surface mb-1">{riskLabel}</h2>
                  <p className="text-sm text-outline mb-2">
                    Score technique{' '}
                    <span className="font-bold" style={{ color: cgc.ring }}>{bd.total}/100</span>
                    {' '}· Risque{' '}
                    <span className="font-bold" style={{ color: riskColor }}>{bd.riskLevel}</span>
                    {' '}· Confiance{' '}
                    <span className="font-bold" style={{ color: bd.confidence === 'Haute' ? '#00fc92' : bd.confidence === 'Moyenne' ? '#ffe066' : '#8b949e' }}>{bd.confidence}</span>
                  </p>
                  {/* Mini score bars */}
                  <div className="flex flex-wrap gap-3 justify-center md:justify-start">
                    {[
                      { label: 'TLS',     score: bd.tls,             max: 25 },
                      { label: 'Cert',    score: bd.certificate,     max: 25 },
                      { label: 'Vulns',   score: bd.vulnerabilities, max: 30 },
                      { label: 'Headers', score: bd.headers,         max: 20 },
                    ].map(c => {
                      const pct = c.score / c.max;
                      const bc = pct >= 0.9 ? '#00fc92' : pct >= 0.7 ? '#a4e6ff' : pct >= 0.5 ? '#ffe066' : pct >= 0.3 ? '#ffaa40' : '#ffb4ab';
                      return (
                        <div key={c.label} className="flex flex-col items-center gap-1">
                          <span className="text-[8px] font-bold text-outline uppercase tracking-wider">{c.label}</span>
                          <span className="text-sm font-headline font-extrabold" style={{ color: bc }}>{c.score}<span className="text-[9px] text-outline font-normal">/{c.max}</span></span>
                        </div>
                      );
                    })}
                  </div>
                </div>
                {/* Domain badge */}
                <div className="flex-shrink-0 flex flex-col items-center gap-2">
                  <div className="px-4 py-2 rounded-xl bg-surface-container/50 border border-outline-variant/20 font-mono text-sm text-on-surface-variant">
                    {result.domain}
                  </div>
                  <span className="text-[9px] font-bold px-2 py-0.5 rounded-full border" style={{ color: riskColor, background: `${riskColor}15`, borderColor: `${riskColor}30` }}>
                    Risque {bd.riskLevel}
                  </span>
                </div>
              </div>
            );
          })()}

          {/* ── Verdict final agrégé (Score récapitulatif) ───────────────── */}
          {(() => {
            const bd = computeScoreBreakdown(result);
            const riskColor = bd.riskLevel === 'Critique' ? '#ffb4ab' : bd.riskLevel === 'Élevé' ? '#ffaa40' : bd.riskLevel === 'Moyen' ? '#ffe066' : '#00fc92';
            const confColor = bd.confidence === 'Haute' ? '#00fc92' : bd.confidence === 'Moyenne' ? '#ffe066' : '#8b949e';
            const consColor = bd.consensus.level === 'Fort' ? '#00fc92' : bd.consensus.level === 'Moyen' ? '#ffe066' : '#ffaa40';
            const sc = gradeColor(bd.grade);
            return (
              <div className="rounded-2xl border-2 overflow-hidden" style={{ borderColor: `${sc.ring}40` }}>
                {/* Header */}
                <div className="px-5 py-4 border-b border-outline-variant/[0.08] flex items-start gap-3" style={{ background: `${sc.ring}08` }}>
                  <span className="material-symbols-outlined text-xl shrink-0 mt-0.5" style={{ color: sc.ring, fontVariationSettings: "'FILL' 1" }}>verified_user</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="font-headline font-extrabold text-sm text-on-surface">Verdict final agrégé</span>
                      <span className="text-[9px] font-bold px-2 py-0.5 rounded-full border" style={{ color: riskColor, background: `${riskColor}15`, borderColor: `${riskColor}30` }}>
                        Risque {bd.riskLevel}
                      </span>
                    </div>
                    <p className="text-[11px] text-outline/70 leading-relaxed">
                      Le score final n'est pas une moyenne des notes sources. Il est calculé par catégories — TLS, certificat, vulnérabilités, en-têtes HTTP — pondérées selon la pertinence de chaque outil pour chaque dimension.
                    </p>
                  </div>
                </div>

                {/* Key metrics */}
                <div className="grid grid-cols-2 sm:grid-cols-5 divide-x divide-y sm:divide-y-0 divide-outline-variant/[0.08] border-b border-outline-variant/[0.08]">
                  <div className="px-3 py-3 text-center">
                    <div className="text-[8px] font-bold text-outline uppercase tracking-widest mb-1">Score technique</div>
                    <span className="text-3xl font-headline font-extrabold" style={{ color: sc.ring }}>{bd.total}</span>
                    <span className="text-xs text-outline">/100</span>
                  </div>
                  <div className="px-3 py-3 text-center">
                    <div className="text-[8px] font-bold text-outline uppercase tracking-widest mb-1">Grade final</div>
                    <div className="text-3xl font-headline font-extrabold" style={{ color: sc.ring }}>{bd.grade}</div>
                  </div>
                  <div className="px-3 py-3 text-center">
                    <div className="text-[8px] font-bold text-outline uppercase tracking-widest mb-1">Niveau de risque</div>
                    <div className="text-base font-headline font-bold mt-1" style={{ color: riskColor }}>{bd.riskLevel}</div>
                  </div>
                  <div className="px-3 py-3 text-center">
                    <div className="text-[8px] font-bold text-outline uppercase tracking-widest mb-1">Confiance rapport</div>
                    <div className="text-base font-headline font-bold mt-1" style={{ color: confColor }}>{bd.confidence}</div>
                  </div>
                  <div className="px-3 py-3 text-center col-span-2 sm:col-span-1">
                    <div className="text-[8px] font-bold text-outline uppercase tracking-widest mb-1">Consensus sources</div>
                    <div className="text-base font-headline font-bold mt-1" style={{ color: consColor }}>{bd.consensus.level}</div>
                    {bd.consensus.pct > 0 && <div className="text-[8px] text-outline/40">{bd.consensus.pct}% alignées</div>}
                  </div>
                </div>

                {/* Heartbleed special alert — correct wording */}
                {(bd.hblStatus === 'to_confirm' || bd.hblStatus === 'confirmed') && (
                  <div className={`px-5 py-3 border-b border-outline-variant/[0.08] flex items-start gap-3 ${bd.hblStatus === 'confirmed' ? 'bg-error/[0.06]' : 'bg-[#ffaa40]/[0.04]'}`}>
                    <span className="material-symbols-outlined text-sm shrink-0 mt-0.5" style={{ color: bd.hblStatus === 'confirmed' ? '#ffb4ab' : '#ffaa40', fontVariationSettings: "'FILL' 1" }}>
                      {bd.hblStatus === 'confirmed' ? 'dangerous' : 'warning'}
                    </span>
                    <div>
                      <div className="text-xs font-bold" style={{ color: bd.hblStatus === 'confirmed' ? '#ffb4ab' : '#ffaa40' }}>
                        {bd.hblStatus === 'confirmed'
                          ? 'Vulnérabilité critique confirmée — Heartbleed (≥2 sources)'
                          : 'Alerte critique à confirmer — Heartbleed (1 seule source)'}
                      </div>
                      <p className="text-[10px] text-outline/70 mt-0.5 leading-relaxed">
                        {bd.hblStatus === 'confirmed'
                          ? 'Deux sources indépendantes confirment Heartbleed. Mise à jour OpenSSL et régénération des certificats requises immédiatement.'
                          : 'Détecté par Kali/Nmap uniquement. SSLyze ne confirme pas. Ne pas conclure à une vulnérabilité réelle avant confirmation par un second outil indépendant.'}
                      </p>
                    </div>
                  </div>
                )}

                {/* Score breakdown bars */}
                <div className="px-5 py-4">
                  <div className="text-[9px] font-bold text-outline uppercase tracking-widest mb-3">Décomposition du score par catégorie</div>
                  <div className="space-y-2.5">
                    {([
                      { label: 'TLS et protocoles', score: bd.tls,             max: 25, src: 'SSL Labs · SSLyze · Kali' },
                      { label: 'Certificat',         score: bd.certificate,     max: 25, src: 'SSL Labs · Censys · OpenSSL · OCSP' },
                      { label: 'Vulnérabilités',     score: bd.vulnerabilities, max: 30, src: 'Kali/Nmap · SSLyze · SSL Labs' },
                      { label: 'En-têtes HTTP',      score: bd.headers,         max: 20, src: 'Protections principales (sans COOP/OCSP)' },
                    ] as const).map(row => {
                      const pct    = row.score / row.max;
                      const barCol = pct >= 0.9 ? '#00fc92' : pct >= 0.7 ? '#a4e6ff' : pct >= 0.5 ? '#ffe066' : pct >= 0.3 ? '#ffaa40' : '#ffb4ab';
                      return (
                        <div key={row.label}>
                          <div className="flex justify-between items-end mb-1">
                            <div>
                              <span className="text-[10px] text-on-surface-variant">{row.label}</span>
                              <span className="text-[9px] text-outline/40 ml-2">{row.src}</span>
                            </div>
                            <span className="text-xs font-bold" style={{ color: barCol }}>{row.score}<span className="text-outline text-[9px] font-normal">/{row.max}</span></span>
                          </div>
                          <div className="h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
                            <div className="h-full rounded-full transition-all" style={{ width: `${pct*100}%`, background: barCol }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  <p className="text-[9px] text-outline/40 mt-4 italic leading-relaxed border-t border-outline-variant/[0.06] pt-3">
                    {bd.consensus.level === 'Faible'
                      ? "Les sources ne sont pas totalement alignées car elles n'analysent pas le même périmètre, ou une alerte n'est confirmée que par une seule source."
                      : bd.consensus.level === 'Moyen'
                      ? "Les sources sont partiellement alignées. Certains résultats peuvent différer selon le moment du scan ou le périmètre analysé."
                      : "Les sources sont alignées sur les points clés. Le verdict final bénéficie d'un bon niveau de confiance."}
                  </p>
                </div>
              </div>
            );
          })()}


          {/* ── Gemini AI SSL Assessment ──────────────────────────────────── */}
          <div className="rounded-2xl border border-primary/20 bg-surface-container-low overflow-hidden">
            <button
              onClick={handleAiAnalysis}
              className="w-full flex items-center gap-3 px-5 py-4 hover:bg-primary/5 transition-all text-left"
            >
              <span className="text-lg">🧠</span>
              <div className="flex-1">
                <span className="font-headline font-bold text-on-surface text-sm">Analyse IA — Gemini SSL Assessment</span>
                <span className="text-xs text-outline block mt-0.5">Interprétation globale, risques clés et recommandations générées par Gemini</span>
              </div>
              {aiLoading && (
                <span className="flex items-center gap-1.5 text-[10px] text-primary shrink-0">
                  <span className="material-symbols-outlined text-xs animate-spin">progress_activity</span> Gemini analyse...
                </span>
              )}
              <span className={`material-symbols-outlined text-outline text-lg transition-transform shrink-0 ${aiOpen ? 'rotate-180' : ''}`}>
                {aiAnalysis ? 'expand_more' : 'auto_awesome'}
              </span>
            </button>
            {aiOpen && (
              <div className="border-t border-primary/10 px-5 py-4 bg-surface-container-lowest/60">
                {aiLoading ? (
                  <div className="flex items-center gap-2 text-outline text-sm">
                    <span className="material-symbols-outlined text-base animate-spin text-primary">progress_activity</span>
                    Gemini génère l'analyse SSL…
                  </div>
                ) : aiAnalysis ? (
                  <div className="space-y-4">
                    {aiAnalysis.summary && (
                      <p className="text-sm text-on-surface-variant leading-relaxed">{aiAnalysis.summary}</p>
                    )}
                    {aiAnalysis.keyRisks.length > 0 && (
                      <div>
                        <div className="text-[10px] font-bold text-error uppercase tracking-widest mb-2">Risques identifiés</div>
                        <ul className="space-y-1.5">
                          {aiAnalysis.keyRisks.map((r, i) => (
                            <li key={i} className="flex items-start gap-2 text-xs text-on-surface-variant">
                              <span className="text-error mt-0.5 shrink-0 font-bold">✗</span>
                              <span>{r}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {aiAnalysis.recommendations.length > 0 && (
                      <div>
                        <div className="text-[10px] font-bold text-tertiary uppercase tracking-widest mb-2">Recommandations prioritaires</div>
                        <ul className="space-y-1.5">
                          {aiAnalysis.recommendations.map((r, i) => (
                            <li key={i} className="flex items-start gap-2 text-xs text-on-surface-variant">
                              <span className="text-tertiary mt-0.5 shrink-0 font-bold">→</span>
                              <span>{r}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-sm text-outline italic">Cliquez sur le bouton pour lancer l'analyse Gemini…</p>
                )}
              </div>
            )}
          </div>

          {/* ── 4 Sources — détails à la demande ─────────────────────────── */}
          <div className="rounded-2xl bg-surface-container overflow-hidden">
            <div className="px-5 pt-4 pb-2 flex items-center justify-between">
              <span className="text-[10px] font-headline font-bold uppercase tracking-[0.2em] text-outline flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[13px]">source</span>
                Sources d'analyse
              </span>
            </div>
            <div className="divide-y divide-outline-variant/[0.08]">

              {/* ── Kali Linux ── */}
              {(() => {
                const g = result.grade ?? '?';
                const isDone = result.scanStatus === 'COMPLETED' || result.scanStatus === 'FAILED';
                const status = isDone ? (g !== '?' ? 'READY' : 'ERROR') : 'PENDING';
                const c = status === 'READY' ? gradeColor(g) : { ring: '#8b949e', text: '#8b949e', bg: 'rgba(139,148,158,0.06)' };
                type F = { text: string; type: 'ok' | 'warn' | 'bad' };
                const findings: F[] = status !== 'READY' ? [] : [
                  result.heartbleed         ? { text: 'Heartbleed', type: 'bad' }             : null,
                  result.poodle             ? { text: 'POODLE', type: 'bad' }                 : null,
                  result.robot              ? { text: 'ROBOT', type: 'bad' }                  : null,
                  result.drown              ? { text: 'DROWN', type: 'bad' }                  : null,
                  result.sweet32            ? { text: 'SWEET32 / 3DES', type: 'bad' }         : null,
                  result.crime              ? { text: 'CRIME (compression)', type: 'bad' }    : null,
                  result.tls10              ? { text: 'TLS 1.0 actif', type: 'bad' }          : null,
                  result.tls11              ? { text: 'TLS 1.1 actif', type: 'bad' }          : null,
                  !result.tls13             ? { text: 'TLS 1.3 absent', type: 'warn' }        : { text: 'TLS 1.3 ✓', type: 'ok' },
                  !result.hsts              ? { text: 'HSTS manquant', type: 'warn' }         : { text: 'HSTS ✓', type: 'ok' },
                  result.certExpired        ? { text: 'Certificat expiré', type: 'bad' }      : null,
                  !result.chainComplete     ? { text: 'Chaîne incomplète', type: 'bad' }      : null,
                ].filter(Boolean) as F[];
                const isExp = expandedTool === 'kali';
                return (
                  <div>
                    <div className="flex items-center gap-3 px-5 py-3 cursor-pointer hover:bg-surface-container-high/40 transition-colors select-none"
                      onClick={() => setExpandedTool(isExp ? null : 'kali')}>
                      <span className="material-symbols-outlined text-[14px] text-outline">computer</span>
                      <span className="text-[10px] font-headline font-bold uppercase tracking-[0.15em] text-outline">Kali Linux</span>
                      <span className="text-[9px] text-outline/40 hidden sm:inline">· Scan interne · 30%</span>
                      <div className="flex-1" />
                      {status === 'PENDING' && <span className="material-symbols-outlined text-sm text-primary animate-spin">progress_activity</span>}
                      {status === 'READY' && <span className="text-lg font-headline font-extrabold" style={{ color: c.ring }}>{g}</span>}
                      {status !== 'READY' && status !== 'PENDING' && <span className="material-symbols-outlined text-sm text-error">error</span>}
                      <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded-full ${status === 'READY' ? 'text-tertiary bg-tertiary/10' : status === 'PENDING' ? 'text-primary bg-primary/10' : 'text-error bg-error/10'}`}>{status}</span>
                      <button onClick={e => { e.stopPropagation(); setExpandedTool(isExp ? null : 'kali'); }} className={`flex items-center gap-1 text-[9px] font-bold px-2.5 py-1 rounded-full border transition-all ${
                        isExp
                          ? 'bg-primary/15 border-primary/30 text-primary'
                          : 'bg-surface-container-highest border-outline/20 text-outline hover:bg-primary/10 hover:border-primary/30 hover:text-primary'
                      }`}>
                        Détails<span className={`material-symbols-outlined text-[11px] transition-transform ${isExp ? 'rotate-180' : ''}`}>expand_more</span>
                      </button>
                    </div>
                    {isExp && (
                      <div className="px-5 pb-3 pt-2 bg-surface-container-low/50 border-t border-outline-variant/[0.08]">
                        {findings.length === 0
                          ? <p className="text-[10px] text-outline italic">{status === 'PENDING' ? 'Scan Kali en cours…' : 'Aucun détail disponible.'}</p>
                          : <div className="flex flex-wrap gap-2 pt-1.5">
                              {findings.map((f, i) => {
                                const isOk = f.type === 'ok';
                                const isWarn = f.type === 'warn';
                                const styleClass = isOk
                                  ? 'bg-tertiary/10 text-tertiary border-tertiary/20'
                                  : isWarn
                                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                                  : 'bg-error/10 text-error border-error/20';
                                const icon = isOk
                                  ? 'check_circle'
                                  : isWarn
                                  ? 'warning'
                                  : 'dangerous';
                                return (
                                  <div
                                    key={i}
                                    className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-xl text-xs font-semibold border transition-all ${styleClass}`}
                                  >
                                    <span className="material-symbols-outlined text-[13px] leading-none shrink-0" style={{ fontVariationSettings: "'FILL' 1" }}>
                                      {icon}
                                    </span>
                                    <span>{f.text}</span>
                                  </div>
                                );
                              })}
                            </div>}
                        <div className="mt-2 text-[9px] text-outline/40">Outils : sslyze · sslscan · testssl.sh · nmap · nikto</div>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* ── SSL Labs ── */}
              {(() => {
                const s = result.ssllabsStatus ?? 'PENDING';
                const g = result.ssllabsGrade ?? '?';
                const c = s === 'READY' ? gradeColor(g) : { ring: '#8b949e', text: '#8b949e', bg: '' };
                type F = { text: string; type: 'ok' | 'warn' | 'bad' };
                const findings: F[] = s !== 'READY' ? [] : [
                  result.ssllabsHasWarnings    ? { text: 'Avertissements SSL Labs détectés', type: 'warn' } : { text: 'Aucun avertissement', type: 'ok' },
                  !result.ssllabsForwardSecrecy ? { text: 'Pas de Forward Secrecy (PFS)', type: 'bad' }     : { text: 'Forward Secrecy (PFS) ✓', type: 'ok' },
                  result.ssllabsDrown           ? { text: 'DROWN (SSLv2 actif)', type: 'bad' }              : null,
                ].filter(Boolean) as F[];
                const isExp = expandedTool === 'ssllabs';
                return (
                  <div>
                    <div className="flex items-center gap-3 px-5 py-3 cursor-pointer hover:bg-surface-container-high/40 transition-colors select-none"
                      onClick={() => setExpandedTool(isExp ? null : 'ssllabs')}>
                      <span className="material-symbols-outlined text-[14px] text-outline">public</span>
                      <span className="text-[10px] font-headline font-bold uppercase tracking-[0.15em] text-outline">SSL Labs</span>
                      <span className="text-[9px] text-outline/40 hidden sm:inline">· Qualys · 30%</span>
                      <div className="flex-1" />
                      {s === 'PENDING' && <span className="material-symbols-outlined text-sm text-primary animate-spin">progress_activity</span>}
                      {s === 'READY' && <span className="text-lg font-headline font-extrabold" style={{ color: c.ring }}>{g}</span>}
                      {s !== 'READY' && s !== 'PENDING' && <span className="material-symbols-outlined text-sm text-error">error</span>}
                      <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded-full ${s === 'READY' ? 'text-tertiary bg-tertiary/10' : s === 'PENDING' ? 'text-primary bg-primary/10' : 'text-error bg-error/10'}`}>{s}</span>
                      <button onClick={e => { e.stopPropagation(); setExpandedTool(isExp ? null : 'ssllabs'); }} className={`flex items-center gap-1 text-[9px] font-bold px-2.5 py-1 rounded-full border transition-all ${
                        isExp
                          ? 'bg-primary/15 border-primary/30 text-primary'
                          : 'bg-surface-container-highest border-outline/20 text-outline hover:bg-primary/10 hover:border-primary/30 hover:text-primary'
                      }`}>
                        Détails<span className={`material-symbols-outlined text-[11px] transition-transform ${isExp ? 'rotate-180' : ''}`}>expand_more</span>
                      </button>
                    </div>
                    {isExp && (
                      <div className="px-5 pb-3 pt-2 bg-surface-container-low/50 border-t border-outline-variant/[0.08]">
                        {findings.length === 0
                          ? <div>
                              <p className="text-[10px] text-outline italic mb-2">{s === 'PENDING' ? 'Analyse SSL Labs en cours…' : 'Erreur lors de l\'analyse SSL Labs.'}</p>
                              {s !== 'READY' && s !== 'PENDING' && (
                                <a href={`https://www.ssllabs.com/ssltest/analyze.html?d=${result.domain}&hideResults=on`}
                                  target="_blank" rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 text-[10px] text-primary hover:underline">
                                  <span className="material-symbols-outlined text-[12px]">open_in_new</span>Tester manuellement sur ssllabs.com
                                </a>
                              )}
                            </div>
                          : <div className="flex flex-wrap gap-2 pt-1.5">
                              {findings.map((f, i) => {
                                const isOk = f.type === 'ok';
                                const isWarn = f.type === 'warn';
                                const styleClass = isOk
                                  ? 'bg-tertiary/10 text-tertiary border-tertiary/20'
                                  : isWarn
                                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                                  : 'bg-error/10 text-error border-error/20';
                                const icon = isOk
                                  ? 'check_circle'
                                  : isWarn
                                  ? 'warning'
                                  : 'dangerous';
                                return (
                                  <div
                                    key={i}
                                    className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-xl text-xs font-semibold border transition-all ${styleClass}`}
                                  >
                                    <span className="material-symbols-outlined text-[13px] leading-none shrink-0" style={{ fontVariationSettings: "'FILL' 1" }}>
                                      {icon}
                                    </span>
                                    <span>{f.text}</span>
                                  </div>
                                );
                              })}
                            </div>}
                        {s === 'READY' && result.ssllabsIpAddress && (
                          <div className="mt-2 text-[9px] text-outline/40 font-mono">{result.ssllabsIpAddress}</div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* ── Censys ── */}
              {(() => {
                const s = result.censysStatus ?? 'PENDING';
                const g = result.censysGrade ?? '?';
                const c = s === 'READY' ? gradeColor(g) : { ring: '#8b949e', text: '#8b949e', bg: '' };
                type F = { text: string; type: 'ok' | 'warn' | 'bad' };
                const findings: F[] = s !== 'READY' ? [] : [
                  !result.censysCertValid    ? { text: 'Cert non fiable (CA)', type: 'bad' }              : { text: 'Cert fiable ✓', type: 'ok' },
                  !result.censysCtPresent    ? { text: 'Certificate Transparency absent', type: 'warn' }  : { text: 'Certificate Transparency ✓', type: 'ok' },
                  result.censysExpired       ? { text: 'Certificat expiré', type: 'bad' }                 : null,
                  result.censysDaysLeft >= 0 && result.censysDaysLeft < 30  ? { text: `Expire dans ${result.censysDaysLeft}j ⚠`, type: 'bad' }  : null,
                  result.censysDaysLeft >= 30 && result.censysDaysLeft < 90 ? { text: `${result.censysDaysLeft}j restants`, type: 'warn' }       : null,
                  result.censysDaysLeft >= 90 ? { text: `${result.censysDaysLeft}j de validité`, type: 'ok' } : null,
                  result.censysKeySize && parseInt(result.censysKeySize) < 2048 ? { text: `Clé ${result.censysKeySize} bits (faible)`, type: 'bad' } : null,
                  result.censysOpenPorts ? { text: `Ports ouverts : ${result.censysOpenPorts}`, type: 'ok' } : null,
                ].filter(Boolean) as F[];
                const isExp = expandedTool === 'censys';
                return (
                  <div>
                    <div className="flex items-center gap-3 px-5 py-3 cursor-pointer hover:bg-surface-container-high/40 transition-colors select-none"
                      onClick={() => setExpandedTool(isExp ? null : 'censys')}>
                      <span className="material-symbols-outlined text-[14px] text-outline">search</span>
                      <span className="text-[10px] font-headline font-bold uppercase tracking-[0.15em] text-outline">Censys</span>
                      <span className="text-[9px] text-outline/40 hidden sm:inline">· Certificat & IP · 20%</span>
                      <div className="flex-1" />
                      {s === 'PENDING' && <span className="material-symbols-outlined text-sm text-primary animate-spin">progress_activity</span>}
                      {s === 'READY' && <span className="text-lg font-headline font-extrabold" style={{ color: c.ring }}>{g}</span>}
                      {s !== 'READY' && s !== 'PENDING' && <span className="material-symbols-outlined text-sm text-error">error</span>}
                      <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded-full ${s === 'READY' ? 'text-tertiary bg-tertiary/10' : s === 'PENDING' ? 'text-primary bg-primary/10' : 'text-error bg-error/10'}`}>{s}</span>
                      <button onClick={e => { e.stopPropagation(); setExpandedTool(isExp ? null : 'censys'); }} className={`flex items-center gap-1 text-[9px] font-bold px-2.5 py-1 rounded-full border transition-all ${
                        isExp
                          ? 'bg-primary/15 border-primary/30 text-primary'
                          : 'bg-surface-container-highest border-outline/20 text-outline hover:bg-primary/10 hover:border-primary/30 hover:text-primary'
                      }`}>
                        Détails<span className={`material-symbols-outlined text-[11px] transition-transform ${isExp ? 'rotate-180' : ''}`}>expand_more</span>
                      </button>
                    </div>
                    {isExp && (
                      <div className="px-5 pb-3 pt-2 bg-surface-container-low/50 border-t border-outline-variant/[0.08]">
                        {findings.length === 0
                          ? <p className="text-[10px] text-outline italic">{s === 'PENDING' ? 'Analyse Censys en cours…' : 'Aucun détail disponible.'}</p>
                          : <div className="flex flex-wrap gap-2 pt-1.5">
                              {findings.map((f, i) => {
                                const isOk = f.type === 'ok';
                                const isWarn = f.type === 'warn';
                                const styleClass = isOk
                                  ? 'bg-tertiary/10 text-tertiary border-tertiary/20'
                                  : isWarn
                                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                                  : 'bg-error/10 text-error border-error/20';
                                const icon = isOk
                                  ? 'check_circle'
                                  : isWarn
                                  ? 'warning'
                                  : 'dangerous';
                                return (
                                  <div
                                    key={i}
                                    className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-xl text-xs font-semibold border transition-all ${styleClass}`}
                                  >
                                    <span className="material-symbols-outlined text-[13px] leading-none shrink-0" style={{ fontVariationSettings: "'FILL' 1" }}>
                                      {icon}
                                    </span>
                                    <span>{f.text}</span>
                                  </div>
                                );
                              })}
                            </div>}
                        {s === 'READY' && result.censysIpAddress && (
                          <div className="mt-2 text-[9px] text-outline/40 font-mono">{result.censysIpAddress}</div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* ── SSLyze ── */}
              {(() => {
                const s = result.sslyzeStatus ?? 'PENDING';
                const g = result.sslyzeGrade ?? '?';
                const c = s === 'READY' ? gradeColor(g) : { ring: '#8b949e', text: '#8b949e', bg: '' };
                type F = { text: string; type: 'ok' | 'warn' | 'bad' };
                const findings: F[] = s !== 'READY' ? [] : [
                  result.sslyzeSupportsSSL20         ? { text: 'SSL 2.0 actif', type: 'bad' }                    : null,
                  result.sslyzeSupportsSSL30         ? { text: 'SSL 3.0 actif', type: 'bad' }                    : null,
                  result.sslyzeSupportsTLS10         ? { text: 'TLS 1.0 actif', type: 'bad' }                    : null,
                  result.sslyzeSupportsTLS11         ? { text: 'TLS 1.1 actif', type: 'bad' }                    : null,
                  result.sslyzeSupportsTLS13         ? { text: 'TLS 1.3 ✓', type: 'ok' }                        : { text: 'TLS 1.3 absent', type: 'warn' },
                  result.sslyzeHeartbleed            ? { text: 'Heartbleed', type: 'bad' }                       : null,
                  result.sslyzeRobot                 ? { text: 'ROBOT', type: 'bad' }                            : null,
                  result.sslyzeCcsInjection          ? { text: 'CCS Injection', type: 'bad' }                    : null,
                  result.sslyzeCompression           ? { text: 'Compression TLS (CRIME)', type: 'bad' }          : null,
                  result.sslyzeInsecureRenegotiation ? { text: 'Renégociation non sécurisée', type: 'bad' }      : null,
                  !result.sslyzeChainTrusted         ? { text: 'Chaîne non fiable', type: 'bad' }                : { text: 'Chaîne de confiance ✓', type: 'ok' },
                  result.sslyzeCipherCount > 0       ? { text: `${result.sslyzeCipherCount} cipher suites`, type: result.sslyzeCipherCount > 30 ? 'warn' : 'ok' } : null,
                ].filter(Boolean) as F[];
                const isExp = expandedTool === 'sslyze';
                return (
                  <div>
                    <div className="flex items-center gap-3 px-5 py-3 cursor-pointer hover:bg-surface-container-high/40 transition-colors select-none"
                      onClick={() => setExpandedTool(isExp ? null : 'sslyze')}>
                      <span className="material-symbols-outlined text-[14px] text-outline">security</span>
                      <span className="text-[10px] font-headline font-bold uppercase tracking-[0.15em] text-outline">SSLyze</span>
                      <span className="text-[9px] text-outline/40 hidden sm:inline">· Protocoles & ciphers · 20%</span>
                      <div className="flex-1" />
                      {s === 'PENDING' && <span className="material-symbols-outlined text-sm text-primary animate-spin">progress_activity</span>}
                      {s === 'READY' && <span className="text-lg font-headline font-extrabold" style={{ color: c.ring }}>{g}</span>}
                      {s !== 'READY' && s !== 'PENDING' && <span className="material-symbols-outlined text-sm text-error">error</span>}
                      <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded-full ${s === 'READY' ? 'text-tertiary bg-tertiary/10' : s === 'PENDING' ? 'text-primary bg-primary/10' : 'text-error bg-error/10'}`}>{s}</span>
                      <button onClick={e => { e.stopPropagation(); setExpandedTool(isExp ? null : 'sslyze'); }} className={`flex items-center gap-1 text-[9px] font-bold px-2.5 py-1 rounded-full border transition-all ${
                        isExp
                          ? 'bg-primary/15 border-primary/30 text-primary'
                          : 'bg-surface-container-highest border-outline/20 text-outline hover:bg-primary/10 hover:border-primary/30 hover:text-primary'
                      }`}>
                        Détails<span className={`material-symbols-outlined text-[11px] transition-transform ${isExp ? 'rotate-180' : ''}`}>expand_more</span>
                      </button>
                    </div>
                    {isExp && (
                      <div className="px-5 pb-3 pt-2 bg-surface-container-low/50 border-t border-outline-variant/[0.08]">
                        {findings.length === 0
                          ? <p className="text-[10px] text-outline italic">{s === 'PENDING' ? 'Analyse SSLyze en cours…' : 'Aucun détail disponible.'}</p>
                          : <div className="flex flex-wrap gap-2 pt-1.5">
                              {findings.map((f, i) => {
                                const isOk = f.type === 'ok';
                                const isWarn = f.type === 'warn';
                                const styleClass = isOk
                                  ? 'bg-tertiary/10 text-tertiary border-tertiary/20'
                                  : isWarn
                                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                                  : 'bg-error/10 text-error border-error/20';
                                const icon = isOk
                                  ? 'check_circle'
                                  : isWarn
                                  ? 'warning'
                                  : 'dangerous';
                                return (
                                  <div
                                    key={i}
                                    className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-xl text-xs font-semibold border transition-all ${styleClass}`}
                                  >
                                    <span className="material-symbols-outlined text-[13px] leading-none shrink-0" style={{ fontVariationSettings: "'FILL' 1" }}>
                                      {icon}
                                    </span>
                                    <span>{f.text}</span>
                                  </div>
                                );
                              })}
                            </div>}
                        {s === 'READY' && result.sslyzeIpAddress && (
                          <div className="mt-2 text-[9px] text-outline/40 font-mono">{result.sslyzeIpAddress}</div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* ── Méthodologie du scan (inside Sources) ── */}
              {(() => {
                const isOpen = expandedTool === '__methodology__';
                return (
                  <div className="border-t border-outline-variant/[0.08]">
                    <div className="flex items-center gap-3 px-5 py-3 cursor-pointer hover:bg-surface-container-high/40 transition-colors select-none"
                      onClick={() => setExpandedTool(isOpen ? null : '__methodology__')}>
                      <span className="material-symbols-outlined text-[14px] text-outline">article</span>
                      <span className="text-[10px] font-headline font-bold uppercase tracking-[0.15em] text-outline">Méthodologie du scan</span>
                      <div className="flex-1" />
                      <button onClick={e => { e.stopPropagation(); setExpandedTool(isOpen ? null : '__methodology__'); }} className={`flex items-center gap-1 text-[9px] font-bold px-2.5 py-1 rounded-full border transition-all ${
                        isOpen
                          ? 'bg-primary/15 border-primary/30 text-primary'
                          : 'bg-surface-container-highest border-outline/20 text-outline hover:bg-primary/10 hover:border-primary/30 hover:text-primary'
                      }`}>
                        Détails<span className={`material-symbols-outlined text-[11px] transition-transform ${isOpen ? 'rotate-180' : ''}`}>expand_more</span>
                      </button>
                    </div>
                    {isOpen && (
                      <div className="px-5 pb-4 pt-3 bg-surface-container-low/50 border-t border-outline-variant/[0.08]">
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
                          <div className="space-y-2">
                            <div className="text-[10px] font-bold text-outline uppercase tracking-widest mb-2">Paramètres du scan</div>
                            {[
                              { label: 'Domaine testé',  value: result.domain },
                              { label: 'Port testé',     value: '443 (HTTPS)' },
                              { label: 'Date du scan',   value: new Date().toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) },
                              { label: 'IP détectée',    value: result.sslyzeIpAddress || result.ssllabsIpAddress || result.censysIpAddress || 'Non disponible' },
                              { label: 'Sources prêtes', value: `${result.sourcesReady ?? '?'}/${result.sourcesTotal ?? 4}` },
                            ].map(row => (
                              <div key={row.label} className="flex justify-between items-center py-1 border-b border-outline-variant/[0.06]">
                                <span className="text-[10px] text-outline">{row.label}</span>
                                <span className="text-[10px] font-mono text-on-surface">{row.value}</span>
                              </div>
                            ))}
                          </div>
                          <div>
                            <div className="text-[10px] font-bold text-outline uppercase tracking-widest mb-2">Sources utilisées</div>
                            <div className="space-y-1.5">
                              {[
                                { tool: 'SSLyze',                desc: 'Protocoles, ciphers, vulnérabilités TLS', status: result.sslyzeStatus ?? 'PENDING' },
                                { tool: 'Nmap ssl-enum-ciphers', desc: 'Énumération suites de chiffrement',       status: 'READY' as const },
                                { tool: 'Nmap ssl-heartbleed',   desc: 'Détection Heartbleed (CVE-2014-0160)',    status: 'READY' as const },
                                { tool: 'OpenSSL s_client',      desc: 'Validation certificat et chaîne CA',      status: 'READY' as const },
                                { tool: 'SSL Labs (Qualys)',      desc: 'Évaluation externe complète',             status: result.ssllabsStatus ?? 'PENDING' },
                                { tool: 'Censys',                desc: 'Données certificat et ports ouverts',      status: result.censysStatus ?? 'PENDING' },
                                { tool: 'Analyse HTTP headers',  desc: 'En-têtes de sécurité navigateur',         status: 'READY' as const },
                              ].map(src => (
                                <div key={src.tool} className="flex items-center gap-2">
                                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${src.status === 'READY' ? 'bg-tertiary' : src.status === 'PENDING' ? 'bg-primary animate-pulse' : 'bg-outline/40'}`} />
                                  <div className="flex-1 min-w-0">
                                    <span className="text-[10px] font-bold text-on-surface">{src.tool}</span>
                                    <span className="text-[9px] text-outline ml-1.5">{src.desc}</span>
                                  </div>
                                  <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded-full ${src.status === 'READY' ? 'text-tertiary bg-tertiary/10' : src.status === 'PENDING' ? 'text-primary bg-primary/10' : 'text-error bg-error/10'}`}>{src.status}</span>
                                </div>
                              ))}
                            </div>
                            <p className="text-[9px] text-outline/50 mt-3 leading-relaxed italic">
                              Le statut final est calculé par croisement des sources disponibles. En cas de désaccord entre sources, le résultat est marqué « À confirmer » plutôt que « Vulnérable ».
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* ── Pourquoi les sources donnent des notes différentes ? (inside Sources) ── */}
              {(() => {
                const isOpen = expandedTool === '__why_sources__';
                return (
                  <div className="border-t border-outline-variant/[0.08]">
                    <div className="flex items-center gap-3 px-5 py-3 cursor-pointer hover:bg-surface-container-high/40 transition-colors select-none"
                      onClick={() => setExpandedTool(isOpen ? null : '__why_sources__')}>
                      <span className="material-symbols-outlined text-[14px] text-outline">help_outline</span>
                      <span className="text-[10px] font-headline font-bold uppercase tracking-[0.15em] text-outline">Pourquoi les sources donnent-elles des notes différentes ?</span>
                      <div className="flex-1"/>
                      <button onClick={e => { e.stopPropagation(); setExpandedTool(isOpen ? null : '__why_sources__'); }} className={`flex items-center gap-1 text-[9px] font-bold px-2.5 py-1 rounded-full border transition-all ${
                        isOpen
                          ? 'bg-primary/15 border-primary/30 text-primary'
                          : 'bg-surface-container-highest border-outline/20 text-outline hover:bg-primary/10 hover:border-primary/30 hover:text-primary'
                      }`}>
                        Détails<span className={`material-symbols-outlined text-[11px] transition-transform ${isOpen ? 'rotate-180' : ''}`}>expand_more</span>
                      </button>
                    </div>
                    {isOpen && (
                      <div className="px-5 pb-5 pt-3 border-t border-outline-variant/[0.08] space-y-4 bg-surface-container-low/40">
                        <p className="text-xs text-on-surface-variant leading-relaxed">
                          Les sources n'évaluent pas toutes le même périmètre. Chacune a un rôle spécifique et sa propre méthode d'analyse.
                          C'est pourquoi elles peuvent produire des grades différents sans se contredire — Kali peut noter F à cause des headers manquants,
                          pendant que SSL Labs note A sur la configuration TLS.
                        </p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          {[
                            {
                              name: 'Kali Linux / Nmap', icon: 'computer',       confColor: '#ffe066',
                              role: 'Tests actifs & vulnérabilités',
                              scope: 'Vulnérabilités CVE, en-têtes HTTP, ports exposés',
                              impact: 'Vulnérabilités (30 pts) + En-têtes HTTP (20 pts)',
                              conf: 'Moyenne — certains résultats doivent être confirmés par un second outil',
                            },
                            {
                              name: 'SSL Labs (Qualys)', icon: 'cloud',           confColor: '#00fc92',
                              role: 'Référence TLS publique',
                              scope: 'Configuration TLS, certificat, cipher suites, Forward Secrecy',
                              impact: 'TLS (25 pts) + Certificat (25 pts)',
                              conf: 'Haute — référence sectorielle pour TLS/certificat',
                            },
                            {
                              name: 'Censys',            icon: 'travel_explore', confColor: '#ffe066',
                              role: 'Observation externe Internet',
                              scope: 'Certificat, IP, ports ouverts, exposition publique',
                              impact: 'Certificat + observation externe',
                              conf: 'Moyenne — peut être moins récente selon la date d\'indexation Censys',
                            },
                            {
                              name: 'SSLyze',            icon: 'security',       confColor: '#00fc92',
                              role: 'Analyse technique TLS approfondie',
                              scope: 'Protocoles, ciphers, compression, vulnérabilités TLS (Heartbleed, ROBOT…)',
                              impact: 'TLS (25 pts) + Vulnérabilités TLS (30 pts)',
                              conf: 'Haute — outil de référence pour les protocoles et ciphers TLS',
                            },
                          ].map(src => (
                            <div key={src.name} className="rounded-xl border border-outline-variant/[0.1] bg-surface-container-low p-3">
                              <div className="flex items-center gap-2 mb-2.5">
                                <span className="material-symbols-outlined text-[13px] text-primary">{src.icon}</span>
                                <span className="text-[10px] font-bold text-on-surface">{src.name}</span>
                              </div>
                              <div className="space-y-1.5">
                                {[
                                  { lbl: 'Rôle',         val: src.role },
                                  { lbl: 'Périmètre',    val: src.scope },
                                  { lbl: 'Impact score', val: src.impact },
                                ].map(r => (
                                  <div key={r.lbl} className="flex items-start gap-2">
                                    <span className="text-[9px] text-outline/60 w-20 shrink-0 mt-0.5">{r.lbl}</span>
                                    <span className="text-[10px] text-on-surface-variant leading-tight">{r.val}</span>
                                  </div>
                                ))}
                                <div className="flex items-start gap-2 pt-1.5 border-t border-outline-variant/[0.06] mt-1">
                                  <span className="text-[9px] text-outline/60 w-20 shrink-0 mt-0.5">Confiance</span>
                                  <span className="text-[9px] font-bold leading-tight" style={{ color: src.confColor }}>{src.conf}</span>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                        <div className="rounded-xl bg-primary/[0.05] border border-primary/10 px-4 py-3">
                          <p className="text-[10px] text-on-surface-variant leading-relaxed">
                            <strong className="text-primary">Conclusion :</strong> Le verdict final n'est pas une moyenne simple des notes sources. Il est calculé par catégories pondérées selon la pertinence de chaque source pour chaque dimension de sécurité. En cas de désaccord entre sources, le résultat est marqué <em>« À confirmer »</em> plutôt que <em>« Vulnérable »</em>.
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}

            </div>
          </div>


          {/* ── Detailed sections — visible when Kali finished + sources left PENDING ─ */}
          {(() => {
            const allDone = isSslScanSettled(result);

            if (!allDone) return (
              <div className="flex items-center gap-4 px-5 py-5 rounded-2xl bg-surface-container border border-outline-variant/20">
                <span className="material-symbols-outlined text-primary text-2xl animate-spin shrink-0">progress_activity</span>
                <div>
                  <div className="font-headline font-bold text-sm text-on-surface">Analyse en cours…</div>
                  <div className="text-xs text-outline mt-0.5">
                    Les sections détaillées (protocoles, certificat, vulnérabilités, en-têtes HTTP, score) s'afficheront
                    dès que le scan Kali sera terminé et que les sources externes ne seront plus en attente
                    (ERROR/DISABLED compte comme terminé).
                  </div>
                </div>
              </div>
            );

            return (
              <div className="space-y-5">

                {/* ── Versions des protocoles TLS ─────────────────────────── */}
                {(() => {
                  const protocols = ensureTlsProtocols(result);
                  const bd = computeScoreBreakdown(result);
                  const modern = protocols.filter(p => MODERN_PROTO_IDS.has(p.id));
                  const obsolete = protocols.filter(p => OBSOLETE_PROTO_IDS.has(p.id));
                  const modernOn = modern.filter(p => p.status === 'ENABLED').length;
                  const obsoleteOff = obsolete.filter(p => p.status === 'DISABLED').length;
                  const compliance = tlsComplianceLabel(protocols);
                  const confidence = result.sslyzeStatus === 'READY' ? 'Haute'
                    : result.sslyzeStatus === 'PENDING' ? 'Faible' : 'Moyenne';
                  const confTone = confidence === 'Haute' ? 'text-tertiary'
                    : confidence === 'Moyenne' ? 'text-[#ffe066]' : 'text-outline';
                  const complianceTone = compliance.tone === 'ok' ? 'text-tertiary'
                    : compliance.tone === 'bad' ? 'text-error' : 'text-[#ffaa40]';

                  const renderProtoCard = (p: TlsProtocolDetailDto) => {
                    const isObsolete = OBSOLETE_PROTO_IDS.has(p.id);
                    const meta = protocolStatusMeta(p.status, isObsolete);
                    const isOpen = expanded === `proto-${p.id}`;
                    const verdicts = protocolVerdicts(p);
                    const ciphers = p.ciphers || [];
                    const top3 = ciphers.slice(0, 3);
                    const yn = (v: boolean | null | undefined) =>
                      v === true ? 'Oui' : v === false ? 'Non' : 'Non testé';

                    return (
                      <div key={p.id}
                        className={`rounded-xl border cursor-pointer transition-all select-none ${meta.border} ${meta.bg}`}
                        onClick={() => setExpanded(isOpen ? null : `proto-${p.id}`)}>
                        <div className="flex items-center gap-3 px-4 py-3">
                          <span className={`material-symbols-outlined text-base flex-shrink-0 ${meta.color}`}
                            style={{ fontVariationSettings: "'FILL' 1" }}>{meta.icon}</span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-headline font-bold text-sm text-on-surface">{p.label}</span>
                              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${meta.badge}`}>
                                {protocolStatusLabel(p.status)}
                              </span>
                            </div>
                            <div className="flex flex-wrap gap-1.5 mt-1">
                              {verdicts.map(v => (
                                <span key={v} className="text-[10px] text-outline">{v}</span>
                              ))}
                            </div>
                          </div>
                          <span className={`material-symbols-outlined text-outline/50 text-base flex-shrink-0 transition-transform ${isOpen ? 'rotate-180' : ''}`}>expand_more</span>
                        </div>
                        {isOpen && (
                          <div className="px-4 pb-4 pt-1 border-t border-outline-variant/[0.08] space-y-3" onClick={e => e.stopPropagation()}>
                            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                              {[
                                ['État du protocole', protocolStatusLabel(p.status)],
                                ['Handshake', p.handshakeOk === true ? 'Réussi' : p.handshakeOk === false ? 'Échoué' : 'Non testé'],
                                ['Suites acceptées', p.status === 'NOT_TESTED' || p.status === 'INCONCLUSIVE' ? 'Non testé' : String(p.acceptedCount ?? ciphers.length)],
                                ['Suites faibles', p.status === 'ENABLED' ? String(p.weakCount ?? 0) : '—'],
                                ['Forward Secrecy', yn(p.forwardSecrecy)],
                                ['Chiffrement AEAD', yn(p.aead)],
                                ['Compression TLS', yn(p.compression)],
                                ['Renégociation sécurisée', yn(p.secureRenegotiation)],
                                ['Endpoint', p.endpoint || '—'],
                                ['Adresse IP', p.ip || result.sslyzeIpAddress || '—'],
                                ['Port', p.port != null ? String(p.port) : (result.sslyzePort != null ? String(result.sslyzePort) : '—')],
                                ['SNI', p.sni || result.sslyzeSni || '—'],
                                ['Outil', p.tool || '—'],
                                ['Version outil', p.toolVersion || result.sslyzeVersion || '—'],
                                ['Date du scan', formatScanDate(p.scannedAt || result.sslyzeScanStarted)],
                                ['Niveau de confiance', p.confidence || confidence],
                              ].map(([k, v]) => (
                                <div key={k} className="rounded-lg bg-surface-container-highest/60 px-2.5 py-2">
                                  <div className="text-[9px] font-bold text-outline uppercase tracking-widest">{k}</div>
                                  <div className="text-xs text-on-surface mt-0.5 break-all">{v}</div>
                                </div>
                              ))}
                            </div>
                            {p.evidence && (
                              <div>
                                <div className="text-[10px] font-bold text-primary uppercase tracking-widest mb-1">Preuve technique</div>
                                <pre className="font-mono text-[10px] text-[#8b949e] bg-[#0d1117] px-3 py-2.5 rounded-lg overflow-x-auto border border-outline-variant/10 whitespace-pre-wrap">{p.evidence}</pre>
                              </div>
                            )}
                            {(p.id === 'tls12' || p.id === 'tls13') && p.status === 'ENABLED' && (
                              <div>
                                <div className="text-[10px] font-bold text-on-surface uppercase tracking-widest mb-2">Suites cryptographiques</div>
                                {top3.length === 0 ? (
                                  <p className="text-xs text-outline italic">Aucune suite détaillée disponible (données SSLyze absentes).</p>
                                ) : (
                                  <div className="space-y-1.5">
                                    {top3.map((c: TlsCipherSuiteDto) => (
                                      <div key={c.ianaName} className="flex flex-wrap items-center gap-2 px-3 py-2 rounded-lg bg-surface-container-highest/50 border border-outline-variant/10">
                                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                                          c.strength === 'FORBIDDEN' ? 'bg-error/15 text-error'
                                            : c.strength === 'WEAK' ? 'bg-[#ffaa40]/15 text-[#ffaa40]'
                                            : 'bg-tertiary/15 text-tertiary'
                                        }`}>{cipherStrengthLabel(c.strength)}</span>
                                        <span className="font-mono text-[10px] text-on-surface">{c.ianaName}</span>
                                        <span className="text-[10px] text-outline">{c.encryption}</span>
                                        <span className="text-[10px] text-outline">· {c.keyExchange}</span>
                                        {c.keySize ? <span className="text-[10px] text-outline">· {c.keySize} bits</span> : null}
                                        <span className="text-[10px] text-outline">· FS {c.forwardSecrecy ? 'oui' : 'non'}</span>
                                      </div>
                                    ))}
                                    {ciphers.length > 3 && (
                                      <button type="button"
                                        onClick={() => setCipherModalProto(p)}
                                        className="mt-1 text-xs font-bold text-primary hover:underline">
                                        Voir toutes les suites ({ciphers.length})
                                      </button>
                                    )}
                                    {ciphers.length > 0 && ciphers.length <= 3 && (
                                      <button type="button"
                                        onClick={() => setCipherModalProto(p)}
                                        className="mt-1 text-xs font-bold text-primary hover:underline">
                                        Voir toutes les suites
                                      </button>
                                    )}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  };

                  return (
                    <div className="bg-surface-container rounded-2xl p-5 space-y-5">
                      <div>
                        <h2 className="font-headline font-bold text-sm flex items-center gap-2 mb-1">
                          <span className="material-symbols-outlined text-primary text-lg">shield</span>
                          Versions des protocoles TLS
                        </h2>
                        <p className="text-xs text-outline">Analyse des versions SSL/TLS testées (SSLyze + Kali). Un protocole non testé n’est jamais affiché comme désactivé.</p>
                      </div>

                      {/* Synthèse */}
                      <div className="rounded-xl border border-primary/20 bg-surface-container-low p-4">
                        <div className="text-[10px] font-bold text-primary uppercase tracking-widest mb-3">Synthèse</div>
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                          <div>
                            <div className="text-[10px] text-outline">Plage TLS</div>
                            <div className="text-sm font-headline font-bold text-on-surface">{tlsRangeLabel(protocols)}</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-outline">Protocoles modernes activés</div>
                            <div className="text-sm font-headline font-bold text-[#a4e6ff]">{modernOn} / 2</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-outline">Protocoles obsolètes désactivés</div>
                            <div className="text-sm font-headline font-bold text-tertiary">{obsoleteOff} / 4</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-outline">Niveau de conformité</div>
                            <div className={`text-sm font-headline font-bold ${complianceTone}`}>{compliance.text}</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-outline">Niveau de confiance</div>
                            <div className={`text-sm font-headline font-bold ${confTone}`}>Confiance {confidence.toLowerCase()}</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-outline">Score catégorie</div>
                            <div className="text-sm font-headline font-bold text-on-surface">{bd.tls}/25</div>
                          </div>
                        </div>
                      </div>

                      <div>
                        <div className="text-[10px] font-bold text-outline uppercase tracking-widest mb-2">Protocoles modernes</div>
                        <div className="space-y-2">{modern.map(renderProtoCard)}</div>
                      </div>

                      <div>
                        <div className="text-[10px] font-bold text-outline uppercase tracking-widest mb-2">Protocoles obsolètes</div>
                        <div className="space-y-2">{obsolete.map(renderProtoCard)}</div>
                      </div>

                      <div className="rounded-xl border border-outline-variant/20 bg-surface-container-highest/30 px-4 py-3 flex items-start gap-2">
                        <span className="material-symbols-outlined text-primary text-base shrink-0 mt-0.5">clinical_notes</span>
                        <p className="text-xs text-on-surface-variant leading-relaxed">{tlsSectionConclusion(protocols)}</p>
                      </div>

                      {cipherModalProto && (
                        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60"
                          onClick={() => setCipherModalProto(null)}>
                          <div className="w-full max-w-3xl max-h-[80vh] overflow-hidden rounded-2xl border border-outline-variant/20 bg-surface-container shadow-2xl"
                            onClick={e => e.stopPropagation()}>
                            <div className="flex items-center justify-between px-5 py-3 border-b border-outline-variant/15">
                              <div>
                                <div className="font-headline font-bold text-sm text-on-surface">Suites — {cipherModalProto.label}</div>
                                <div className="text-[11px] text-outline">{(cipherModalProto.ciphers || []).length} suite(s) acceptée(s)</div>
                              </div>
                              <button type="button" onClick={() => setCipherModalProto(null)}
                                className="material-symbols-outlined text-outline hover:text-on-surface">close</button>
                            </div>
                            <div className="overflow-auto max-h-[65vh] p-4">
                              <table className="w-full text-left text-[11px]">
                                <thead className="text-outline sticky top-0 bg-surface-container">
                                  <tr>
                                    <th className="py-2 pr-2 font-bold">Force</th>
                                    <th className="py-2 pr-2 font-bold">IANA</th>
                                    <th className="py-2 pr-2 font-bold">Chiffrement</th>
                                    <th className="py-2 pr-2 font-bold">Échange</th>
                                    <th className="py-2 pr-2 font-bold">Clé</th>
                                    <th className="py-2 font-bold">FS</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {(cipherModalProto.ciphers || []).map(c => (
                                    <tr key={c.ianaName} className="border-t border-outline-variant/10">
                                      <td className="py-2 pr-2">
                                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                                          c.strength === 'FORBIDDEN' ? 'bg-error/15 text-error'
                                            : c.strength === 'WEAK' ? 'bg-[#ffaa40]/15 text-[#ffaa40]'
                                            : 'bg-tertiary/15 text-tertiary'
                                        }`}>{cipherStrengthLabel(c.strength)}</span>
                                      </td>
                                      <td className="py-2 pr-2 font-mono text-on-surface break-all">{c.ianaName}</td>
                                      <td className="py-2 pr-2 text-on-surface-variant">{c.encryption || '—'}</td>
                                      <td className="py-2 pr-2 text-on-surface-variant">{c.keyExchange || '—'}</td>
                                      <td className="py-2 pr-2 text-on-surface-variant">{c.keySize ? `${c.keySize}` : '—'}</td>
                                      <td className="py-2 text-on-surface-variant">{c.forwardSecrecy ? 'Oui' : 'Non'}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })()}

                {/* ── Détails du certificat ──────────────────────────────── */}
                <CertificateDetailSection
                  result={result}
                  certificateScore={computeScoreBreakdown(result).certificate}
                />

                {/* ── Vulnérabilités SSL/TLS ─────────────────────────────── */}
                <SslVulnerabilitiesSection result={result} />

                {/* ── En-têtes de sécurité HTTP ─────────────────────────── */}
                <SslSecurityHeadersSection result={result} />

                {/* ── Résumé exécutif ──────────────────────────────────────────── */}
                {(() => {
                  const hblSrcs: SourceValue[] = [result.heartbleed ?? undefined, result.sslyzeHeartbleed ?? undefined];
                  const hblSt = getVulnStatus(hblSrcs);
                  const hdrMain = [
                    result.hsts,
                    result.contentSecurityPolicy || result.cspReportOnly,
                    result.xFrameOptions || !!(result.cspValue && /frame-ancestors\b/i.test(result.cspValue)),
                    result.xContentTypeOptions,
                    result.referrerPolicy,
                    result.permissionsPolicy,
                  ];
                  const hdrCount = hdrMain.filter(Boolean).length;
                  const hdrTotal = 6;
                  const tlsOk = (result.tls12 || result.sslyzeSupportsTLS12) && (result.tls13 || result.sslyzeSupportsTLS13);
                  const criticalItems: string[] = [];
                  const highItems: string[] = [];
                  const mediumItems: string[] = [];
                  const lowItems: string[] = [];
                  if (hblSt === 'to_confirm') criticalItems.push('Alerte Heartbleed détectée par une source — critique si confirmée (à vérifier avec un second outil)');
                  if (hblSt === 'confirmed')  criticalItems.push('Heartbleed confirmé — mise à jour OpenSSL et régénération des certificats requises');
                  if (result.poodle)          criticalItems.push('POODLE détecté — désactiver SSL 3.0 immédiatement');
                  if (result.drown || result.ssllabsDrown) criticalItems.push('DROWN détecté — désactiver SSL 2.0 sur tous les services utilisant la même clé');
                  if (!result.hsts)                 highItems.push('HSTS absent — ajouter Strict-Transport-Security');
                  if (!result.contentSecurityPolicy && result.cspReportOnly) {
                    highItems.push('CSP présente en mode Report-Only — non appliquée (collecte les violations sans bloquer)');
                  } else if (!result.contentSecurityPolicy) {
                    highItems.push('Content-Security-Policy absente — risque XSS accru');
                  }
                  if (!result.xFrameOptions)        highItems.push('X-Frame-Options absent — risque de clickjacking');
                  if (result.robot || result.sslyzeRobot) highItems.push('ROBOT détecté — supprimer les suites RSA key-exchange');
                  if (!result.referrerPolicy)    mediumItems.push('Referrer-Policy absente — fuite d\'URL possible vers des tiers');
                  if (!result.permissionsPolicy) mediumItems.push('Permissions-Policy absente — fonctionnalités navigateur non restreintes');
                  if (!result.xContentTypeOptions) mediumItems.push('X-Content-Type-Options absent — risque MIME sniffing');
                  if (result.certDaysLeft > 0 && result.certDaysLeft < 60) lowItems.push(`Certificat expire dans ${result.certDaysLeft} jours — prévoir un renouvellement`);
                  const allPriItems = [...criticalItems, ...highItems, ...mediumItems, ...lowItems];
                  return (
                    <div className="rounded-2xl border border-primary/15 bg-surface-container-low overflow-hidden">
                      <div className="px-5 pt-4 pb-3 border-b border-outline-variant/[0.08] flex items-center gap-2">
                        <span className="material-symbols-outlined text-primary text-base" style={{ fontVariationSettings: "'FILL' 1" }}>summarize</span>
                        <div>
                          <div className="font-headline font-bold text-sm text-on-surface">Résumé exécutif</div>
                          <div className="text-[11px] text-outline">Synthèse de l'état de sécurité SSL/TLS — {new Date().toLocaleDateString('fr-FR')}</div>
                        </div>
                      </div>
                      <div className="px-5 py-4 space-y-3">
                        {[
                          {
                            ok: tlsOk,
                            text: tlsOk
                              ? <><strong className="text-on-surface">Configuration TLS moderne</strong> — TLS 1.2 et TLS 1.3 activés sur ce serveur.</>
                              : <><strong className="text-[#ffaa40]">Configuration TLS incomplète</strong> — TLS 1.3 {!(result.tls13||result.sslyzeSupportsTLS13)?'absent':'actif'}, TLS 1.2 {!(result.tls12||result.sslyzeSupportsTLS12)?'absent':'actif'}.</>,
                          },
                          {
                            ok: !result.certExpired,
                            text: !result.certExpired
                              ? <><strong className="text-on-surface">Certificat valide</strong>, fiable et correctement chaîné ({result.certDaysLeft > 0 ? `${result.certDaysLeft} jours restants` : 'validité inconnue'}).</>
                              : <><strong className="text-error">Certificat expiré</strong> — les connexions seront rejetées par les navigateurs modernes.</>,
                          },
                          hblSt === 'to_confirm' ? {
                            ok: false,
                            text: <><strong className="text-[#ffaa40]">Alerte Heartbleed détectée par une source — critique si confirmée</strong> (à vérifier avec un second outil indépendant).</>,
                          } : hblSt === 'confirmed' ? {
                            ok: false,
                            text: <><strong className="text-error">Heartbleed confirmé</strong> — mise à jour immédiate d'OpenSSL requise.</>,
                          } : null,
                          {
                            ok: hdrCount >= 5,
                            text: <>Protections HTTP principales : <strong className={hdrCount >= 5 ? 'text-tertiary' : hdrCount >= 3 ? 'text-[#ffe066]' : 'text-error'}>{hdrCount}/{hdrTotal} actives</strong>{hdrCount < hdrTotal ? ` — couverture ${hdrCount === 0 ? 'absente' : 'partielle'} (COOP/CORP/COEP exclus car contextuels).` : ' — bonne couverture des protections principales.'}</>,
                          },
                        ].filter(Boolean).map((item: any, i) => (
                          <div key={i} className="flex items-start gap-2.5">
                            <span className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${item.ok ? 'bg-tertiary/15' : 'bg-error/15'}`}>
                              <span className={`material-symbols-outlined text-[11px] ${item.ok ? 'text-tertiary' : 'text-error'}`} style={{ fontVariationSettings: "'FILL' 1" }}>{item.ok ? 'check' : 'warning'}</span>
                            </span>
                            <p className="text-xs text-on-surface-variant leading-relaxed">{item.text}</p>
                          </div>
                        ))}
                        {allPriItems.length > 0 && (
                          <div className="border-t border-outline-variant/[0.08] pt-3 space-y-1.5">
                            <div className="text-[10px] font-bold text-outline uppercase tracking-[0.15em] mb-2">Plan de priorité</div>
                            {criticalItems.map((item, i) => (
                              <div key={`c${i}`} className="flex items-start gap-2">
                                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-error/20 text-error shrink-0 mt-0.5 whitespace-nowrap">Critique</span>
                                <span className="text-xs text-on-surface-variant">{item}</span>
                              </div>
                            ))}
                            {highItems.map((item, i) => (
                              <div key={`h${i}`} className="flex items-start gap-2">
                                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#ffaa40]/20 text-[#ffaa40] shrink-0 mt-0.5 whitespace-nowrap">Haute</span>
                                <span className="text-xs text-on-surface-variant">{item}</span>
                              </div>
                            ))}
                            {mediumItems.map((item, i) => (
                              <div key={`m${i}`} className="flex items-start gap-2">
                                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#ffe066]/20 text-[#ffe066] shrink-0 mt-0.5 whitespace-nowrap">Moyenne</span>
                                <span className="text-xs text-on-surface-variant">{item}</span>
                              </div>
                            ))}
                            {lowItems.map((item, i) => (
                              <div key={`l${i}`} className="flex items-start gap-2">
                                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-surface-container-highest text-outline shrink-0 mt-0.5 whitespace-nowrap">Basse</span>
                                <span className="text-xs text-on-surface-variant">{item}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })()}

                {/* ── Score récapitulatif ────────────────────────────────── */}
                <div className="bg-surface-container rounded-2xl p-6">
                  <h2 className="font-headline font-bold text-base flex items-center gap-2 mb-5">
                    <span className="material-symbols-outlined text-primary text-lg">analytics</span>
                    Score récapitulatif
                  </h2>
                  {(() => {
                    const bd  = computeScoreBreakdown(result);
                    const col = gradeColor(bd.grade).ring;

                    const categories = [
                      { label: 'TLS et protocoles', score: bd.tls,             max: 25, icon: 'shield',     desc: 'TLS 1.3, désactivation des versions obsolètes', src: 'SSL Labs · SSLyze' },
                      { label: 'Certificat',         score: bd.certificate,     max: 25, icon: 'verified',   desc: 'Validité, chaîne CA, SAN, OCSP Stapling',       src: 'SSL Labs · Censys · SSLyze' },
                      { label: 'Vulnérabilités',     score: bd.vulnerabilities, max: 30, icon: 'bug_report', desc: 'Heartbleed, POODLE, DROWN, ROBOT, RC4, 3DES…',  src: 'Kali · SSLyze · SSL Labs' },
                      { label: 'En-têtes HTTP',      score: bd.headers,         max: 20, icon: 'http',       desc: 'HSTS, CSP, anti-framing, XCTO… (sans OCSP / COOP)', src: 'Analyse HTTP live' },
                    ];
                    const categoryLabel: Record<string, string> = {
                      tls: 'TLS',
                      certificate: 'Certificat',
                      vulnerabilities: 'Vulnérabilités',
                      headers: 'En-têtes',
                    };

                    return (
                      <div>
                        {/* Score total + grade + risk + confidence */}
                        <div className="flex flex-wrap items-end gap-4 mb-5">
                          <div className="flex items-end gap-2">
                            <span className="text-5xl font-headline font-extrabold" style={{ color: col }}>{bd.total}</span>
                            <span className="text-xl text-outline mb-1">/100</span>
                            <span className="text-2xl font-headline font-bold ml-1 mb-1 px-3 py-0.5 rounded-lg"
                              style={{ color: col, background: `${col}15`, border: `1px solid ${col}33` }}>{bd.grade}</span>
                          </div>
                          <div className="flex gap-2 flex-wrap mb-1">
                            {[
                              { label: 'Risque', value: bd.riskLevel,       color: bd.riskLevel==='Critique'?'#ffb4ab':bd.riskLevel==='Élevé'?'#ffaa40':bd.riskLevel==='Moyen'?'#ffe066':'#00fc92' },
                              { label: 'Confiance', value: bd.confidence,   color: bd.confidence==='Haute'?'#00fc92':bd.confidence==='Moyenne'?'#ffe066':'#8b949e' },
                              { label: 'Consensus', value: bd.consensus.level, color: bd.consensus.level==='Fort'?'#00fc92':bd.consensus.level==='Moyen'?'#ffe066':'#ffaa40' },
                            ].map(badge => (
                              <span key={badge.label} className="text-[9px] font-bold px-2 py-0.5 rounded-full border whitespace-nowrap"
                                style={{ color: badge.color, background: `${badge.color}15`, borderColor: `${badge.color}30` }}>
                                {badge.label} · {badge.value}
                              </span>
                            ))}
                          </div>
                        </div>
                        <div className="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden mb-6">
                          <div className="h-full rounded-full transition-all" style={{ width: `${bd.total}%`, background: col }} />
                        </div>

                        {/* 4-category breakdown */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
                          {categories.map(cat => {
                            const pct    = cat.score / cat.max;
                            const catCol = pct >= 0.9 ? '#00fc92' : pct >= 0.7 ? '#a4e6ff' : pct >= 0.5 ? '#ffe066' : pct >= 0.3 ? '#ffaa40' : '#ffb4ab';
                            return (
                              <div key={cat.label} className="rounded-xl border border-outline-variant/[0.1] bg-surface-container-low p-3">
                                <div className="flex items-center gap-1.5 mb-2">
                                  <span className="material-symbols-outlined text-[13px] text-outline">{cat.icon}</span>
                                  <span className="text-[9px] font-bold uppercase tracking-wide text-outline">{cat.label}</span>
                                </div>
                                <div className="flex items-end gap-1 mb-1.5">
                                  <span className="text-xl font-headline font-extrabold" style={{ color: catCol }}>{cat.score}</span>
                                  <span className="text-xs text-outline mb-0.5">/{cat.max}</span>
                                </div>
                                <div className="h-1.5 w-full bg-surface-container-highest rounded-full overflow-hidden">
                                  <div className="h-full rounded-full" style={{ width: `${pct * 100}%`, background: catCol }} />
                                </div>
                                <p className="text-[9px] text-outline/50 mt-1.5 leading-tight">{cat.desc}</p>
                                <p className="text-[8px] text-outline/30 mt-0.5 leading-tight">Sources : {cat.src}</p>
                              </div>
                            );
                          })}
                        </div>

                        {/* Deduction breakdown from computeScoreBreakdown */}
                        {bd.penalties.length > 0 && (
                          <div className="rounded-xl border border-outline-variant/[0.1] bg-surface-container-low p-4">
                            <div className="text-[10px] font-bold text-outline uppercase tracking-[0.15em] mb-3">Ce qui baisse le score</div>
                            <div className="space-y-1.5">
                              {bd.penalties.map((p, i) => {
                                const sevCol = p.category === 'vulnerabilities' && p.points >= 10 ? '#ffb4ab'
                                  : p.category === 'vulnerabilities' && p.points >= 5 ? '#ffaa40'
                                  : p.category === 'headers' && p.points >= 4 ? '#ffaa40'
                                  : '#ffe066';
                                return (
                                  <div key={i} className="flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: sevCol }} />
                                      <span className="text-xs text-on-surface-variant">{p.label}</span>
                                      <span className="text-[8px] text-outline/40 hidden sm:inline">
                                        {categoryLabel[p.category] || p.category}
                                      </span>
                                    </div>
                                    <span className="text-[10px] font-bold shrink-0" style={{ color: sevCol }}>-{p.points} pts</span>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>


              </div>
            );
          })()}

        </div>
      )}

      {/* ── Empty state ───────────────────────────────────────────────── */}
      {!scanning && !result && !error && (
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <div className="w-20 h-20 rounded-2xl bg-primary/10 flex items-center justify-center mb-6">
            <span className="material-symbols-outlined text-primary text-4xl" style={{ fontVariationSettings: "'FILL' 1" }}>lock</span>
          </div>
          <h3 className="text-xl font-headline font-bold text-on-surface mb-2">Aucune analyse</h3>
          <p className="text-on-surface-variant text-sm max-w-sm">
            Entrez un domaine ci-dessus et cliquez sur <strong>ANALYSER</strong> pour lancer l'inspection SSL/TLS complète.
          </p>
          <div className="mt-8 grid grid-cols-2 md:grid-cols-4 gap-3 max-w-lg w-full">
            {['sslyze', 'sslscan', 'testssl.sh', 'nmap'].map(tool => (
              <div key={tool} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-container border border-outline-variant/10 text-xs text-outline font-mono">
                <span className="w-1.5 h-1.5 rounded-full bg-primary/60 flex-shrink-0" />
                {tool}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── How SSL scan works ──────────────────────────────────── */}
      <SslHowtoCard open={howtoOpen} onClose={() => setHowtoOpen(false)} />

      {/* ── Schedule Modal ─────────────────────────────────────── */}
      <SSLScheduleModal
        domain={domain}
        open={scheduleModalOpen}
        scheduleDate={scheduleDate}
        scheduleHour={scheduleHour}
        scheduleMinute={scheduleMinute}
        scheduleFrequency={scheduleFrequency}
        scheduleSubmitting={scheduleSubmitting}
        scheduleError={scheduleError}
        scheduleSuccess={scheduleSuccess}
        onClose={() => setScheduleModalOpen(false)}
        onDateChange={setScheduleDate}
        onHourChange={setScheduleHour}
        onMinuteChange={setScheduleMinute}
        onFrequencyChange={setScheduleFrequency}
        onSubmit={handleCreateSslSchedule}
      />
    </div>
  );
};

export default SSLAnalysis;

/* ═══════════════════════════════════════════════════════════════════════
   SSL Schedule Modal (rendered at page level)
════════════════════════════════════════════════════════════════════════ */
export function SSLScheduleModal(props: {
  domain: string;
  open: boolean;
  scheduleDate: string;
  scheduleHour: string;
  scheduleMinute: string;
  scheduleFrequency: ScheduleType;
  scheduleSubmitting: boolean;
  scheduleError: string;
  scheduleSuccess: string;
  onClose: () => void;
  onDateChange: (v: string) => void;
  onHourChange: (v: string) => void;
  onMinuteChange: (v: string) => void;
  onFrequencyChange: (v: ScheduleType) => void;
  onSubmit: () => void;
}) {
  if (!props.open) return null;
  const freqLabels: Record<ScheduleType, string> = {
    ONCE: 'Une fois',
    WEEKLY: 'Hebdomadaire',
    EVERY_15_DAYS: 'Tous les 15 jours',
    MONTHLY: 'Mensuel',
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={props.onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div
        className="relative z-10 w-full max-w-md bg-surface-container rounded-2xl border border-violet-500/20 shadow-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 bg-surface-container-highest/50 border-b border-outline-variant/[0.1]">
          <div className="flex items-center gap-3">
            <span className="material-symbols-outlined text-violet-400 text-lg" style={{ fontVariationSettings: "'FILL' 1" }}>calendar_clock</span>
            <div>
              <h2 className="font-headline font-bold text-on-surface text-sm">Planifier un scan SSL</h2>
              <p className="text-[11px] text-outline font-mono">{props.domain}</p>
            </div>
          </div>
          <button onClick={props.onClose} className="text-outline hover:text-on-surface transition-colors">
            <span className="material-symbols-outlined text-lg">close</span>
          </button>
        </div>

        <div className="p-5 space-y-4">
          {/* Date */}
          <div>
            <label className="block text-[10px] font-bold text-outline uppercase tracking-widest mb-1.5">Date du premier scan</label>
            <input
              type="date"
              className="w-full bg-surface-container-low border border-outline-variant/[0.2] rounded-lg px-3 py-2.5 text-sm text-on-surface focus:ring-1 focus:ring-violet-500 focus:border-violet-500/50 appearance-none cursor-pointer [color-scheme:dark]"
              value={props.scheduleDate}
              onChange={e => props.onDateChange(e.target.value)}
            />
          </div>

          {/* Time */}
          <div>
            <label className="block text-[10px] font-bold text-outline uppercase tracking-widest mb-1.5">Heure</label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <select
                  className="w-full bg-surface-container-low border border-outline-variant/[0.2] rounded-lg px-3 py-2.5 pr-8 text-sm text-on-surface focus:ring-1 focus:ring-violet-500 focus:border-violet-500/50 appearance-none cursor-pointer [color-scheme:dark]"
                  value={props.scheduleHour}
                  onChange={e => props.onHourChange(e.target.value)}
                >
                  {Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0')).map(h => (
                    <option key={h} value={h}>{h}h</option>
                  ))}
                </select>
                <span className="material-symbols-outlined absolute right-2 top-1/2 -translate-y-1/2 text-outline text-[14px] pointer-events-none">expand_more</span>
              </div>
              <div className="relative flex-1">
                <select
                  className="w-full bg-surface-container-low border border-outline-variant/[0.2] rounded-lg px-3 py-2.5 pr-8 text-sm text-on-surface focus:ring-1 focus:ring-violet-500 focus:border-violet-500/50 appearance-none cursor-pointer [color-scheme:dark]"
                  value={props.scheduleMinute}
                  onChange={e => props.onMinuteChange(e.target.value)}
                >
                  {['00','05','10','15','20','25','30','35','40','45','50','55'].map(m => (
                    <option key={m} value={m}>:{m}</option>
                  ))}
                </select>
                <span className="material-symbols-outlined absolute right-2 top-1/2 -translate-y-1/2 text-outline text-[14px] pointer-events-none">expand_more</span>
              </div>
            </div>
          </div>

          {/* Frequency */}
          <div>
            <label className="block text-[10px] font-bold text-outline uppercase tracking-widest mb-1.5">Fréquence</label>
            <div className="grid grid-cols-2 gap-2">
              {(['ONCE', 'WEEKLY', 'EVERY_15_DAYS', 'MONTHLY'] as ScheduleType[]).map(f => (
                <button
                  key={f}
                  onClick={() => props.onFrequencyChange(f)}
                  className={`py-2.5 px-3 rounded-xl text-xs font-bold border transition-all ${
                    props.scheduleFrequency === f
                      ? 'bg-violet-500/20 border-violet-500/50 text-violet-300 shadow-[0_0_12px_rgba(167,139,250,0.2)]'
                      : 'bg-surface-container-low border-outline-variant/[0.15] text-outline hover:border-violet-500/30 hover:text-violet-400'
                  }`}
                >
                  {freqLabels[f]}
                </button>
              ))}
            </div>
          </div>

          {/* Summary */}
          <div className="px-3 py-2.5 rounded-xl bg-violet-500/5 border border-violet-500/10 text-[11px] text-on-surface-variant">
            <span className="material-symbols-outlined text-[13px] text-violet-400 align-middle mr-1">info</span>
            Le scan SSL de <span className="font-bold text-on-surface">{props.domain}</span> sera planifié le{' '}
            <span className="font-bold text-violet-300">{props.scheduleDate}</span> à{' '}
            <span className="font-bold text-violet-300">{props.scheduleHour}:{props.scheduleMinute}</span> — {freqLabels[props.scheduleFrequency].toLowerCase()}.
          </div>

          {/* Messages */}
          {props.scheduleError && (
            <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-error/10 border border-error/20 text-xs text-error">
              <span className="material-symbols-outlined text-sm shrink-0 mt-0.5">error</span>
              <span>{props.scheduleError}</span>
            </div>
          )}
          {props.scheduleSuccess && (
            <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-tertiary/10 border border-tertiary/20 text-xs text-tertiary">
              <span className="material-symbols-outlined text-sm shrink-0 mt-0.5">check_circle</span>
              <span>{props.scheduleSuccess}</span>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-3 pt-1">
            <button
              onClick={props.onClose}
              className="flex-1 py-2.5 rounded-xl border border-outline-variant/20 text-sm font-bold text-outline hover:text-on-surface hover:border-outline/40 transition-all"
            >
              Annuler
            </button>
            <button
              onClick={props.onSubmit}
              disabled={props.scheduleSubmitting || !!props.scheduleSuccess}
              className="flex-1 py-2.5 rounded-xl bg-violet-500/20 border border-violet-500/40 text-sm font-bold text-violet-300 hover:bg-violet-500/30 hover:border-violet-500/60 hover:shadow-[0_0_16px_rgba(167,139,250,0.3)] disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {props.scheduleSubmitting ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="material-symbols-outlined text-base animate-spin">progress_activity</span>
                  Planification…
                </span>
              ) : props.scheduleSuccess ? 'Planifié !' : 'Confirmer'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function SslHowtoCard({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;

  const steps: Array<{ n: string; title: string; tools?: string; desc: string }> = [
    {
      n: '0',
      title: 'Lancement',
      desc: 'Vous saisissez un domaine puis ANALYSER. Le backend crée un scan ssl-only, ouvre le journal en direct (SSE) et démarre trois sources en même temps : Kali, SSL Labs et Censys.',
    },
    {
      n: '1/6',
      title: 'SSLyze',
      tools: 'Kali · ~180 s',
      desc: 'Protocoles TLS, suites cryptographiques, Heartbleed, ROBOT, chaîne de certificats. Produit sslyze.json (note source 20 %).',
    },
    {
      n: '2/6',
      title: 'sslscan',
      tools: 'Kali · ~120 s',
      desc: 'Inventaire TLS 1.0–1.3, 3DES, RC4, POODLE. Écrit sslscan.xml.',
    },
    {
      n: '3/6',
      title: 'testssl.sh',
      tools: 'Kali · jusqu’à 600 s',
      desc: 'Vulnérabilités TLS (BEAST, FREAK, LOGJAM, SWEET32, DROWN, CRIME) et en-têtes HTTP. Écrit testssl.json.',
    },
    {
      n: '4/6',
      title: 'Nmap ssl-enum-ciphers',
      tools: 'Kali · ~120 s',
      desc: 'Confirmation des protocoles et ciphers côté serveur. Écrit nmap-ssl.txt.',
    },
    {
      n: '4b/6',
      title: 'Nmap ssl-heartbleed',
      tools: 'Kali · ~90 s',
      desc: 'Preuve ciblée CVE-2014-0160 (Heartbleed). Écrit nmap-heartbleed.xml.',
    },
    {
      n: '5/6',
      title: 'Nikto',
      tools: 'Kali · jusqu’à 600 s',
      desc: 'En-têtes HTTP et mauvaises pratiques web exposées sur le même hôte.',
    },
    {
      n: '6/6',
      title: 'WhatWeb',
      tools: 'Kali · ~60 s',
      desc: 'Empreinte technologique (serveur, CMS, frameworks) pour le contexte du rapport.',
    },
    {
      n: 'Σ',
      title: 'Synthèse Kali',
      desc: 'Le scanner fusionne les fichiers en ssl-summary.json (note Kali interne, 20 % du score combiné).',
    },
    {
      n: '∥',
      title: 'SSL Labs (Qualys)',
      tools: 'Externe · 30 %',
      desc: 'Tourne en parallèle de Kali. Note A–F, Forward Secrecy, avertissements. N’attend pas la fin des outils Kali.',
    },
    {
      n: '∥',
      title: 'Censys',
      tools: 'Externe · 30 %',
      desc: 'Aussi en parallèle : certificat observé sur Internet, IP, ports ouverts, Certificate Transparency.',
    },
    {
      n: '✓',
      title: 'Rapport dans l’application',
      desc: 'Le backend assemble les 4 sources, calcule le grade combiné, persiste le résultat, puis affiche protocoles, certificat, vulnérabilités, en-têtes et score. Gemini peut ensuite commenter le verdict.',
    },
  ];

  return (
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 print:hidden"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl max-h-[88vh] overflow-y-auto rounded-2xl border border-outline-variant/30 bg-surface-container shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="sticky top-0 z-10 flex items-start justify-between gap-3 px-5 py-4 border-b border-outline-variant/15 bg-surface-container">
          <div className="flex items-start gap-3">
            <span className="material-symbols-outlined text-primary mt-0.5" style={{ fontVariationSettings: "'FILL' 1" }}>
              account_tree
            </span>
            <div>
              <h2 className="font-headline font-bold text-on-surface text-base">
                Comment le scan SSL / TLS se déroule
              </h2>
              <p className="text-xs text-on-surface-variant mt-1 max-w-md">
                Ordre réel dans Vulnix : Kali enchaîne les outils 1 → 6, pendant que SSL Labs et Censys partent en parallèle dès le clic ANALYSER.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-outline hover:text-on-surface hover:bg-surface-container-high"
            aria-label="Fermer"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        <ol className="px-5 py-4 space-y-2">
          {steps.map((s, i) => (
            <li
              key={`${s.n}-${s.title}-${i}`}
              className="flex gap-3 rounded-xl border border-outline-variant/10 bg-surface-container-low/60 px-3 py-2.5"
            >
              <span className="shrink-0 w-11 text-center text-[10px] font-headline font-extrabold text-primary pt-0.5">
                {s.n}
              </span>
              <div className="min-w-0">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="text-sm font-headline font-bold text-on-surface">{s.title}</span>
                  {s.tools && (
                    <span className="text-[9px] font-bold uppercase tracking-wider text-outline">{s.tools}</span>
                  )}
                </div>
                <p className="text-[11px] text-on-surface-variant leading-relaxed mt-0.5">{s.desc}</p>
              </div>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
