import type { SslResultDto } from '../services/api';
import { computeHttpHeadersCategoryScore } from '../components/sslHeaderModel';

/**
 * The SSL verdict shown at the top of the SSL page: a score out of 100 by category (each lost point is listed),
 * then grade caps for the flaws that no amount of points can make up for (an expired certificate is refused by
 * every browser, whatever the rest of the configuration). The caps follow the spirit of the SSL Labs grading guide.
 */

export type SourceValue = boolean | null | undefined | 'timeout' | 'error';
export type VulnStatus = 'confirmed' | 'to_confirm' | 'secure' | 'indeterminate' | 'not_tested';
export type ConfidenceLevel = 'Haute' | 'Moyenne' | 'Faible';
export type RiskLevel = 'Critique' | 'Élevé' | 'Moyen' | 'Faible';

export type GradeCap = {
  /** Best grade still possible with this flaw. */
  grade: 'F' | 'C' | 'B' | 'A';
  reason: string;
  action: string;
};

export type ScoreBreakdown = {
  tls: number; // /25
  certificate: number; // /25
  vulnerabilities: number; // /30
  headers: number; // /20
  total: number; // /100
  /** Grade after caps: this is the verdict. */
  grade: string;
  /** Grade from the points alone, before caps. */
  scoreGrade: string;
  /** Caps that lowered the grade, most severe first. */
  caps: GradeCap[];
  /** Every blocking flaw found (whether or not it lowered the grade), most severe first: the things to fix. */
  flaws: GradeCap[];
  riskLevel: RiskLevel;
  confidence: ConfidenceLevel;
  consensus: { level: 'Fort' | 'Moyen' | 'Faible'; pct: number };
  hblStatus: VulnStatus;
  penalties: Array<{
    label: string;
    points: number;
    category: 'tls' | 'certificate' | 'vulnerabilities' | 'headers';
  }>;
};

export const GRADE_ORDER = ['A+', 'A', 'B', 'C', 'D', 'E', 'F'] as const;

export function gradeRank(g: string): number {
  const i = (GRADE_ORDER as readonly string[]).indexOf(g);
  return i < 0 ? GRADE_ORDER.length - 1 : i;
}

export function getVulnStatus(sources: SourceValue[]): VulnStatus {
  const tested = sources.filter((s) => s === true || s === false);
  const positive = tested.filter((s) => s === true);
  const failed = sources.filter((s) => s === 'timeout' || s === 'error');
  if (tested.length === 0 && failed.length > 0) return 'indeterminate';
  if (tested.length === 0) return 'not_tested';
  if (positive.length >= 2) return 'confirmed';
  if (positive.length === 1) return 'to_confirm';
  return 'secure';
}

export function getGrade(score: number): string {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  if (score >= 50) return 'E';
  return 'F';
}

function calculateRiskLevel(score: number, hblStatus: VulnStatus, critVulnStatuses: VulnStatus[], caps: GradeCap[]): RiskLevel {
  if (hblStatus === 'confirmed' || critVulnStatuses.some((s) => s === 'confirmed')) return 'Critique';
  if (caps.some((c) => c.grade === 'F')) return 'Critique';
  if (hblStatus === 'to_confirm' || critVulnStatuses.some((s) => s === 'to_confirm')) return 'Élevé';
  if (caps.some((c) => c.grade === 'C')) return 'Élevé';
  if (score < 60) return 'Élevé';
  if (score < 80 || caps.some((c) => c.grade === 'B')) return 'Moyen';
  return 'Faible';
}

export function calculateSourceConsensus(result: SslResultDto): { level: 'Fort' | 'Moyen' | 'Faible'; pct: number } {
  const multiSourceChecks: SourceValue[][] = [
    [result.heartbleed ?? undefined, result.sslyzeHeartbleed ?? undefined],
    [result.robot ?? undefined, result.sslyzeRobot ?? undefined],
    [result.crime ?? undefined, result.sslyzeCompression ?? undefined],
    [result.drown ?? undefined, result.ssllabsDrown ?? undefined],
  ];
  let agreeing = 0;
  let total = 0;
  for (const srcs of multiSourceChecks) {
    const tested = srcs.filter((s) => s === true || s === false);
    if (tested.length >= 2) {
      total++;
      if (tested.every((s) => s === tested[0])) agreeing++;
    }
  }
  if (total === 0) return { level: 'Faible', pct: 0 };
  const pct = agreeing / total;
  return { level: pct >= 0.8 ? 'Fort' : pct >= 0.55 ? 'Moyen' : 'Faible', pct: Math.round(pct * 100) };
}

function keyBits(result: SslResultDto): number {
  if (result.sslyzeStatus === 'READY' && result.sslyzeKeySize > 0) return result.sslyzeKeySize;
  const m = String(result.certKeySize ?? '').match(/(\d+)/);
  return m ? Number(m[1]) : 0;
}

function isRsaKey(result: SslResultDto): boolean {
  // Key type of the site's own key (not the CA signature algorithm). Unknown → treated as RSA.
  const alg = `${result.certificateDetail?.publicKeyAlgorithm ?? ''} ${result.certificateDetail?.keyType ?? ''}`.toUpperCase();
  return /RSA/.test(alg) || !/EC|ED25519|ED448/.test(alg);
}

/** Flaws that cap the grade, whatever the points. Exported for the tests and the page. */
export function computeGradeCaps(result: SslResultDto, hblStatus: VulnStatus): GradeCap[] {
  const caps: GradeCap[] = [];
  const sslyzeReady = result.sslyzeStatus === 'READY';
  const labsGrade = result.ssllabsStatus === 'READY' ? (result.ssllabsGrade ?? '') : '';

  const expired = !!result.certExpired
    || (sslyzeReady && result.sslyzeDaysLeft < 0)
    || result.certificateDetail?.validityStatus === 'EXPIRED';
  if (expired) {
    caps.push({ grade: 'F', reason: 'Certificat expiré : les navigateurs bloquent le site.',
      action: 'Renouveler le certificat, puis automatiser le renouvellement (certbot / ACME).' });
  }
  if ((sslyzeReady && !result.sslyzeChainTrusted) || labsGrade === 'T') {
    caps.push({ grade: 'F', reason: 'Certificat non reconnu par les navigateurs (auto-signé, autorité inconnue ou chaîne invalide).',
      action: 'Installer un certificat émis par une autorité reconnue (Let\'s Encrypt par exemple) avec sa chaîne complète.' });
  }
  if (result.certificateDetail?.hostnameMatch === 'MISMATCH' || labsGrade === 'M') {
    caps.push({ grade: 'F', reason: 'Le certificat ne correspond pas au nom du site.',
      action: 'Émettre un certificat qui couvre ce nom (champ SAN), ou corriger la configuration du serveur virtuel.' });
  }
  if (hblStatus === 'confirmed') {
    caps.push({ grade: 'F', reason: 'Heartbleed confirmé par deux outils.',
      action: 'Mettre à jour OpenSSL, redémarrer le service, puis remplacer le certificat et sa clé.' });
  }
  if (getVulnStatus([result.robot ?? undefined, result.sslyzeRobot ?? undefined]) === 'confirmed') {
    caps.push({ grade: 'F', reason: 'ROBOT confirmé par deux outils.', action: 'Désactiver les suites à échange de clé RSA (TLS_RSA_*).' });
  }
  if (getVulnStatus([result.drown ?? undefined, result.ssllabsDrown ?? undefined]) === 'confirmed') {
    caps.push({ grade: 'F', reason: 'DROWN confirmé par deux outils.', action: 'Désactiver SSL 2.0 partout où ce certificat est utilisé.' });
  }
  if (result.sslyzeCcsInjection) {
    caps.push({ grade: 'F', reason: 'Injection CCS (CVE-2014-0224) détectée par SSLyze.', action: 'Mettre à jour OpenSSL.' });
  }
  if (result.sslyzeSupportsSSL20) {
    caps.push({ grade: 'F', reason: 'SSL 2.0 est activé.', action: 'Désactiver SSL 2.0 (ssl_protocols TLSv1.2 TLSv1.3;).' });
  }
  const bits = keyBits(result);
  if (bits > 0 && bits < 1024 && isRsaKey(result)) {
    caps.push({ grade: 'F', reason: `Clé RSA de ${bits} bits, cassable.`, action: 'Générer une clé RSA de 2048 bits minimum (ou ECDSA P-256).' });
  }

  if (result.sslyzeSupportsSSL30 || result.poodle) {
    caps.push({ grade: 'C', reason: 'SSL 3.0 est activé (POODLE).', action: 'Désactiver SSL 3.0.' });
  }
  if (result.rc4) {
    caps.push({ grade: 'C', reason: 'Le chiffrement RC4 est accepté.', action: 'Retirer RC4 de la liste des suites.' });
  }
  const tls12 = result.tls12 || result.sslyzeSupportsTLS12;
  const tls13 = result.tls13 || result.sslyzeSupportsTLS13;
  if (sslyzeReady && !tls12 && !tls13) {
    caps.push({ grade: 'C', reason: 'Ni TLS 1.2 ni TLS 1.3 ne sont disponibles.', action: 'Activer TLS 1.2 et TLS 1.3.' });
  }

  if (result.tls10 || result.sslyzeSupportsTLS10 || result.tls11 || result.sslyzeSupportsTLS11) {
    caps.push({ grade: 'B', reason: 'TLS 1.0 ou TLS 1.1 est encore activé (obsolètes depuis 2021).',
      action: 'Limiter le serveur à TLS 1.2 et TLS 1.3.' });
  }
  if (result.has3des || result.sweet32 || result.ssllabsHas3des) {
    caps.push({ grade: 'B', reason: 'Le chiffrement 3DES est accepté (SWEET32).', action: 'Retirer les suites 3DES (DES-CBC3).' });
  }
  if (bits >= 1024 && bits < 2048 && isRsaKey(result)) {
    caps.push({ grade: 'B', reason: `Clé RSA de ${bits} bits (2048 minimum recommandé).`, action: 'Générer une clé RSA de 2048 bits minimum.' });
  }
  if (!sslyzeReady && result.scanStatus === 'COMPLETED' && result.chainComplete === false) {
    caps.push({ grade: 'B', reason: 'Chaîne de certificats incomplète (vérification Kali).',
      action: 'Servir le certificat intermédiaire avec le certificat du site (fullchain.pem).' });
  }
  if (result.ssllabsStatus === 'READY' && result.ssllabsForwardSecrecy === false && labsGrade !== '' && labsGrade !== '?') {
    caps.push({ grade: 'B', reason: 'Pas de confidentialité persistante (Forward Secrecy) pour tous les navigateurs, selon SSL Labs.',
      action: 'Privilégier les suites ECDHE.' });
  }
  if (!result.hsts) {
    caps.push({ grade: 'A', reason: 'Pas d\'en-tête HSTS : la note A+ demande HSTS.',
      action: 'Ajouter « Strict-Transport-Security: max-age=31536000; includeSubDomains ».' });
  }
  return caps;
}

export function computeScoreBreakdown(result: SslResultDto): ScoreBreakdown {
  const penalties: ScoreBreakdown['penalties'] = [];

  // ── TLS et protocoles — 25 pts (points gagnés)
  let tls = 0;
  if (result.tls13 || result.sslyzeSupportsTLS13) tls += 8;
  else penalties.push({ label: 'TLS 1.3 absent', points: 8, category: 'tls' });
  if (result.tls12 || result.sslyzeSupportsTLS12) tls += 5;
  else penalties.push({ label: 'TLS 1.2 absent', points: 5, category: 'tls' });
  if (!result.tls10 && !result.sslyzeSupportsTLS10) tls += 4;
  else penalties.push({ label: 'TLS 1.0 encore actif', points: 4, category: 'tls' });
  if (!result.tls11 && !result.sslyzeSupportsTLS11) tls += 4;
  else penalties.push({ label: 'TLS 1.1 encore actif', points: 4, category: 'tls' });
  if (!result.has3des && !result.rc4 && !result.ssllabsHas3des) tls += 4;
  else penalties.push({ label: 'Ciphers faibles actifs (3DES/RC4)', points: 4, category: 'tls' });
  tls = Math.min(25, Math.max(0, tls));

  // ── Certificat — 25 pts (points gagnés)
  let cert = 0;
  const expired = !!result.certExpired || (result.sslyzeStatus === 'READY' && result.sslyzeDaysLeft < 0);
  if (!expired) cert += 8;
  else penalties.push({ label: 'Certificat expiré', points: 8, category: 'certificate' });
  const trusted = result.sslyzeStatus === 'READY' ? result.sslyzeChainTrusted : result.chainComplete;
  if (trusted) cert += 5;
  else penalties.push({ label: 'Chaîne de confiance incomplète ou non reconnue', points: 5, category: 'certificate' });
  if (result.certificateDetail?.hostnameMatch !== 'MISMATCH') cert += 4;
  else penalties.push({ label: 'Nom du site absent du certificat', points: 4, category: 'certificate' });
  if (trusted) cert += 3;
  if (result.certDaysLeft > 30) cert += 3;
  else if (result.certDaysLeft >= 0)
    penalties.push({ label: `Certificat expire dans ${result.certDaysLeft}j`, points: 3, category: 'certificate' });
  // OCSP Stapling compte dans le certificat (plus dans les en-têtes HTTP)
  if (result.ocspStapling || result.sslyzeOcspStapling || result.certificateDetail?.ocspStaplingStatus === 'CONFORME') {
    cert += 2;
  } else {
    penalties.push({ label: 'OCSP Stapling non détecté', points: 2, category: 'certificate' });
  }
  cert = Math.min(25, Math.max(0, cert));

  // ── Vulnérabilités — 30 pts (déductions) — aligné sur la section vulnérabilités
  let vuln = 30;

  const hblSrcs: SourceValue[] = [result.heartbleed ?? undefined, result.sslyzeHeartbleed ?? undefined];
  const hblSt = getVulnStatus(hblSrcs);
  if (hblSt === 'confirmed') { vuln -= 12; penalties.push({ label: 'Heartbleed confirmé (≥2 sources)', points: 12, category: 'vulnerabilities' }); }
  else if (hblSt === 'to_confirm') { vuln -= 7; penalties.push({ label: 'Heartbleed à confirmer (1 source)', points: 7, category: 'vulnerabilities' }); }
  else if (hblSt === 'indeterminate') { vuln -= 2; penalties.push({ label: 'Heartbleed indéterminé (timeout/erreur)', points: 2, category: 'vulnerabilities' }); }

  if (result.poodle === true) { vuln -= 12; penalties.push({ label: 'POODLE confirmé (SSL 3.0 actif)', points: 12, category: 'vulnerabilities' }); }

  const drownSt = getVulnStatus([result.drown ?? undefined, result.ssllabsDrown ?? undefined]);
  if (drownSt === 'confirmed') { vuln -= 12; penalties.push({ label: 'DROWN confirmé', points: 12, category: 'vulnerabilities' }); }
  else if (drownSt === 'to_confirm') { vuln -= 7; penalties.push({ label: 'DROWN à confirmer', points: 7, category: 'vulnerabilities' }); }

  const robotSt = getVulnStatus([result.robot ?? undefined, result.sslyzeRobot ?? undefined]);
  if (robotSt === 'confirmed') { vuln -= 6; penalties.push({ label: 'ROBOT confirmé', points: 6, category: 'vulnerabilities' }); }
  else if (robotSt === 'to_confirm') { vuln -= 3; penalties.push({ label: 'ROBOT à confirmer', points: 3, category: 'vulnerabilities' }); }

  if (result.sweet32) { vuln -= 3; penalties.push({ label: 'SWEET32 détecté', points: 3, category: 'vulnerabilities' }); }
  const crimeSt = getVulnStatus([result.crime ?? undefined, result.sslyzeCompression ?? undefined]);
  if (crimeSt === 'confirmed' || crimeSt === 'to_confirm') { vuln -= 3; penalties.push({ label: 'CRIME détecté', points: 3, category: 'vulnerabilities' }); }
  if (result.beast) { vuln -= 1; penalties.push({ label: 'BEAST détecté', points: 1, category: 'vulnerabilities' }); }
  if (result.freak) { vuln -= 2; penalties.push({ label: 'FREAK détecté', points: 2, category: 'vulnerabilities' }); }
  if (result.logjam) { vuln -= 2; penalties.push({ label: 'Logjam détecté', points: 2, category: 'vulnerabilities' }); }
  if (result.rc4) { vuln -= 3; penalties.push({ label: 'RC4 détecté', points: 3, category: 'vulnerabilities' }); }
  if (result.has3des || result.ssllabsHas3des) { vuln -= 2; penalties.push({ label: 'Chiffrement 3DES accepté', points: 2, category: 'vulnerabilities' }); }
  vuln = Math.max(0, vuln);

  // ── En-têtes HTTP — 20 pts (protections principales uniquement ; pas OCSP / COOP / CORP / COEP)
  const headersScore = computeHttpHeadersCategoryScore(result);
  const headers = headersScore.score;
  penalties.push(...headersScore.penalties);

  const total = tls + cert + vuln + headers;
  const scoreGrade = getGrade(total);
  const allCaps = computeGradeCaps(result, hblSt);
  // Keep only caps that actually lower the grade, most severe first.
  const caps = allCaps
    .filter((c) => gradeRank(c.grade) > gradeRank(scoreGrade) || (c.grade === 'A' && scoreGrade === 'A+'))
    .sort((a, b) => gradeRank(b.grade) - gradeRank(a.grade));
  const grade = caps.length > 0 && gradeRank(caps[0].grade) > gradeRank(scoreGrade) ? caps[0].grade : scoreGrade;
  const consensus = calculateSourceConsensus(result);

  const sourcesUp = [result.sslyzeStatus, result.ssllabsStatus, result.censysStatus].filter((s) => s === 'READY').length;
  const confidence: ConfidenceLevel = sourcesUp >= 3 && consensus.level === 'Fort' ? 'Haute'
    : sourcesUp >= 2 ? 'Moyenne' : 'Faible';

  const riskLevel = calculateRiskLevel(total, hblSt, [getVulnStatus([result.poodle ?? undefined]), drownSt], allCaps);

  const flaws = [...allCaps].sort((a, b) => gradeRank(b.grade) - gradeRank(a.grade));
  return { tls, certificate: cert, vulnerabilities: vuln, headers, total, grade, scoreGrade, caps, flaws, riskLevel, confidence, consensus, hblStatus: hblSt, penalties };
}

export type TopRisk = { label: string; action: string; severity: 'critique' | 'haute' | 'moyenne' };

const CATEGORY_ACTION: Record<string, string> = {
  tls: 'Voir la section « Protocoles TLS » pour la configuration à appliquer.',
  certificate: 'Voir la section « Certificat » pour le détail.',
  vulnerabilities: 'Voir la section « Vulnérabilités » pour la correction.',
  headers: 'Voir la section « En-têtes de sécurité » : la ligne de configuration y est donnée.',
};

const SHARED_TOPICS = ['expiré', 'tls 1.0', 'tls 1.1', '3des', 'rc4', 'heartbleed', 'robot', 'drown', 'poodle',
  'ssl 3.0', 'chaîne', 'nom du site', 'hsts', 'sweet32'];

/**
 * The three things to fix first: the blocking flaws (expired certificate, 3DES, TLS 1.0…) even when the score alone
 * already gives a low grade, then the biggest lost points. HSTS alone (the A+ cap) is not blocking.
 */
export function topRisks(bd: ScoreBreakdown, limit = 3): TopRisk[] {
  const blocking = (bd.flaws ?? bd.caps).filter((c) => c.grade !== 'A');
  const out: TopRisk[] = blocking.map((c) => ({
    label: c.reason,
    action: c.action,
    severity: c.grade === 'F' ? 'critique' : c.grade === 'C' ? 'haute' : 'moyenne',
  }));
  const seen = new Set(out.map((r) => r.label));
  // A penalty about the same flaw as a cap would repeat it (cap "certificat expiré" + "Certificat expiré −8 pts").
  const capText = blocking.map((c) => c.reason.toLowerCase()).join(' ');
  const sameFlaw = (label: string) =>
    SHARED_TOPICS.some((t) => label.toLowerCase().includes(t) && capText.includes(t));
  [...bd.penalties]
    .sort((a, b) => b.points - a.points)
    .forEach((p) => {
      if (seen.has(p.label) || sameFlaw(p.label)) return;
      seen.add(p.label);
      out.push({ label: `${p.label} (−${p.points} pts)`, action: CATEGORY_ACTION[p.category], severity: p.points >= 7 ? 'haute' : 'moyenne' });
    });
  return out.slice(0, limit);
}
