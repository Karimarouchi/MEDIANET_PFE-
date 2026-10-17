import type { SslResultDto } from '../services/api';
import { computeScoreBreakdown, gradeRank } from './sslScore';

/**
 * What changed on an SSL target since its previous scan: new problems, fixed problems, and changes worth a look
 * even when they are not flaws (a certificate from another authority, a new key). Plain comparison rules, no model:
 * a sudden change of certificate authority is the classic sign of a misconfiguration or an interception.
 */
export type SslChangeKind = 'new' | 'fixed' | 'changed';

export type SslChange = {
  kind: SslChangeKind;
  area: 'Note' | 'Protocoles' | 'Vulnérabilités' | 'Certificat' | 'En-têtes';
  label: string;
  before?: string;
  after?: string;
  /** Changes that deserve a check even if nothing broke (issuer, key). */
  alert?: boolean;
};

export type SslDiff = {
  changes: SslChange[];
  newCount: number;
  fixedCount: number;
  changedCount: number;
};

const PROTOCOLS: Array<{ id: string; label: string; obsolete: boolean; on: (r: SslResultDto) => boolean }> = [
  { id: 'ssl20', label: 'SSL 2.0', obsolete: true, on: (r) => !!r.sslyzeSupportsSSL20 },
  { id: 'ssl30', label: 'SSL 3.0', obsolete: true, on: (r) => !!r.sslyzeSupportsSSL30 },
  { id: 'tls10', label: 'TLS 1.0', obsolete: true, on: (r) => !!(r.tls10 || r.sslyzeSupportsTLS10) },
  { id: 'tls11', label: 'TLS 1.1', obsolete: true, on: (r) => !!(r.tls11 || r.sslyzeSupportsTLS11) },
  { id: 'tls12', label: 'TLS 1.2', obsolete: false, on: (r) => !!(r.tls12 || r.sslyzeSupportsTLS12) },
  { id: 'tls13', label: 'TLS 1.3', obsolete: false, on: (r) => !!(r.tls13 || r.sslyzeSupportsTLS13) },
];

const FLAWS: Array<{ label: string; on: (r: SslResultDto) => boolean }> = [
  { label: 'Heartbleed', on: (r) => !!(r.heartbleed && r.sslyzeHeartbleed) },
  { label: 'POODLE', on: (r) => !!r.poodle },
  { label: 'ROBOT', on: (r) => !!(r.robot || r.sslyzeRobot) },
  { label: 'DROWN', on: (r) => !!(r.drown || r.ssllabsDrown) },
  { label: 'SWEET32 / 3DES', on: (r) => !!(r.sweet32 || r.has3des || r.ssllabsHas3des) },
  { label: 'CRIME (compression)', on: (r) => !!(r.crime || r.sslyzeCompression) },
  { label: 'RC4', on: (r) => !!r.rc4 },
  { label: 'FREAK', on: (r) => !!r.freak },
  { label: 'Logjam', on: (r) => !!r.logjam },
  { label: 'BEAST', on: (r) => !!r.beast },
  { label: 'Certificat expiré', on: (r) => !!r.certExpired || (r.sslyzeStatus === 'READY' && r.sslyzeDaysLeft < 0) },
  { label: 'Certificat non reconnu', on: (r) => r.sslyzeStatus === 'READY' && !r.sslyzeChainTrusted },
  { label: 'Nom du site absent du certificat', on: (r) => r.certificateDetail?.hostnameMatch === 'MISMATCH' },
];

const HEADERS: Array<{ label: string; on: (r: SslResultDto) => boolean }> = [
  { label: 'HSTS', on: (r) => !!r.hsts },
  { label: 'Content-Security-Policy', on: (r) => !!r.contentSecurityPolicy },
  { label: 'X-Frame-Options', on: (r) => !!r.xFrameOptions },
  { label: 'X-Content-Type-Options', on: (r) => !!r.xContentTypeOptions },
  { label: 'Referrer-Policy', on: (r) => !!r.referrerPolicy },
  { label: 'Permissions-Policy', on: (r) => !!r.permissionsPolicy },
];

function issuer(r: SslResultDto): string {
  const v = r.sslyzeCertIssuer || r.certIssuer || r.censysIssuer || '';
  return v === 'unknown' ? '' : v.trim();
}

/** Organisation of an issuer DN ("O=Let's Encrypt") or the whole string: renewals change the CN (R10 → R11), not the O. */
function issuerOrg(dn: string): string {
  const m = dn.match(/(?:^|[,/])\s*O\s*=\s*([^,/]+)/i);
  return (m ? m[1] : dn).trim().toLowerCase();
}

function keyDesc(r: SslResultDto): string {
  const d = r.certificateDetail;
  const size = d?.keySize || r.sslyzeKeySize || 0;
  const type = d?.keyType || d?.publicKeyAlgorithm || '';
  return size ? `${type ? `${type} ` : ''}${size} bits`.trim() : '';
}

export function compareSslResults(prev: SslResultDto, cur: SslResultDto): SslDiff {
  const changes: SslChange[] = [];

  const pg = computeScoreBreakdown(prev).grade;
  const cg = computeScoreBreakdown(cur).grade;
  if (pg !== cg) {
    const better = gradeRank(cg) < gradeRank(pg);
    changes.push({ kind: better ? 'fixed' : 'new', area: 'Note', label: better ? 'Note en hausse' : 'Note en baisse', before: pg, after: cg });
  }

  // Protocols only when SSLyze ran both times: Kali alone does not test SSL 2/3, so a missing source is not a change.
  const protoComparable = prev.sslyzeStatus === 'READY' && cur.sslyzeStatus === 'READY';
  for (const p of PROTOCOLS) {
    if (!protoComparable && (p.id === 'ssl20' || p.id === 'ssl30')) continue;
    const a = p.on(prev);
    const b = p.on(cur);
    if (a === b) continue;
    if (p.obsolete) {
      changes.push({ kind: b ? 'new' : 'fixed', area: 'Protocoles', label: `${p.label} ${b ? 'activé' : 'désactivé'}` });
    } else {
      changes.push({ kind: b ? 'fixed' : 'new', area: 'Protocoles', label: `${p.label} ${b ? 'activé' : 'n\'est plus disponible'}` });
    }
  }

  for (const f of FLAWS) {
    const a = f.on(prev);
    const b = f.on(cur);
    if (a !== b) changes.push({ kind: b ? 'new' : 'fixed', area: 'Vulnérabilités', label: f.label });
  }

  const pi = issuer(prev);
  const ci = issuer(cur);
  if (pi && ci && issuerOrg(pi) !== issuerOrg(ci)) {
    changes.push({ kind: 'changed', area: 'Certificat', label: 'Autorité de certification différente', before: pi, after: ci, alert: true });
  }
  const pSerial = prev.certificateDetail?.serialNumber || prev.certSerialNumber;
  const cSerial = cur.certificateDetail?.serialNumber || cur.certSerialNumber;
  if (pSerial && cSerial && pSerial !== 'unknown' && cSerial !== 'unknown' && pSerial !== cSerial) {
    changes.push({ kind: 'changed', area: 'Certificat', label: 'Nouveau certificat (renouvellement)', before: prev.certNotAfterStr || undefined, after: cur.certNotAfterStr || undefined });
  }
  const pk = keyDesc(prev);
  const ck = keyDesc(cur);
  if (pk && ck && pk !== ck) {
    changes.push({ kind: 'changed', area: 'Certificat', label: 'Type ou taille de clé différent', before: pk, after: ck, alert: true });
  }

  for (const h of HEADERS) {
    const a = h.on(prev);
    const b = h.on(cur);
    if (a !== b) changes.push({ kind: b ? 'fixed' : 'new', area: 'En-têtes', label: `${h.label} ${b ? 'ajouté' : 'disparu'}` });
  }

  return {
    changes,
    newCount: changes.filter((c) => c.kind === 'new').length,
    fixedCount: changes.filter((c) => c.kind === 'fixed').length,
    changedCount: changes.filter((c) => c.kind === 'changed').length,
  };
}
