import type { SslResultDto } from '../services/api';
import { computeScoreBreakdown, gradeRank } from './sslScore';
import { sslFindings } from './sslFindings';

export function gradeColor(g: string) {
  if (g === 'A+') return { ring: '#00fc92', text: '#00fc92', bg: 'rgba(0,252,146,.08)' };
  if (g === 'A')  return { ring: '#a4e6ff', text: '#a4e6ff', bg: 'rgba(164,230,255,.08)' };
  if (g === 'B')  return { ring: '#ffe066', text: '#ffe066', bg: 'rgba(255,224,102,.08)' };
  if (g === 'C')  return { ring: '#ffaa40', text: '#ffaa40', bg: 'rgba(255,170,64,.08)' };
  if (g === 'D')  return { ring: '#ff7b54', text: '#ff7b54', bg: 'rgba(255,123,84,.08)' };
  if (g === 'E')  return { ring: '#ff9580', text: '#ff9580', bg: 'rgba(255,149,128,.08)' };
  return           { ring: '#ffb4ab', text: '#ffb4ab', bg: 'rgba(255,180,171,.08)' };
}

/** SSL Labs grades on the verdict scale: A- counts as A, T (untrusted) and M (name mismatch) as F. */
export function labsOnVerdictScale(g: string): string {
  if (g === 'A-') return 'A';
  if (g === 'T' || g === 'M') return 'F';
  return g;
}

export type SourceGrade = { id: 'kali' | 'ssllabs' | 'sslyze' | 'censys'; name: string; grade: string; looksAt: string };

const usable = (g: string | null | undefined): g is string => !!g && g !== '?' && g !== 'N/A';

/** Grades of the tools that did their job on this scan; a tool that failed, timed out or had no data is left out. */
export function sourceGrades(r: SslResultDto): SourceGrade[] {
  const out: SourceGrade[] = [];
  if (r.scanStatus === 'COMPLETED' && usable(r.grade)) {
    out.push({ id: 'kali', name: 'Kali', grade: r.grade, looksAt: 'protocoles, failles, en-têtes' });
  }
  if (r.ssllabsStatus === 'READY' && usable(r.ssllabsGrade)) {
    out.push({ id: 'ssllabs', name: 'SSL Labs', grade: r.ssllabsGrade, looksAt: 'configuration TLS (référence publique)' });
  }
  if (r.sslyzeStatus === 'READY' && usable(r.sslyzeGrade)) {
    out.push({ id: 'sslyze', name: 'SSLyze', grade: r.sslyzeGrade, looksAt: 'protocoles et suites de chiffrement' });
  }
  if (r.censysStatus === 'READY' && usable(r.censysGrade)) {
    out.push({ id: 'censys', name: 'Censys', grade: r.censysGrade, looksAt: 'certificat vu depuis Internet' });
  }
  return out;
}

export type LabsComparison = {
  domain: string;
  vulnix: string;
  score: number;
  labs: string | null;
  /** Grade steps, positive when Vulnix is stricter than SSL Labs. */
  gap: number | null;
  verdict: 'same' | 'stricter' | 'lenient' | 'no_labs';
  reason: string;
};

/**
 * Vulnix's SSL/TLS verdict next to SSL Labs' grade, with the reason of a difference. Both grade the TLS
 * configuration (HSTS for A+); Vulnix grades the browser protection headers apart.
 */
export function compareWithLabs(r: SslResultDto): LabsComparison {
  const bd = computeScoreBreakdown(r);
  const labs = r.ssllabsStatus === 'READY' && usable(r.ssllabsGrade) ? r.ssllabsGrade : null;
  const base = { domain: r.domain, vulnix: bd.grade, score: bd.total, labs };
  if (!labs) return { ...base, gap: null, verdict: 'no_labs', reason: 'SSL Labs n’a pas donné de note pour ce scan.' };
  const gap = gradeRank(bd.grade) - gradeRank(labsOnVerdictScale(labs));
  if (gap === 0) return { ...base, gap, verdict: 'same', reason: 'Même note.' };
  // Browser protection headers are graded apart, so they never explain a gap on the SSL/TLS grade.
  const findings = sslFindings(r).findings.filter((f) => !f.id.startsWith('header_') || f.id === 'header_hsts');
  if (gap > 0) {
    const list = findings.slice(0, 3).map((f) => f.title);
    return { ...base, gap, verdict: 'stricter',
      reason: `Vulnix pénalise : ${list.join(', ') || 'voir le détail de la note'}.` };
  }
  const labsAt = r.ssllabsTestTime ? new Date(r.ssllabsTestTime).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' }) : null;
  if (bd.grade === 'A+' && labsOnVerdictScale(labs) === 'A') {
    return { ...base, gap, verdict: 'lenient',
      reason: `SSL Labs n’a pas vu de HSTS valable${labsAt ? ` lors de son test du ${labsAt}` : ''} alors que Vulnix le voit maintenant : relancer le scan pour une note SSL Labs à jour.` };
  }
  return { ...base, gap, verdict: 'lenient',
    reason: `SSL Labs applique une règle de plus${labsAt ? ` (test du ${labsAt})` : ''} : voir sa note dans les détails techniques.` };
}
