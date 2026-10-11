import React, { useState, useEffect, useRef } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import InfoHoverCard from '../components/InfoHoverCard';
import SecretsPanel from '../components/SecretsPanel';
import ScanLiveLog from '../components/ScanLiveLog';
import RemediationPlanView from '../components/RemediationPlanView';
import CodeFixView from '../components/CodeFixView';
import { parseLogLine, type LogEntry } from '../utils/scanLog';
import { effectiveVerdict } from '../utils/secretView';
import {
  PackageChecker, SupplyChainBanner, SupplyChainCell, ecosystemOfPurl, supplyChainKey, useSupplyChainReport,
} from '../components/SupplyChainPanel';
import {
  buildDependencyRows, countViews, defaultView, filterRows, reasonLine, severityRank, VIEW_HELP, type DepView,
} from '../utils/dependencyView';
import {
  getCvesByScan, getAllScans, requestFix, applyFix, getSecretsByScan, triageSecrets, setSecretVerdict, getSbomByScan,
  validateFixVersion, getCveJournalPolicy, getCveJournalRecommendation, getKevStatus,
  type CveDto, type ScanResultDto, type FixPreviewResponse, type SecretDto, type SbomComponent, type SupplyChainBrief, type SupplyChainItem,
  type VersionValidationResult, type CveVersionRecommendation, type CveJournalPolicy,
  apiUrl,
} from '../services/api';

const DEP_PAGE = 20;

/* ── helpers ── */


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
  if (score === null || score === undefined) return { bar: 'bg-slate-300', text: 'text-slate-400', label: 'Non disponible' };
  if (score >= 0.7) return { bar: 'bg-red-500', text: 'text-red-500', label: 'Très élevé' };
  if (score >= 0.3) return { bar: 'bg-orange-500', text: 'text-orange-500', label: 'Élevé' };
  if (score >= 0.05) return { bar: 'bg-yellow-500', text: 'text-yellow-600', label: 'Modéré' };
  return { bar: 'bg-slate-400', text: 'text-slate-400', label: 'Faible' };
}

/** CISA KEV = already exploited in the wild. Not the same as CVSS CRITICAL. */

function cvssBand(score: number | null | undefined): string {
  if (score == null) return 'inconnu';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

function sourceList(cve: CveDto): string[] {
  return `${cve.sources ?? ''},${cve.source ?? ''}`
    .split(/[,;]+/)
    .map(s => s.trim())
    .filter(Boolean)
    .filter((s, i, arr) => arr.findIndex(x => x.toUpperCase() === s.toUpperCase()) === i);
}

function parseMinNumber(raw: string): number | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const n = Number(trimmed.replace(',', '.'));
  return Number.isFinite(n) ? n : null;
}

function cveMatchesQuery(cve: CveDto, rawQuery: string): boolean {
  const q = rawQuery.trim().toLowerCase();
  if (!q) return true;
  const epssPct = cve.epssScore != null ? (cve.epssScore * 100).toFixed(2) : '';
  const haystack = [
    cve.cveId,
    cve.canonicalId,
    cve.aliases,
    cve.packageName,
    cve.packageVersion,
    cve.fixedVersion,
    cve.description,
    cve.severity,
    cve.source,
    cve.sources,
    cve.dataSource,
    cve.cweId,
    cve.target,
    cve.ecosystem,
    cve.packageManager,
    cve.purl,
    cve.moduleName,
    cve.manifestFile,
    cve.componentName,
    cve.componentVersion,
    cve.filePath,
    cve.dependencyPath,
    cve.dependencyScope,
    cve.directOrTransitive,
    cve.affectedOs,
    cve.priorityLabel,
    cve.cvssScore != null ? String(cve.cvssScore) : '',
    epssPct,
    epssPct ? epssPct + '%' : '',
    cve.kevListed ? 'kev cisa kev' : '',
    cve.exploitAvailable ? 'exploit' : '',
    cve.fixAvailable ? 'fix available correctif' : '',
  ].filter(Boolean).join(' ').toLowerCase();
  return haystack.indexOf(q) !== -1;
}

function isCodeWeakness(cve: CveDto): boolean {
  if (cve.findingKind === 'CODE_WEAKNESS') return true;
  if (cve.findingKind === 'DEPENDENCY' || cve.findingKind === 'DAST') return false;
  const src = `${cve.source ?? ''} ${cve.sources ?? ''}`.toLowerCase();
  return src.includes('semgrep') || (cve.cveId ?? '').startsWith('CWE-');
}

function formatAliases(cve: CveDto): string {
  const canonical = (cve.canonicalId || cve.cveId || '').toUpperCase();
  const parts = (cve.aliases ?? '')
    .split(/[,;]+/)
    .map(s => s.trim())
    .filter(Boolean)
    .filter(s => s.toUpperCase() !== canonical);
  const unique = parts.filter((s, i, arr) => arr.findIndex(x => x.toUpperCase() === s.toUpperCase()) === i);
  return unique.join(' · ');
}

function formatSources(sources?: string | null, fallback?: string | null): string {
  const parts = `${sources ?? ''},${fallback ?? ''}`
    .split(/[,;]+/)
    .map(s => s.trim())
    .filter(Boolean);
  const unique = parts
    .map(s => s.toUpperCase())
    .filter((s, i, arr) => arr.indexOf(s) === i);
  return unique.length > 0 ? unique.join(' · ') : '—';
}

function isDevOnly(cve: CveDto): boolean {
  const scope = (cve.dependencyScope ?? '').toLowerCase();
  return scope === 'dev' || scope === 'development' || scope === 'test';
}

type FindingType = 'CVE' | 'GHSA' | 'CWE' | 'CODE';

function inferGitProvider(repoUrl: string, provider?: string): 'GITHUB' | 'GITLAB' {
  if (provider === 'GITLAB' || repoUrl?.includes('gitlab.com')) {
    return 'GITLAB';
  }
  return 'GITHUB';
}

/**
 * Extract GitHub owner/repo or GitLab path_with_namespace.
 * GitLab uses the URL path slug (pfe-mediannet), never the display name (Pfe mediannet).
 * Subgroups are kept (group/sub/project). UI suffixes (/–/tree/...) are stripped.
 */
function extractRepoFullName(repoUrl: string, provider?: string): string | null {
  const gitProvider = inferGitProvider(repoUrl, provider);
  if (gitProvider === 'GITLAB') {
    return extractGitLabPathWithNamespace(repoUrl);
  }

  const httpsMatch = repoUrl?.match(/github\.com\/([^/]+\/[^/.]+?)(?:\.git)?(?:\/.*)?$/);
  if (httpsMatch) return httpsMatch[1];
  const sshMatch = repoUrl?.match(/git@github\.com:([^/]+\/[^/]+?)(?:\.git)?$/);
  if (sshMatch) return sshMatch[1];
  return null;
}

function extractGitLabPathWithNamespace(repoUrl: string): string | null {
  if (!repoUrl?.trim()) return null;
  const raw = repoUrl.trim();
  if (!/^https?:\/\//i.test(raw) && !raw.startsWith('git@')) {
    return stripGitLabWebSuffix(raw.replace(/\.git$/i, '').replace(/\/+$/, ''));
  }
  const sshMatch = raw.match(/^git@[^:]+:(.+)$/);
  if (sshMatch) {
    return stripGitLabWebSuffix(sshMatch[1].replace(/\.git$/i, '').replace(/\/+$/, ''));
  }
  try {
    const pathname = new URL(raw).pathname.replace(/^\/+/, '').replace(/\.git$/i, '');
    return stripGitLabWebSuffix(pathname) || null;
  } catch {
    return null;
  }
}

function stripGitLabWebSuffix(path: string): string {
  const cut = path.indexOf('/-/');
  const cleaned = (cut >= 0 ? path.slice(0, cut) : path).replace(/\/+$/, '');
  try {
    return decodeURIComponent(cleaned);
  } catch {
    return cleaned;
  }
}

type DiffLine = { type: 'unchanged' | 'removed' | 'added'; line: string; lineNo: number };

/** Extract a dependency version from pom.xml / package.json content. */
function extractVersionFromFixContent(content: string, packageName: string, filePath?: string | null): string | null {
  if (!content || !packageName) return null;
  const artifact = packageName.includes(':') ? packageName.split(':').pop()! : packageName;
  const file = (filePath || '').toLowerCase();

  if (file.endsWith('pom.xml') || content.includes('<artifactId>')) {
    // artifactId then version
    const re1 = new RegExp(
      `<artifactId>\\s*${artifact.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*</artifactId>[\\s\\S]{0,240}?<version>\\s*([^<\\s]+)\\s*</version>`,
      'gi'
    );
    let last: string | null = null;
    let m: RegExpExecArray | null;
    while ((m = re1.exec(content)) !== null) last = m[1].trim();
    if (last) return last;

    // version then artifactId
    const re2 = new RegExp(
      `<version>\\s*([^<\\s]+)\\s*</version>[\\s\\S]{0,240}?<artifactId>\\s*${artifact.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*</artifactId>`,
      'gi'
    );
    while ((m = re2.exec(content)) !== null) last = m[1].trim();
    if (last) return last;
  }

  const npmRe = new RegExp(`"${packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\s*:\\s*"\\^?~?([0-9][^"\\s]*)"`);
  const npmMatch = content.match(npmRe);
  if (npmMatch) return npmMatch[1];

  const ovRe = new RegExp(`"${artifact.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\s*:\\s*"\\^?~?([0-9][^"\\s]*)"`);
  const ovMatch = content.match(ovRe);
  if (ovMatch) return ovMatch[1];

  // Fallback: any newly typed version-looking token in added lines context
  const loose = content.match(/<version>\s*([0-9]+\.[0-9][^<\s]*)\s*<\/version>/g);
  if (loose && loose.length) {
    const lastTag = loose[loose.length - 1].match(/<version>\s*([0-9][^<\s]*)\s*<\/version>/);
    if (lastTag) return lastTag[1];
  }
  return null;
}

function compareSemverLike(a: string, b: string): number {
  const na = a.replace(/^[^0-9]*/, '').split(/[-+]/)[0];
  const nb = b.replace(/^[^0-9]*/, '').split(/[-+]/)[0];
  const pa = na.split('.').map((x) => parseInt(x.replace(/\D.*/, ''), 10) || 0);
  const pb = nb.split('.').map((x) => parseInt(x.replace(/\D.*/, ''), 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

function parseFixedVersionList(raw?: string | null): string[] {
  if (!raw) return [];
  return raw
    .split(/[,;|/]/)
    .map((v) => v.trim())
    .filter(Boolean)
    .map((v) => v.replace(/^[^\d]*/, '').trim())
    .filter((v) => /^\d/.test(v));
}

/** Prefer a fix on the same major(.minor) line as the installed version. */
function pickPreferredFixVersion(fixedVersions: string[], currentVersion?: string | null): string | null {
  if (!fixedVersions.length) return null;
  if (!currentVersion) {
    return [...fixedVersions].sort((a, b) => compareSemverLike(b, a))[0];
  }
  const cur = currentVersion.replace(/^[^\d]*/, '').split(/[-+]/)[0];
  const curParts = cur.split('.');
  const curMajor = curParts[0];
  const curMinor = curParts[1];

  const sameMajorMinor = fixedVersions.filter((v) => {
    const p = v.split('.');
    return p[0] === curMajor && p[1] === curMinor;
  });
  if (sameMajorMinor.length) {
    return [...sameMajorMinor].sort((a, b) => compareSemverLike(b, a))[0];
  }
  const sameMajor = fixedVersions.filter((v) => v.split('.')[0] === curMajor);
  if (sameMajor.length) {
    return [...sameMajor].sort((a, b) => compareSemverLike(b, a))[0];
  }
  // Fallback: closest listed fix (often another major line, e.g. 11.0.8 while on 10.1.x)
  return [...fixedVersions].sort((a, b) => compareSemverLike(b, a))[0];
}

function buildLocalVersionCheck(
  packageName: string,
  chosen: string | null,
  recommended: string | null,
  current: string | null,
  cveId?: string | null,
  fixedInList: string[] = [],
  officialChefVersion: string | null = null,
): VersionValidationResult {
  const fixedIn = fixedInList.length
    ? fixedInList
    : (recommended ? [recommended] : []);

  if (!chosen) {
    return {
      packageName,
      cveId: cveId ?? undefined,
      chosenVersion: chosen,
      recommendedVersion: officialChefVersion || recommended,
      currentVersion: current,
      verdict: 'UNKNOWN',
      riskLevel: 'MEDIUM',
      title: 'Version choisie non détectée',
      summary: 'Impossible de lire la version dans le diff. Vérifiez la balise version avant de continuer.',
      details: [
        officialChefVersion ? `Version chef (politique) : ${officialChefVersion}` : '',
        fixedIn.length ? `Versions Fixed In pour ce CVE : ${fixedIn.join(', ')}` : 'Aucune version Fixed In disponible.',
      ].filter(Boolean),
      advice: (officialChefVersion || recommended)
        ? `Indiquez une version explicite (politique : ${officialChefVersion || recommended}).`
        : 'Indiquez une version explicite.',
      canProceed: true,
      source: 'LOCAL',
    };
  }

  const chosenNorm = chosen.replace(/^[^\d]*/, '').trim();
  const chefNorm = officialChefVersion
    ? officialChefVersion.replace(/^[^\d]*/, '').trim()
    : null;

  // Sprint A: deviation from chef policy is always highlighted
  if (chefNorm && compareSemverLike(chefNorm, chosenNorm) !== 0 && chefNorm !== chosenNorm) {
    return {
      packageName,
      cveId: cveId ?? undefined,
      chosenVersion: chosenNorm,
      recommendedVersion: chefNorm,
      currentVersion: current,
      verdict: 'RISKY',
      riskLevel: 'HIGH',
      title: 'Écart avec la politique chef',
      summary: `La version choisie (${chosenNorm}) diffère de la version stable officielle du chef (${chefNorm}).`,
      details: [
        `Version chef (politique) : ${chefNorm}`,
        `Version choisie : ${chosenNorm}`,
        fixedIn.length ? `Fixed In (scan) : ${fixedIn.join(', ')}` : '',
      ].filter(Boolean),
      advice: `Préférez ${chefNorm} sauf raison métier forte (motif obligatoire).`,
      canProceed: true,
      source: 'LOCAL',
    };
  }

  const inFixedList = fixedIn.some((v) => compareSemverLike(v, chosenNorm) === 0
    || v === chosenNorm
    || v.startsWith(chosenNorm + '.')
    || chosenNorm.startsWith(v + '.'));

  // Exact match (or equivalent) with a Fixed In version for THIS CVE → OK
  if (inFixedList || fixedIn.some((v) => v === chosenNorm) || (chefNorm && chefNorm === chosenNorm)) {
    const sameLine = recommended && chosenNorm.split('.')[0] === recommended.split('.')[0]
      && chosenNorm.split('.')[1] === recommended.split('.')[1];
    return {
      packageName,
      cveId: cveId ?? undefined,
      chosenVersion: chosenNorm,
      recommendedVersion: officialChefVersion || recommended,
      currentVersion: current,
      verdict: 'OK',
      riskLevel: chefNorm || sameLine || !recommended ? 'LOW' : 'MEDIUM',
      title: chefNorm ? 'Version conforme à la politique chef' : 'Version acceptée (listée Fixed In)',
      summary: chefNorm
        ? `La version ${chosenNorm} respecte la politique du chef.`
        : (`La version ${chosenNorm} figure dans les versions de correction de ce CVE`
          + (recommended && chosenNorm !== recommended
            ? ` (version idéale pour votre branche actuelle : ${recommended}).`
            : '.')),
      details: [
        `Version choisie : ${chosenNorm}`,
        chefNorm ? `Version chef : ${chefNorm}` : '',
        `Versions Fixed In (CVE) : ${fixedIn.join(', ') || '—'}`,
        !chefNorm && recommended ? `Idéale pour ${current || 'votre branche'} : ${recommended}` : '',
      ].filter(Boolean),
      advice: 'Vous pouvez continuer.',
      canProceed: true,
      source: 'LOCAL',
    };
  }

  if (current && compareSemverLike(chosenNorm, current) <= 0) {
    return {
      packageName,
      cveId: cveId ?? undefined,
      chosenVersion: chosenNorm,
      recommendedVersion: officialChefVersion || recommended,
      currentVersion: current,
      verdict: 'RISKY',
      riskLevel: 'HIGH',
      title: 'Attention : version trop basse',
      summary: `La version choisie (${chosenNorm}) n'est pas supérieure à la version vulnérable (${current}).`,
      details: [
        chefNorm ? `Version chef : ${chefNorm}` : '',
        `Versions Fixed In : ${fixedIn.join(', ') || '—'}`,
        recommended ? `Idéale pour votre branche : ${recommended}` : '',
      ].filter(Boolean),
      advice: (officialChefVersion || recommended)
        ? `Utilisez ${officialChefVersion || recommended}.`
        : `Choisissez une des versions Fixed In.`,
      canProceed: true,
      source: 'LOCAL',
    };
  }

  // Same major.minor line as preferred, but lower than preferred → RISKY
  if (recommended && compareSemverLike(chosenNorm, recommended) < 0
    && chosenNorm.split('.')[0] === recommended.split('.')[0]
    && chosenNorm.split('.')[1] === recommended.split('.')[1]) {
    return {
      packageName,
      cveId: cveId ?? undefined,
      chosenVersion: chosenNorm,
      recommendedVersion: officialChefVersion || recommended,
      currentVersion: current,
      verdict: 'RISKY',
      riskLevel: 'HIGH',
      title: 'Attention : version potentiellement risquée',
      summary: `Sur la branche ${recommended.split('.').slice(0, 2).join('.')}.x, la version idéale est ${recommended}. ${chosenNorm} est plus basse.`,
      details: [
        `Version choisie : ${chosenNorm}`,
        chefNorm ? `Version chef : ${chefNorm}` : '',
        `Versions Fixed In : ${fixedIn.join(', ')}`,
        `Idéale (même branche) : ${recommended}`,
      ].filter(Boolean),
      advice: `Préférez ${officialChefVersion || recommended}.`,
      canProceed: true,
      source: 'LOCAL',
    };
  }

  // Chosen not in list — warn but don't invent a fake ideal from other CVEs
  return {
    packageName,
    cveId: cveId ?? undefined,
    chosenVersion: chosenNorm,
    recommendedVersion: officialChefVersion || recommended,
    currentVersion: current,
    verdict: 'UNKNOWN',
    riskLevel: 'MEDIUM',
    title: 'Version hors liste Fixed In',
    summary: `La version ${chosenNorm} n'est pas dans la liste Fixed In de ce CVE`
      + (fixedIn.length ? ` (${fixedIn.join(', ')})` : '')
      + '. Vérifiez qu\'elle corrige bien la faille.',
    details: [
      `Version choisie : ${chosenNorm}`,
      chefNorm ? `Version chef : ${chefNorm}` : '',
      fixedIn.length ? `Versions Fixed In : ${fixedIn.join(', ')}` : 'Pas de Fixed In.',
      recommended ? `Idéale pour votre branche : ${recommended}` : '',
    ].filter(Boolean),
    advice: (officialChefVersion || recommended)
      ? `En cas de doute, utilisez ${officialChefVersion || recommended}.`
      : 'Choisissez une version de la liste Fixed In.',
    canProceed: true,
    source: 'LOCAL',
  };
}

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
function findingType(cve: { cveId: string; source: string; findingKind?: string | null }): FindingType {
  if (cve.findingKind === 'CODE_WEAKNESS') return 'CODE';
  // npm-audit / OSV advisories have ids such as NSWG-ECO-101: they are still dependency vulnerabilities, not code
  if (cve.findingKind === 'DEPENDENCY' && !cve.cveId?.startsWith('CWE-')) return cve.cveId?.startsWith('GHSA-') ? 'GHSA' : 'CVE';
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

/* ── component ── */

const Vulnerabilities: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const scanIdParam = searchParams.get('scanId');

  const [allScans, setAllScans] = useState<ScanResultDto[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(scanIdParam ? Number(scanIdParam) : null);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [scanClientFilter, setScanClientFilter] = useState('ALL');
  const [activeTab, setActiveTab] = useState<'cve' | 'code' | 'sbom' | 'evolution'>('cve');
  // Supply-chain screening (npm / PyPI) shares the Dépendances tab with the SBOM: one table, one risk banner
  const supply = useSupplyChainReport(selectedScanId, true);

  const [cves, setCves] = useState<CveDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  // usage filter: does the project's own code import the vulnerable package?
  const [usageFilter, setUsageFilter] = useState<'ALL' | 'YES' | 'NOT_IMPORTED'>('ALL');
  const [cvssMin, setCvssMin] = useState('');
  const [epssMin, setEpssMin] = useState('');
  const [kevCatalogSize, setKevCatalogSize] = useState<number | null>(null);
  const [selected, setSelected] = useState<CveDto | null>(null);

  const [secrets, setSecrets] = useState<SecretDto[]>([]);
  const [secretsLoading, setSecretsLoading] = useState(false);
  const [secretsTriaging, setSecretsTriaging] = useState(false);
  // probable false positives are not counted in the tab badge
  const openSecrets = secrets.filter(s => effectiveVerdict(s) !== 'LIKELY_FALSE_POSITIVE'
    && !(s.mlScope === 'TEST_OR_DOC' && s.analystVerdict !== 'REAL'));

  const [sbomComponents, setSbomComponents] = useState<SbomComponent[]>([]);
  const [sbomLoading, setSbomLoading] = useState(false);
  const [sbomSearch, setSbomSearch] = useState('');
  const [sbomFilter, setSbomFilter] = useState<DepView | null>(null); // null = ouvre sur la vue la plus utile (urgent d'abord)
  const [sbomLimit, setSbomLimit] = useState(DEP_PAGE);
  const [sbomEcosystem, setSbomEcosystem] = useState('');
  const [sbomSelectedPkg, setSbomSelectedPkg] = useState<SbomComponent | null>(null);


  // Live logs state
  const [logs, setLogs] = useState<LogEntry[]>([]);
  // the backend sent the completion marker (models finished): keep the 100 % view a moment, then open the results
  const [finishing, setFinishing] = useState(false);
  const finishingRef = useRef(false);
  const [scanRunning, setScanRunning] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const currentStatusRef = useRef<string | null>(null);

  // Auto-fix state
  const [fixLoading, setFixLoading] = useState(false);
  const [fixError, setFixError] = useState<string | null>(null);
  const [fixPreview, setFixPreview] = useState<(FixPreviewResponse & { repoFullName: string }) | null>(null);
  const [applyLoading, setApplyLoading] = useState(false);
  const [applySuccess, setApplySuccess] = useState<string | null>(null);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [fixedCveIds, setFixedCveIds] = useState<Set<number>>(new Set());

  // Assisted-fix agent: AI vs human knowledge choice
  const [fixChoice, setFixChoice] = useState<'AI' | 'HUMAN'>('AI');
  const [fixReason, setFixReason] = useState('');
  const [showReasonModal, setShowReasonModal] = useState(false);
  const [memorizeFix, setMemorizeFix] = useState(true);
  const [knowledgeSavedNote, setKnowledgeSavedNote] = useState(false);
  const [showVersionCheckModal, setShowVersionCheckModal] = useState(false);
  const [versionCheck, setVersionCheck] = useState<VersionValidationResult | null>(null);
  const [versionCheckLoading, setVersionCheckLoading] = useState(false);
  const [pendingRiskAccepted, setPendingRiskAccepted] = useState(false);
  const [chefPolicyVersion, setChefPolicyVersion] = useState<string | null>(null);
  const [chefPolicyMeta, setChefPolicyMeta] = useState<CveJournalPolicy | null>(null);
  const [journalRecommendation, setJournalRecommendation] = useState<CveVersionRecommendation | null>(null);
  const [journalRecLoading, setJournalRecLoading] = useState(false);

  // Inline edit state — lets the user override the AI's suggested fix in the diff modal
  const [fixLineEdits, setFixLineEdits] = useState<Record<number, string>>({});      // edited text of added lines (diff index → text)
  const [fixDeletedAdds, setFixDeletedAdds] = useState<Set<number>>(new Set());        // added lines the user dropped
  const [fixRestoredRemovals, setFixRestoredRemovals] = useState<Set<number>>(new Set()); // removed lines the user kept
  const fixHasEdits =
    Object.keys(fixLineEdits).length > 0 || fixDeletedAdds.size > 0 || fixRestoredRemovals.size > 0;

  const activeFixedLines = React.useMemo(() => {
    if (!fixPreview) return [] as string[];
    if (fixChoice === 'HUMAN' && fixPreview.humanFixedLines?.length) {
      return fixPreview.humanFixedLines;
    }
    return fixPreview.fixedLines;
  }, [fixPreview, fixChoice]);

  const activeFixedContent = React.useMemo(() => {
    if (!fixPreview) return '';
    if (fixChoice === 'HUMAN' && fixPreview.humanFixedContent != null) {
      return fixPreview.humanFixedContent;
    }
    return fixPreview.fixedContent;
  }, [fixPreview, fixChoice]);

  // Rebuild the fixed file content from the (possibly edited) diff.
  // When the user hasn't touched anything we keep the backend content verbatim
  // to preserve exact formatting / trailing newlines.
  const buildEditedFixedContent = (): string => {
    if (!fixPreview) return '';
    const diff = computeDiff(fixPreview.originalLines, activeFixedLines);
    const lines: string[] = [];
    diff.forEach((entry, idx) => {
      if (entry.type === 'removed') {
        if (fixRestoredRemovals.has(idx)) lines.push(entry.line);
        return;
      }
      if (entry.type === 'added') {
        if (fixDeletedAdds.has(idx)) return;
        lines.push(fixLineEdits[idx] ?? entry.line);
        return;
      }
      lines.push(entry.line);
    });
    return lines.join('\n');
  };

  const selectFixChoice = (choice: 'AI' | 'HUMAN') => {
    setFixChoice(choice);
    setFixLineEdits({});
    setFixDeletedAdds(new Set());
    setFixRestoredRemovals(new Set());
  };

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
    getKevStatus()
      .then(r => setKevCatalogSize(r.data.catalogSize ?? 0))
      .catch(() => setKevCatalogSize(null));
    return () => clearInterval(interval);
  }, []);

  // When scanId param changes, update selection
  useEffect(() => {
    if (scanIdParam) setSelectedScanId(Number(scanIdParam));
  }, [scanIdParam]);

  // Journal CVE — politique chef + recommandation IA pour le CVE sélectionné
  useEffect(() => {
    let cancelled = false;
    const loadJournalContext = async () => {
      if (!selected?.cveId) {
        setChefPolicyVersion(null);
        setChefPolicyMeta(null);
        setJournalRecommendation(null);
        return;
      }
      setJournalRecLoading(true);
      try {
        const [policyRes, recRes] = await Promise.all([
          getCveJournalPolicy(selected.cveId, selected.packageName).catch(() => null),
          getCveJournalRecommendation({
            cveId: selected.cveId,
            packageName: selected.packageName,
            fixedVersion: selected.fixedVersion,
            severity: selected.severity,
            description: selected.description,
            ecosystem: selected.ecosystem,
          }).catch(() => null),
        ]);
        if (cancelled) return;
        const official = policyRes?.data?.officialStableVersion ?? null;
        setChefPolicyVersion(official);
        setChefPolicyMeta(policyRes?.data ?? null);
        setJournalRecommendation(recRes?.data ?? null);
      } catch {
        if (!cancelled) {
          setChefPolicyVersion(null);
          setChefPolicyMeta(null);
          setJournalRecommendation(null);
        }
      } finally {
        if (!cancelled) setJournalRecLoading(false);
      }
    };
    void loadJournalContext();
    return () => { cancelled = true; };
  }, [selected?.cveId, selected?.packageName, selected?.fixedVersion, selected?.severity, selected?.description, selected?.ecosystem]);

  // Detect status change for selected scan and trigger load only when needed
  const selectedScanStatus = currentScan?.status || null;

  // Derived flag: show logs when scan is running OR status not yet known
  const showLogs = finishing || scanRunning || selectedScanStatus === 'RUNNING' || (selectedScanId != null && !selectedScanStatus);

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

      const evtSource = new EventSource(
        apiUrl(`/api/scans/${selectedScanId}/logs`),
        { withCredentials: true },
      );
      eventSourceRef.current = evtSource;

      evtSource.onmessage = (event) => {
        const raw = event.data;
        if (raw === '%%SCAN_COMPLETE%%') {
          evtSource.close();
          eventSourceRef.current = null;
          currentStatusRef.current = null; // force reload on next poll
          loadCves(selectedScanId);
          loadSecrets(selectedScanId);
          loadSbom(selectedScanId);
          // 100 % shown for a moment, then the results open (supply-chain and secret-triage models are done by now)
          finishingRef.current = true;
          setFinishing(true);
          window.setTimeout(() => {
            finishingRef.current = false;
            setFinishing(false);
            setScanRunning(false);
          }, 2500);
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
        loadSbom(selectedScanId);
      };
    } else if (selectedScanStatus === 'COMPLETED' || selectedScanStatus === 'FAILED') {
      setScanRunning(false);
      if (!finishingRef.current) setLogs([]);
      loadCves(selectedScanId);
      loadSecrets(selectedScanId);
      loadSbom(selectedScanId);
    }

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [selectedScanId, selectedScanStatus]);

  // Reload SBOM when user switches to sbom tab and data is missing
  useEffect(() => {
    if (activeTab === 'sbom' && selectedScanId && sbomComponents.length === 0 && !sbomLoading) {
      loadSbom(selectedScanId);
    }
  }, [activeTab, sbomComponents.length, sbomLoading, selectedScanId]);


  const loadCves = async (scanId: number) => {
    setLoading(true);
    try {
      const res = await getCvesByScan(scanId);
      setCves(res.data);
      if (res.data.length > 0) setSelected(res.data[0]);
      else setSelected(null);
    } catch (err) {
      console.error('Failed to fetch CVEs', err);
      setCves([]);
    } finally {
      setLoading(false);
    }
  };

  const handleTriageSecrets = async () => {
    if (selectedScanId == null) return;
    setSecretsTriaging(true);
    try {
      const res = await triageSecrets(selectedScanId);
      setSecrets(res.data);
    } catch (err) {
      console.error('Secret triage failed', err);
    } finally {
      setSecretsTriaging(false);
    }
  };

  const handleSecretVerdict = async (secretId: number, verdict: 'REAL' | 'FALSE_POSITIVE' | null) => {
    try {
      const res = await setSecretVerdict(secretId, verdict);
      setSecrets(prev => prev.map(x => (x.id === secretId ? res.data : x)));
    } catch (err) {
      console.error('Cannot save the verdict', err);
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
    setApplyError(null);
    setFixPreview(null);
    setApplySuccess(null);
    setFixLineEdits({});
    setFixDeletedAdds(new Set());
    setFixRestoredRemovals(new Set());
    setFixChoice('AI');
    setFixReason('');
    setShowReasonModal(false);
    setKnowledgeSavedNote(false);
    setMemorizeFix(true);
    setShowVersionCheckModal(false);
    setVersionCheck(null);
    try {
      // Sprint A: chef policy > same-branch Fixed In
      const thisCveFixed = parseFixedVersionList(cve.fixedVersion);
      let fixedVer = pickPreferredFixVersion(thisCveFixed, cve.packageVersion) || '';
      let chefVersion: string | null = null;
      try {
        if (cve.cveId) {
          const policy = await getCveJournalPolicy(cve.cveId, cve.packageName);
          if (policy.data.officialStableVersion) {
            chefVersion = policy.data.officialStableVersion;
            fixedVer = chefVersion;
          }
        }
      } catch {
        // policy endpoint optional — fall back to scan Fixed In
      }
      setChefPolicyVersion(chefVersion);
      if (!fixedVer) {
        const grpKey = cve.packageName && cve.fixedVersion
          ? `${cve.packageName}|${cve.packageVersion ?? ''}|${cve.filePath ?? ''}`
          : null;
        const group = grpKey ? (fixGroups.get(grpKey) ?? [cve]) : [cve];
        fixedVer = pickPreferredFixVersion(
          group.flatMap(c => parseFixedVersionList(c.fixedVersion)),
          cve.packageVersion,
        ) || '';
      }

      // Pass filePath hint and branch to backend — it will use GitHub Tree API to auto-discover the actual path
      const res = await requestFix({
        repoFullName,
        packageName: cve.packageName,
        currentVersion: cve.packageVersion,
        fixedVersion: fixedVer,
        cveId: cve.cveId,
        filePath: cve.filePath,
        source: cve.source,
        provider,
        branch: currentScan?.branch ?? null,
      });
      setFixPreview({ ...res.data, repoFullName });
      // Auto-select human knowledge if the agent recommends it
      if (res.data.hasHumanKnowledge && res.data.llmAdvice?.recommendation === 'HUMAN') {
        setFixChoice('HUMAN');
      } else {
        setFixChoice('AI');
      }
    } catch (err: any) {
      let msg = err?.response?.data?.error || err?.message || 'Erreur lors de la génération du correctif.';
      setFixError(msg);
    } finally {
      setFixLoading(false);
    }
  };

  const doApplyFix = async (reasonOverride?: string, riskAccepted = false) => {
    if (!fixPreview || !selected) return;
    setApplyLoading(true);
    setApplyError(null);
    try {
      const provider = currentScan ? inferGitProvider(currentScan.repoUrl, currentScan.gitProvider) : 'GITHUB';
      const grpKey = selected.packageName && selected.fixedVersion
        ? `${selected.packageName}|${selected.packageVersion ?? ''}|${selected.filePath ?? ''}`
        : null;
      const grp = grpKey ? (fixGroups.get(grpKey) ?? [selected]) : [selected];
      // Prefer chef policy version when available
      let preferredFix = chefPolicyVersion
        || fixPreview.officialStableVersion
        || pickPreferredFixVersion(
          parseFixedVersionList(selected.fixedVersion),
          selected.packageVersion,
        )
        || pickPreferredFixVersion(
          grp.flatMap(c => parseFixedVersionList(c.fixedVersion)),
          selected.packageVersion,
        )
        || selected.fixedVersion || '';
      // If developer edited content, prefer extracted chosen version for commit message / audit
      const finalContent = fixHasEdits ? buildEditedFixedContent() : activeFixedContent;
      const extracted = extractVersionFromFixContent(finalContent, selected.packageName, fixPreview.filePath);
      if (extracted) preferredFix = extracted;

      const cveLabel = grp.length > 1
        ? grp.map(c => c.cveId).filter(Boolean).join(', ')
        : (selected.cveId ?? '');

      const chosenSource = fixChoice;
      const reason = (reasonOverride ?? fixReason).trim();
      const isHumanReuse = fixChoice === 'HUMAN' && !!fixPreview.humanKnowledge && !fixHasEdits;
      const contentChanged = !isHumanReuse && finalContent !== (fixPreview.fixedContent ?? '');
      const shouldMemorize = !isHumanReuse && (memorizeFix || fixHasEdits || contentChanged);

      const res = await applyFix({
        repoFullName: fixPreview.repoFullName,
        filePath: fixPreview.filePath,
        sha: fixPreview.sha,
        fixedContent: finalContent,
        commitMessage: `fix: patch ${cveLabel} — update ${selected.packageName} to ${preferredFix} (par développeur)`,
        provider,
        branch: currentScan?.branch ?? null,
        lockFilePath: fixPreview.lockFilePath ?? null,
        lockFileSha: fixPreview.lockFileSha ?? null,
        lockFileContent: fixPreview.lockFileContent ?? null,
        developerEdited: fixHasEdits || contentChanged,
        memorize: shouldMemorize,
        reason: reason || null,
        chosenSource,
        knowledgeId: fixPreview.humanKnowledge?.id ?? null,
        aiFixedContent: fixPreview.fixedContent,
        packageName: selected.packageName,
        currentVersion: selected.packageVersion,
        fixedVersion: preferredFix || selected.fixedVersion,
        cveId: selected.cveId,
        source: selected.source,
        riskAccepted: riskAccepted || pendingRiskAccepted,
      });

      // Écart politique : pas de commit — en attente validation chef
      if (res.data.status === 'PENDING_APPROVAL') {
        setShowReasonModal(false);
        setFixReason('');
        setPendingRiskAccepted(false);
        setFixPreview(null);
        setApplySuccess(
          res.data.message
          || `Demande envoyée aux chefs. Le commit partira automatiquement au nom de ${
              res.data.requestedByLogin || 'vous'
            } si un chef accepte.`,
        );
        return;
      }

      setApplySuccess(res.data.commitUrl || 'Commit appliqué avec succès.');
      setKnowledgeSavedNote(!!res.data.knowledgeSaved);
      setShowReasonModal(false);
      setFixReason('');
      setPendingRiskAccepted(false);
      setFixedCveIds(prev => {
        const next = new Set(prev);
        grp.forEach(c => { if (c.id != null) next.add(c.id); });
        return next;
      });
    } catch (err: any) {
      const raw = err?.response?.data;
      const msg =
        (typeof raw === 'string' ? raw : raw?.message || raw?.error)
        || err?.message
        || 'Erreur lors de l\'application du correctif.';
      const friendly = /value too long|varchar\s*\(\s*512\s*\)|character varying\(512\)/i.test(String(msg))
        ? 'Impossible d’envoyer la dérogation : le contenu du fichier correctif dépasse la limite DB. Redémarrez le backend (migration auto), puis réessayez avec le même motif.'
        : String(msg);
      setApplyError(friendly);
      setFixError(friendly);
    } finally {
      setApplyLoading(false);
    }
  };

  const handleApplyFix = async () => {
    if (!fixPreview || !selected) return;
    const finalContent = fixHasEdits ? buildEditedFixedContent() : activeFixedContent;
    const isHumanReuse = fixChoice === 'HUMAN' && !!fixPreview.humanKnowledge && !fixHasEdits;
    const contentChanged = !isHumanReuse && finalContent !== (fixPreview.fixedContent ?? '');
    const shouldMemorize = !isHumanReuse && (memorizeFix || fixHasEdits || contentChanged);

    // Always detect écart vs politique chef (même sans édition manuelle)
    let chefVersion = chefPolicyVersion || fixPreview.officialStableVersion || null;
    if (!chefVersion && selected.cveId) {
      try {
        const policy = await getCveJournalPolicy(selected.cveId, selected.packageName);
        chefVersion = policy.data.officialStableVersion ?? null;
        if (chefVersion) {
          setChefPolicyVersion(chefVersion);
          setChefPolicyMeta(policy.data);
        }
      } catch { /* ignore */ }
    }
    const extractedChosen =
      extractVersionFromFixContent(finalContent, selected.packageName, fixPreview.filePath)
      || Object.values(fixLineEdits).map(l => {
        const vm = l.match(/([0-9]+\.[0-9]+[0-9A-Za-z.\-]*)/);
        return vm ? vm[1] : null;
      }).find(Boolean)
      || null;

    const versionsDiffer = (a: string | null | undefined, b: string | null | undefined) => {
      if (!a || !b) return false;
      const na = a.replace(/^[^0-9]*/, '').trim().toLowerCase();
      const nb = b.replace(/^[^0-9]*/, '').trim().toLowerCase();
      return !!na && na !== nb;
    };

    const policyDeviation = !!(chefVersion && extractedChosen && versionsDiffer(chefVersion, extractedChosen));

    // Warning card avant de continuer : écart chef OU contenu modifié
    if (policyDeviation || fixHasEdits || contentChanged) {
      const fixedIn = parseFixedVersionList(selected.fixedVersion);
      const scanRecommended = pickPreferredFixVersion(fixedIn, selected.packageVersion);
      const recommended = chefVersion || scanRecommended;
      const chosen = extractedChosen;

      const localCheck = buildLocalVersionCheck(
        selected.packageName,
        chosen,
        scanRecommended,
        selected.packageVersion ?? null,
        selected.cveId,
        fixedIn,
        chefVersion,
      );

      setVersionCheckLoading(true);
      setApplyError(null);
      try {
        const res = await validateFixVersion({
          packageName: selected.packageName,
          currentVersion: selected.packageVersion,
          recommendedVersion: recommended,
          chosenVersion: chosen,
          cveId: selected.cveId,
          ecosystem: selected.ecosystem ?? selected.source,
          filePath: fixPreview.filePath,
          fixedContent: finalContent,
        });
        const mergedVerdict = localCheck.verdict === 'OK'
          ? 'OK'
          : (localCheck.verdict === 'RISKY' ? 'RISKY' : (res.data.verdict || localCheck.verdict));
        setVersionCheck({
          ...res.data,
          ...localCheck,
          verdict: mergedVerdict,
          riskLevel: localCheck.verdict === 'OK' ? localCheck.riskLevel : (localCheck.riskLevel || res.data.riskLevel),
          chosenVersion: chosen || res.data.chosenVersion || localCheck.chosenVersion,
          recommendedVersion: recommended || res.data.recommendedVersion || localCheck.recommendedVersion,
          currentVersion: selected.packageVersion || res.data.currentVersion,
          summary: localCheck.summary,
          details: localCheck.details,
          advice: localCheck.advice,
          title: localCheck.title,
        });
        setShowVersionCheckModal(true);
      } catch {
        setVersionCheck(localCheck);
        setShowVersionCheckModal(true);
      } finally {
        setVersionCheckLoading(false);
      }
      return;
    }

    if (shouldMemorize) {
      setShowReasonModal(true);
      return;
    }
    await doApplyFix();
  };

  const handleScanSelect = (scanId: number) => {    setSelectedScanId(scanId);
    setSearchParams({ scanId: String(scanId) });
    setDropdownOpen(false);
    setFilter('ALL');
    setSearch('');
    setKevOnly(false); setUsageFilter('ALL');
    setCvssMin('');
    setEpssMin('');
    setActiveTab('cve');
    setSecrets([]);
    setSbomComponents([]);
    setSbomSelectedPkg(null);
    setSbomSearch('');
    setSbomFilter(null); setSbomLimit(DEP_PAGE);
    setSbomEcosystem('');
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

    // ── Section 1: Main summary table (enriched with ecosystem + dependency type) ──
    const flagsByRow: Record<number, string[]> = {};

    const rows = filtered.map((cve, idx) => {
      const flags: string[] = [];
      if (cve.kevListed)        flags.push('CISA KEV');
      if (cve.exploitAvailable) flags.push('EXPLOIT');
      if (cve.confirmedBy >= 2) flags.push('CONFIRMÉ');
      flagsByRow[idx] = flags;

      const eco = cve.ecosystem || '\u2014';
      const depType = (() => {
        const t = cve.directOrTransitive;
        if (t === 'DIRECT') return 'DIR';
        if (t === 'TRANSITIVE') return `TRANS${cve.dependencyDepth ? '.' + cve.dependencyDepth : ''}`;
        return '\u2014';
      })();
      const fixVer = cve.fixedVersion ? `→${cve.fixedVersion.split(/[,;]/)[0].trim()}` : '';

      return [
        cve.cveId || '\u2014',
        cve.severity,
        cve.cvssScore?.toFixed(1) || '\u2014',
        cve.epssScore != null ? `${(cve.epssScore * 100).toFixed(1)}%` : '\u2014',
        `${cve.packageName || '\u2014'}${cve.packageVersion ? '@' + cve.packageVersion : ''}${fixVer}`,
        eco,
        depType,
        cve.kevListed ? 'KEV' : '\u2014',
        cve.source?.toUpperCase() || '\u2014',
      ];
    });

    const badgeDef: Record<string, { color: [number, number, number]; w: number }> = {
      'CISA KEV': { color: [245, 158,  11], w: 18 },
      'EXPLOIT':  { color: [220,  38,  38], w: 16 },
      'CONFIRMÉ': { color: [ 16, 185, 129], w: 19 },
    };

    autoTable(doc, {
      startY: summaryY + 18,
      head: [['CVE / ID', 'Severity', 'CVSS', 'EPSS', 'Package', 'Éco', 'Dep', 'KEV', 'Source']],
      body: rows,
      styles: { fontSize: 7, cellPadding: 2, overflow: 'linebreak', minCellHeight: 16 },
      headStyles: { fillColor: [30, 30, 50], textColor: [255, 255, 255], fontStyle: 'bold', fontSize: 7.5 },
      columnStyles: {
        0: { cellWidth: 32, fontStyle: 'bold' },
        1: { cellWidth: 18, halign: 'center' },
        2: { cellWidth: 12, halign: 'center' },
        3: { cellWidth: 13, halign: 'center' },
        4: { cellWidth: 55 },
        5: { cellWidth: 13, halign: 'center' },
        6: { cellWidth: 16, halign: 'center' },
        7: { cellWidth: 16, halign: 'center' },
        8: { cellWidth: 16 },
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
        if (data.column.index === 7) {
          const val = data.cell.raw as string;
          if (val === 'KEV') { data.cell.styles.textColor = [245, 158, 11]; data.cell.styles.fontStyle = 'bold'; }
        }
        // Color dependency type: DIR = teal, TRANS = amber
        if (data.column.index === 6) {
          const val = data.cell.raw as string;
          if (val.startsWith('DIR'))        { data.cell.styles.textColor = [20, 184, 166]; data.cell.styles.fontStyle = 'bold'; }
          else if (val.startsWith('TRANS'))  { data.cell.styles.textColor = [245, 158, 11]; }
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

        let bx = data.cell.x + padding;
        let by = data.cell.y + 7;

        flags.forEach(flag => {
          const def = badgeDef[flag];
          if (!def) return;

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
        doc.setFontSize(7);
      },
      alternateRowStyles: { fillColor: [247, 247, 252] },
      margin: { left: 14, right: 14 },
    });

    // ── Section 2: Detail — Composant vulnérable & Chemin de dépendance (CRITICAL + HIGH only) ──
    const detailCves = filtered.filter(c => c.severity === 'CRITICAL' || c.severity === 'HIGH');

    if (detailCves.length > 0) {
      // Page break before detail section
      doc.addPage();

      // Section title
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 30, 40);
      doc.text(`Composants vulnérables & Chemins de dépendance`, 14, 20);

      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 100, 120);
      doc.text(`Détail des ${detailCves.length} vulnérabilités CRITICAL / HIGH — Composant, PURL, chemin de dépendance, version corrigée`, 14, 27);

      const detailRows = detailCves.map(cve => {
        const compName = cve.componentName || cve.packageName || '\u2014';
        const compVer  = cve.componentVersion || cve.packageVersion || '\u2014';
        const depType  = (() => {
          const t = cve.directOrTransitive;
          if (t === 'DIRECT')  return 'DIRECT';
          if (t === 'TRANSITIVE') return `TRANSITIVE (prof.${cve.dependencyDepth ?? '?'})`;
          return 'INCONNU';
        })();
        const conf = cve.dependencyConfidence || '\u2014';
        const depPath   = cve.dependencyPath || cve.purl || cve.manifestFile || '\u2014';
        const manifest  = cve.manifestFile || '\u2014';
        const fixVer    = cve.fixedVersion ? cve.fixedVersion.split(/[,;]/)[0].trim() : '\u2014';
        const module    = cve.moduleName || '\u2014';

        return [
          cve.cveId || '\u2014',
          cve.severity,
          `${compName}@${compVer}`,
          depType,
          conf,
          cve.ecosystem || '\u2014',
          depPath,
          manifest,
          module,
          fixVer,
        ];
      });

      autoTable(doc, {
        startY: 32,
        head: [[
          'CVE', 'Sev', 'Composant vulnérable', 'Type dép.',
          'Confiance', 'Écosyst.', 'Chemin de dépendance',
          'Manifeste', 'Module', 'Fixed In'
        ]],
        body: detailRows,
        styles: { fontSize: 6.5, cellPadding: 2, overflow: 'linebreak', minCellHeight: 14 },
        headStyles: { fillColor: [40, 20, 20], textColor: [255, 255, 255], fontStyle: 'bold', fontSize: 7 },
        columnStyles: {
          0: { cellWidth: 28, fontStyle: 'bold' },
          1: { cellWidth: 16, halign: 'center' },
          2: { cellWidth: 38 },
          3: { cellWidth: 24 },
          4: { cellWidth: 16, halign: 'center' },
          5: { cellWidth: 14, halign: 'center' },
          6: { cellWidth: 60 },
          7: { cellWidth: 32 },
          8: { cellWidth: 18 },
          9: { cellWidth: 18, halign: 'center' },
        },
        didParseCell: (data) => {
          if (data.section !== 'body') return;
          // Severity column coloring
          if (data.column.index === 1) {
            const val = data.cell.raw as string;
            if (val === 'CRITICAL') { data.cell.styles.textColor = [220, 38, 38]; data.cell.styles.fontStyle = 'bold'; }
            else if (val === 'HIGH') { data.cell.styles.textColor = [234, 88, 12]; data.cell.styles.fontStyle = 'bold'; }
          }
          // Dependency type coloring
          if (data.column.index === 3) {
            const val = data.cell.raw as string;
            if (val === 'DIRECT') {
              data.cell.styles.textColor = [20, 184, 166]; data.cell.styles.fontStyle = 'bold';
            } else if (val.startsWith('TRANSITIVE')) {
              data.cell.styles.textColor = [245, 158, 11];
            }
          }
          // Confidence coloring
          if (data.column.index === 4) {
            const val = data.cell.raw as string;
            if (val === 'HIGH') { data.cell.styles.textColor = [20, 184, 166]; data.cell.styles.fontStyle = 'bold'; }
            else if (val === 'MEDIUM') { data.cell.styles.textColor = [245, 158, 11]; }
          }
          // Fixed version: green if available, red dash if not
          if (data.column.index === 9) {
            const val = data.cell.raw as string;
            if (val === '\u2014') { data.cell.styles.textColor = [220, 38, 38]; data.cell.styles.fontStyle = 'bold'; }
            else { data.cell.styles.textColor = [20, 184, 166]; data.cell.styles.fontStyle = 'bold'; }
          }
        },
        alternateRowStyles: { fillColor: [252, 245, 245] },
        margin: { left: 14, right: 14 },
      });
    }

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

  const SEVERITY_ORDER: Record<string, number> = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };

  const dependencyCves = cves.filter(c => !isCodeWeakness(c) && !(c.cveId ?? '').startsWith('npm|'));
  const codeCves = cves.filter(c => isCodeWeakness(c));
  const familyCves = activeTab === 'code' ? codeCves : dependencyCves;

  const cvssMinNum = parseMinNumber(cvssMin);
  const epssMinPct = parseMinNumber(epssMin);

  const filtered = familyCves
    .filter(c => {
      const matchSeverity = filter === 'ALL' || c.severity === filter;
      const matchKev = !kevOnly || !!c.kevListed;
      const matchUsage = usageFilter === 'ALL' || c.codeUsage === usageFilter;
      const matchCvss = cvssMinNum == null || (c.cvssScore ?? -1) >= cvssMinNum;
      const matchEpss = epssMinPct == null || (c.epssScore ?? -1) * 100 >= epssMinPct;
      return matchSeverity && matchKev && matchUsage && matchCvss && matchEpss && cveMatchesQuery(c, search);
    })
    .sort((a, b) => {
      const kevDiff = Number(!!b.kevListed) - Number(!!a.kevListed);
      if (kevDiff !== 0) return kevDiff;
      const expDiff = Number(!!b.exploitAvailable) - Number(!!a.exploitAvailable);
      if (expDiff !== 0) return expDiff;
      const sDiff = (SEVERITY_ORDER[a.severity ?? ''] ?? 4) - (SEVERITY_ORDER[b.severity ?? ''] ?? 4);
      if (sDiff !== 0) return sDiff;
      return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
    });

  const counts = {
    ALL: familyCves.length,
    CRITICAL: familyCves.filter(c => c.severity === 'CRITICAL').length,
    HIGH: familyCves.filter(c => c.severity === 'HIGH').length,
    MEDIUM: familyCves.filter(c => c.severity === 'MEDIUM').length,
    LOW: familyCves.filter(c => c.severity === 'LOW').length,
    KEV: familyCves.filter(c => c.kevListed).length,
    USED: familyCves.filter(c => c.codeUsage === 'YES').length,
    NOT_IMPORTED: familyCves.filter(c => c.codeUsage === 'NOT_IMPORTED').length,
  };

  // Batch-fix group for the currently selected CVE
  const selectedGroup: CveDto[] = (() => {
    if (!selected?.packageName || !selected?.fixedVersion) return selected ? [selected] : [];
    const key = `${selected.packageName}|${selected.packageVersion ?? ''}|${selected.filePath ?? ''}`;
    return fixGroups.get(key) ?? [selected];
  })();
  const groupCount = selectedGroup.length;
  // Prefer chef policy, then same major.minor as installed
  const groupMaxFix = (() => {
    if (chefPolicyVersion) return chefPolicyVersion;
    if (fixPreview?.officialStableVersion) return fixPreview.officialStableVersion;
    const fromSelected = pickPreferredFixVersion(
      parseFixedVersionList(selected?.fixedVersion),
      selected?.packageVersion,
    );
    if (fromSelected) return fromSelected;
    return pickPreferredFixVersion(
      selectedGroup.flatMap(c => parseFixedVersionList(c.fixedVersion)),
      selected?.packageVersion,
    ) || '';
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
              {showLogs ? 'Scan en cours — suivi en direct' :
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
              { key: 'cve', icon: 'shield', label: 'Vulnérabilités', count: dependencyCves.length, danger: dependencyCves.filter(c => c.severity === 'CRITICAL').length > 0 },
              { key: 'code', icon: 'security', label: 'Sécurité du code', count: codeCves.length + openSecrets.length, danger: openSecrets.some(s => effectiveVerdict(s) === 'LIKELY_REAL') || codeCves.some(c => c.severity === 'CRITICAL' || c.severity === 'HIGH') },
              { key: 'sbom', icon: 'inventory_2', label: 'Dépendances', count: sbomComponents.length, danger: (supply.report?.summary.knownMalicious ?? 0) + (supply.report?.summary.highConfidence ?? 0) > 0 },
              { key: 'evolution', icon: 'trending_up', label: 'Évolution', count: 0, danger: false },
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

        {/* LIVE LOGS — pipeline, progress, coloured sources, counters (see ScanLiveLog) */}
        {showLogs && (
          <ScanLiveLog
            entries={logs}
            title={currentScan ? repoName(currentScan.repoUrl) : 'scan'}
            complete={finishing}
          />
        )}

        {/* CVE TABLE — shown when scan is completed */}
        {/* ── SÉCURITÉ DU CODE : secrets exposés + faiblesses du code (Semgrep / SAST) ── */}
        {!showLogs && activeTab === 'code' && (
          <div className="space-y-4 mb-8">
            {/* ── Secrets : triés par le modèle (réels d'abord, faux positifs masqués) ── */}
            <SecretsPanel
              secrets={secrets}
              loading={secretsLoading}
              triaging={secretsTriaging}
              onTriage={handleTriageSecrets}
              onVerdict={handleSecretVerdict}
            />
            <div className="flex items-center gap-4 pt-2">
              <div className="flex-1 h-px bg-outline-variant/[0.15]"></div>
              <span className="text-[10px] text-outline uppercase tracking-widest font-bold px-3">Faiblesses du code (SAST / OWASP)</span>
              <div className="flex-1 h-px bg-outline-variant/[0.15]"></div>
            </div>
          </div>
        )}

        {!showLogs && (activeTab === 'cve' || activeTab === 'code') && (
          <>
            {/* Filter Header */}
            <div className="mb-6 flex flex-col gap-3 bg-surface-container-low p-4 rounded-xl border border-outline-variant/[0.1]">
              <div className="flex flex-col lg:flex-row gap-3 items-stretch lg:items-center justify-between">
                <div className="relative w-full lg:flex-1 min-w-0">
                  <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">search</span>
                  <input
                    className="bg-surface-container-lowest border-none w-full pl-10 pr-4 py-2 text-sm rounded-lg focus:ring-1 focus:ring-primary text-on-surface"
                    placeholder="Filtrer tout : CVE, paquet, alias, CVSS, EPSS, KEV…"
                    type="text"
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                  />
                </div>
                <div className="flex items-center gap-2 shrink-0 flex-wrap">
                  <label className="flex items-center gap-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                    CVSS ≥
                    <input
                      className="bg-surface-container-lowest border-none w-[4.5rem] px-2 py-2 text-sm rounded-lg focus:ring-1 focus:ring-primary text-on-surface font-mono"
                      type="number"
                      min={0}
                      max={10}
                      step={0.1}
                      placeholder="0"
                      value={cvssMin}
                      onChange={e => setCvssMin(e.target.value)}
                      title="Afficher uniquement les CVE avec un CVSS supérieur ou égal"
                    />
                  </label>
                  <label className="flex items-center gap-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                    EPSS ≥
                    <input
                      className="bg-surface-container-lowest border-none w-[4.5rem] px-2 py-2 text-sm rounded-lg focus:ring-1 focus:ring-primary text-on-surface font-mono"
                      type="number"
                      min={0}
                      max={100}
                      step={0.1}
                      placeholder="%"
                      value={epssMin}
                      onChange={e => setEpssMin(e.target.value)}
                      title="Afficher uniquement les CVE avec un EPSS (en %) supérieur ou égal"
                    />
                  </label>
                </div>
              </div>
              <div className="flex items-center gap-3 w-full flex-wrap">
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
                <button
                  onClick={() => setKevOnly(v => !v)}
                  title={
                    kevCatalogSize == null
                      ? 'Filtrer les CVE déjà exploitées (catalogue CISA KEV)'
                      : kevCatalogSize === 0
                        ? 'Catalogue CISA KEV indisponible — le badge ne peut pas s\'afficher'
                        : `Catalogue CISA chargé (${kevCatalogSize} CVE). ${counts.KEV} dans ce scan = déjà exploitées dans le monde réel.`
                  }
                  className={`px-4 py-1.5 rounded-full text-xs font-bold ${
                    kevOnly ? 'bg-amber-500 text-white' : 'bg-surface-container hover:bg-surface-container-high text-amber-500 border border-amber-500/30'
                  }`}
                >
                  KEV ({counts.KEV}{kevCatalogSize != null ? ` / ${kevCatalogSize}` : ''})
                </button>
                {activeTab !== 'code' && (counts.USED > 0 || counts.NOT_IMPORTED > 0) && (
                  <>
                    <button
                      onClick={() => setUsageFilter(v => (v === 'YES' ? 'ALL' : 'YES'))}
                      title="Paquets importés par le code de votre projet : la vulnérabilité est potentiellement atteignable"
                      className={`px-4 py-1.5 rounded-full text-xs font-bold ${
                        usageFilter === 'YES' ? 'bg-orange-500 text-white' : 'bg-surface-container hover:bg-surface-container-high text-orange-400 border border-orange-400/30'
                      }`}
                    >
                      Utilisé dans le code ({counts.USED})
                    </button>
                    <button
                      onClick={() => setUsageFilter(v => (v === 'NOT_IMPORTED' ? 'ALL' : 'NOT_IMPORTED'))}
                      title="Aucun import trouvé dans votre code : dépendance indirecte, ou inutilisée (alors à supprimer)"
                      className={`px-4 py-1.5 rounded-full text-xs font-bold ${
                        usageFilter === 'NOT_IMPORTED' ? 'bg-slate-500 text-white' : 'bg-surface-container hover:bg-surface-container-high text-slate-300 border border-slate-400/30'
                      }`}
                    >
                      Non importé ({counts.NOT_IMPORTED})
                    </button>
                  </>
                )}
                </div>

                {/* Export PDF button */}
                <button
                  onClick={exportPdf}
                  disabled={filtered.length === 0}
                  title="Exporter les vulnérabilités en PDF"
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20 transition-all disabled:opacity-30 disabled:cursor-not-allowed shrink-0 ml-auto"
                >
                  <span className="material-symbols-outlined text-sm">download</span>
                  Export PDF
                </button>
              </div>
            </div>

            {/* Table */}
            <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] overflow-hidden shadow-2xl">
              <table className="w-full text-left border-collapse table-fixed">
                  <thead>
                    <tr className="bg-surface-container-low/50 border-b border-outline-variant/[0.1]">
                      <th className="w-[38%] px-4 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest">Vulnerability</th>
                      <th className="w-[14%] px-2 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest text-center">
                        {activeTab === 'code' ? 'Severity' : (
                          <InfoHoverCard
                            title="Gravité (CRITICAL / HIGH / MEDIUM / LOW)"
                            body={
                              <>
                                <p>Le badge vient <strong className="text-on-surface">uniquement du score CVSS</strong> (échelle NVD) :</p>
                                <p>CRITICAL ≥ 9,0 · HIGH 7,0–8,9 · MEDIUM 4,0–6,9 · LOW &lt; 4,0.</p>
                                <p>L’EPSS ne change pas ce badge. KEV n’est pas une gravité : c’est un flag « déjà exploitée » (URGENT).</p>
                              </>
                            }
                          >
                            <span className="underline decoration-dotted decoration-slate-500 underline-offset-4">Severity</span>
                          </InfoHoverCard>
                        )}
                      </th>
                      <th className="w-[10%] px-2 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest text-center">
                        {activeTab === 'code' ? 'CWE' : (
                          <InfoHoverCard
                            title="CVSS — impact"
                            body={
                              <>
                                <p>Common Vulnerability Scoring System (0–10) : <strong className="text-on-surface">gravité si la faille est exploitée</strong>.</p>
                                <p>Vulnix convertit ce score en CRITICAL / HIGH / MEDIUM / LOW. L’EPSS n’entre pas dans ce calcul.</p>
                              </>
                            }
                          >
                            <span className="underline decoration-dotted decoration-slate-500 underline-offset-4">CVSS</span>
                          </InfoHoverCard>
                        )}
                      </th>
                      <th className="w-[10%] px-2 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest text-center">
                        {activeTab === 'code' ? 'Ligne' : (
                          <InfoHoverCard
                            title="EPSS — chance d’exploit"
                            body={
                              <>
                                <p>Exploit Prediction Scoring System : <strong className="text-on-surface">probabilité qu’un exploit soit vu dans les 30 jours</strong> (FIRST.org).</p>
                                <p>Ça n’augmente pas le CVSS et ne transforme pas un MEDIUM en CRITICAL. Un EPSS 0,5 % = risque d’exploit proche très bas.</p>
                              </>
                            }
                          >
                            <span className="underline decoration-dotted decoration-slate-500 underline-offset-4">EPSS</span>
                          </InfoHoverCard>
                        )}
                      </th>
                      <th className="w-[18%] px-4 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest">{activeTab === 'code' ? 'Fichier' : 'Package'}</th>
                      <th className="w-[10%] px-2 py-4 text-xs font-bold font-headline text-slate-400 uppercase tracking-widest">
                        {activeTab === 'code' ? 'Source' : (
                          <InfoHoverCard
                            align="right"
                            title="Source — outils de scan"
                            body={
                              <>
                                <p>Scanners qui ont trouvé la CVE (Grype, Trivy…).</p>
                                <p>Le badge <strong className="text-on-surface">2×</strong> = deux outils indépendants. Ça confirme la détection, ça ne change pas le CVSS.</p>
                              </>
                            }
                          >
                            <span className="underline decoration-dotted decoration-slate-500 underline-offset-4">Source</span>
                          </InfoHoverCard>
                        )}
                      </th>
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
                        <p className="text-sm">{familyCves.length === 0
                          ? (activeTab === 'code' ? 'Aucune faiblesse de code détectée.' : 'No vulnerabilities found — your code is clean!')
                          : 'Aucun résultat pour ces filtres (recherche, CVSS, EPSS ou KEV).'}</p>
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
                              <span className="text-on-surface font-semibold text-sm group-hover:text-primary transition-colors truncate">{cve.canonicalId || cve.cveId || 'N/A'}</span>
                              {(() => {
                                const allBadges: React.ReactNode[] = [];
                                if (cve.codeUsage === 'YES') allBadges.push(
                                  <span
                                    key="usage"
                                    title={`Votre code importe ce paquet${cve.usageFiles?.length ? ` (${cve.usageFiles.join(', ')})` : ''} : vulnérabilité potentiellement atteignable`}
                                    className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-orange-500/20 text-orange-300 border border-orange-400/30 shrink-0"
                                  ><span className="material-symbols-outlined text-[10px]">code</span>UTILISÉ</span>
                                );
                                else if (cve.codeUsage === 'TEST_ONLY') allBadges.push(
                                  <span key="usage" title="Importé uniquement par les tests du projet" className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-500/20 text-slate-300 shrink-0">TESTS</span>
                                );
                                else if (cve.codeUsage === 'NOT_IMPORTED') allBadges.push(
                                  <span key="usage" title="Aucun import trouvé dans votre code (dépendance indirecte ou inutilisée)" className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-500/15 text-slate-400 shrink-0">NON IMPORTÉ</span>
                                );
                                if (cve.kevListed) allBadges.push(
                                  <InfoHoverCard
                                    key="kev"
                                    title="KEV ≠ Exploit-DB"
                                    body={
                                      <>
                                        <p><strong className="text-amber-400">CISA KEV</strong> = Known Exploited Vulnerabilities : la faille a <strong className="text-on-surface">déjà été utilisée dans le monde réel</strong>{cve.kevRansomware ? ' (campagnes ransomware)' : ''}.</p>
                                        <p>Ce n’est pas un score. Ça ajoute le traitement URGENT, même si le CVSS n’est pas 10.</p>
                                        <p><strong className="text-error">EXPLOIT</strong> (Exploit-DB) = un PoC public existe. Ce n’est pas une attaque confirmée.</p>
                                      </>
                                    }
                                  >
                                    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-500 text-white shrink-0">
                                      <span className="material-symbols-outlined text-[10px]">warning</span>KEV
                                    </span>
                                  </InfoHoverCard>
                                );
                                if (cve.exploitAvailable) allBadges.push(
                                  <InfoHoverCard
                                    key="exploit"
                                    title="EXPLOIT (Exploit-DB) ≠ KEV"
                                    body={
                                      <>
                                        <p><strong className="text-error">Exploit-DB</strong> = un code d’attaque (PoC) a été publié. Quelqu’un <em>peut</em> s’en servir.</p>
                                        <p><strong className="text-amber-400">CISA KEV</strong> = CISA a constaté une exploitation réelle. Ce n’est pas le même signal.</p>
                                        <p>Sur cette ligne : PoC public{cve.kevListed ? ', et aussi KEV' : ', pas dans KEV'}.</p>
                                      </>
                                    }
                                  >
                                    <a
                                      href={cve.exploitUrl || `https://www.exploit-db.com/search?cve=${cve.cveId}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      onClick={e => e.stopPropagation()}
                                      className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-error text-on-error shrink-0 hover:opacity-80 transition-opacity"
                                    ><span className="material-symbols-outlined text-[10px]">bug_report</span>EXPLOIT</a>
                                  </InfoHoverCard>
                                );
                                {
                                  const srcList = sourceList(cve);
                                  const count = cve.confirmedBy ?? srcList.length;
                                  if (count >= 2) {
                                    allBadges.push(
                                      <InfoHoverCard
                                        key="confirmed"
                                        title={`Confirmé ${count}×`}
                                        body={
                                          <>
                                            <p>Détecté par {count} scanners : <strong className="text-on-surface">{srcList.join(', ') || 'plusieurs outils'}</strong>.</p>
                                            <p>Le 2× augmente la confiance, pas le CVSS ni l’EPSS.</p>
                                          </>
                                        }
                                      >
                                        <span className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold shrink-0 ${count >= 3 ? 'bg-emerald-700 text-white' : 'bg-emerald-600 text-white'}`}>
                                          <span className="material-symbols-outlined text-[10px]">verified</span>{count}×
                                        </span>
                                      </InfoHoverCard>
                                    );
                                  } else if (srcList.length === 1) {
                                    allBadges.push(
                                      <InfoHoverCard
                                        key="confirmed"
                                        title="Source unique"
                                        body={<p>Vu seulement par <strong className="text-on-surface">{srcList[0]}</strong>. Moins de confirmation croisée qu’un badge 2×.</p>}
                                      >
                                        <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-600 text-white shrink-0">
                                          <span className="material-symbols-outlined text-[10px]">sensors</span>1×
                                        </span>
                                      </InfoHoverCard>
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
                          {activeTab === 'code' ? (
                            <span className={`inline-flex items-center px-2 py-1 rounded-full text-[10px] font-bold ${severityBadge(cve.severity)}`}>{cve.severity}</span>
                          ) : (
                            <InfoHoverCard
                              className="w-full justify-center"
                              title={`${cve.severity} — d’où ça vient`}
                              body={
                                <>
                                  <p>Badge calculé depuis le <strong className="text-on-surface">CVSS {cve.cvssScore?.toFixed(1) ?? 'N/D'}</strong> → bande {cvssBand(cve.cvssScore)}.</p>
                                  <p>CRITICAL ≥ 9 · HIGH 7–8,9 · MEDIUM 4–6,9 · LOW &lt; 4. Ex. 4,7 = MEDIUM, 9,2 = CRITICAL.</p>
                                  <p>EPSS {cve.epssScore != null ? `${(cve.epssScore * 100).toFixed(1)} %` : 'N/D'} n’entre pas dans ce badge.</p>
                                </>
                              }
                            >
                              <span className={`inline-flex items-center px-2 py-1 rounded-full text-[10px] font-bold ${severityBadge(cve.severity)}`}>{cve.severity}</span>
                            </InfoHoverCard>
                          )}
                        </td>
                        <td className="px-2 py-4 text-center">
                          {activeTab === 'code' ? (
                            <span className="text-[11px] font-mono text-on-surface-variant">{cve.cweId || (cve.cveId?.startsWith('CWE-') ? cve.cveId : '—')}</span>
                          ) : (
                            <InfoHoverCard
                              className="w-full justify-center"
                              title={`CVSS ${cve.cvssScore?.toFixed(1) ?? '—'}`}
                              body={
                                <>
                                  <p>Score d’<strong className="text-on-surface">impact</strong> (0–10). Ici {cve.cvssScore?.toFixed(1) ?? 'absent'} → <strong className="text-on-surface">{cvssBand(cve.cvssScore)}</strong>.</p>
                                  <p>C’est ce chiffre qui donne CRITICAL / MEDIUM. L’EPSS et Exploit-DB ne le recalculent pas.</p>
                                </>
                              }
                            >
                              <div className={`inline-flex items-center justify-center w-10 h-10 rounded-lg bg-surface-container-highest border ${severityBorder(cve.severity)} font-bold font-headline text-sm`}>
                                {cve.cvssScore?.toFixed(1) || '—'}
                              </div>
                            </InfoHoverCard>
                          )}
                        </td>
                        <td className="px-2 py-4 text-center">
                          {activeTab === 'code' ? (
                            <span className="text-xs text-on-surface-variant">{cve.lineNumber ?? '—'}</span>
                          ) : cve.epssScore != null ? (
                            <InfoHoverCard
                              className="w-full justify-center"
                              title={`EPSS ${(cve.epssScore * 100).toFixed(1)} %`}
                              body={
                                <>
                                  <p>Chance estimée d’exploit dans les <strong className="text-on-surface">30 prochains jours</strong> ({epssInfo(cve.epssScore).label}).</p>
                                  <p>Ne change pas le CVSS : un MEDIUM à 0,5 % reste MEDIUM. Sert à prioriser parmi des scores proches.</p>
                                </>
                              }
                            >
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
                            </InfoHoverCard>
                          ) : (
                            <InfoHoverCard
                              title="EPSS indisponible"
                              body={<p>Pas d’identifiant CVE canonique, donc pas de score FIRST.org pour cette ligne.</p>}
                            >
                              <span className="text-xs text-slate-400">N/D</span>
                            </InfoHoverCard>
                          )}
                        </td>
                        <td className="px-4 py-4">
                          {activeTab === 'code' ? (
                            <>
                              <span className="text-xs font-mono text-on-surface-variant truncate block" title={cve.filePath || ''}>
                                {cve.filePath ? cve.filePath.split('/').slice(-2).join('/') : (cve.packageName || '—')}
                              </span>
                              {cve.lineNumber != null && <span className="text-xs text-slate-500">:{cve.lineNumber}</span>}
                            </>
                          ) : (
                            <>
                              <span className="text-xs font-mono text-on-surface-variant truncate block">{cve.packageName || '—'}</span>
                              {cve.packageVersion && <span className="text-xs text-slate-500">@{cve.packageVersion}</span>}
                            </>
                          )}
                        </td>
                        <td className="px-2 py-4">
                          {activeTab === 'code' ? (
                            <span className="text-[10px] text-slate-500 uppercase tracking-wide">{formatSources(cve.sources, cve.source)}</span>
                          ) : (
                            <InfoHoverCard
                              className="w-full"
                              align="right"
                              title="Sources du scan"
                              body={
                                <>
                                  <p>Outils : <strong className="text-on-surface">{formatSources(cve.sources, cve.source)}</strong>.</p>
                                  <p>{(cve.confirmedBy ?? sourceList(cve).length) >= 2
                                    ? 'Plusieurs scanners = confirmation. Ça ne monte pas le CVSS.'
                                    : 'Un seul scanner a reporté cette CVE.'}</p>
                                </>
                              }
                            >
                              <span className="text-[10px] text-slate-500 uppercase tracking-wide">{formatSources(cve.sources, cve.source)}</span>
                            </InfoHoverCard>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
            </div>
          </>
        )}

        {/* ── DÉPENDANCES : SBOM + supply chain (npm / PyPI), urgent d'abord ── */}
        {!showLogs && activeTab === 'sbom' && (() => {
          const ecosystems = Array.from(new Set(sbomComponents.map(c => c.type).filter(Boolean))).sort();
          // supply-chain verdict of each dependency, keyed like the backend cache (ecosystem:name@version)
          const supplyBriefs = new Map<string, SupplyChainBrief>();
          [...(supply.report?.analyzed ?? []), ...(supply.report?.skipped ?? [])].forEach(b =>
            supplyBriefs.set(supplyChainKey(b.ecosystem ?? 'npm', b.name, b.version), b));
          const supplyFlagged = new Map<string, SupplyChainItem>();
          (supply.report?.flagged ?? []).forEach(f => supplyFlagged.set(supplyChainKey(f.ecosystem ?? 'npm', f.name, f.version), f));
          const flaggedKey = (pkg: SbomComponent) => supplyChainKey(ecosystemOfPurl(pkg.purl) ?? 'npm', pkg.name, pkg.version);

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

          const rows = buildDependencyRows(
            sbomComponents,
            cves,
            pkg => {
              const eco = ecosystemOfPurl(pkg.purl);
              return eco ? supplyBriefs.get(supplyChainKey(eco, pkg.name, pkg.version)) ?? null : null;
            },
            pkg => supplyFlagged.get(flaggedKey(pkg)) ?? null,
            pkg => !!ecosystemOfPurl(pkg.purl),
          );
          const counts = countViews(rows);
          const view: DepView = sbomFilter ?? defaultView(counts);
          const filtered = filterRows(rows, view, sbomSearch, sbomEcosystem);
          const shown = filtered.slice(0, sbomLimit);
          const supplyPending = supply.report ? supply.report.summary.pending > 0 : true;

          const chips: { key: DepView; label: string; icon: string; tone: string }[] = [
            { key: 'critical', label: 'À traiter en premier', icon: 'priority_high', tone: 'error' },
            { key: 'cve', label: 'Avec CVE', icon: 'warning', tone: 'warning' },
            { key: 'suspect', label: 'Suspects (supply chain)', icon: 'gpp_maybe', tone: 'warning' },
            { key: 'all', label: 'Toutes', icon: 'inventory_2', tone: 'primary' },
          ];

          return (
            <div>
              <div className="mb-5">
                <SupplyChainBanner
                  report={supply.report}
                  busy={supply.analyzing || !!supply.report?.analysisRunning}
                  error={supply.error}
                  onAnalyze={() => void supply.analyze()}
                />
              </div>

              {/* Choose what to look at: urgent first, never the whole list by default */}
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-2">
                {chips.map(c => {
                  const active = view === c.key;
                  const n = counts[c.key];
                  const danger = c.key === 'critical' && n > 0;
                  return (
                    <button
                      key={c.key}
                      onClick={() => { setSbomFilter(c.key); setSbomLimit(DEP_PAGE); }}
                      className={`text-left rounded-xl border px-4 py-3 transition-all ${active ? 'border-primary/60 bg-primary/10' : 'border-outline-variant/[0.2] hover:border-primary/30'} ${danger && !active ? 'border-error/40' : ''}`}
                    >
                      <div className="flex items-center gap-2 text-[11px] text-outline uppercase font-bold">
                        <span className={`material-symbols-outlined text-base ${danger ? 'text-error' : ''}`}>{c.icon}</span>
                        {c.label}
                      </div>
                      <p className={`text-2xl font-bold mt-1 ${danger ? 'text-error' : 'text-on-surface'}`}>{n}</p>
                    </button>
                  );
                })}
              </div>
              <p className="text-xs text-outline mb-4">{VIEW_HELP[view]}</p>

              <div className="flex flex-wrap gap-2 mb-4 items-center">
                <div className="relative flex-1 min-w-[200px]">
                  <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-sm">search</span>
                  <input
                    className="w-full bg-surface-container border border-outline-variant/[0.2] rounded-xl pl-9 pr-4 py-2 text-sm text-on-surface placeholder-outline focus:outline-none focus:border-primary/60 transition-colors"
                    placeholder="Rechercher un paquet…"
                    value={sbomSearch}
                    onChange={e => { setSbomSearch(e.target.value); setSbomLimit(DEP_PAGE); }}
                  />
                </div>
                {ecosystems.length > 1 && (
                  <select
                    className="bg-surface-container border border-outline-variant/[0.2] rounded-xl px-3 py-2 text-xs text-on-surface focus:outline-none focus:border-primary/60 transition-colors"
                    value={sbomEcosystem}
                    onChange={e => { setSbomEcosystem(e.target.value); setSbomLimit(DEP_PAGE); }}
                  >
                    <option value="">Tous les écosystèmes</option>
                    {ecosystems.map(e => <option key={e} value={e}>{e}</option>)}
                  </select>
                )}
                <span className="text-xs text-outline ml-auto">{shown.length} affichés sur {filtered.length}</span>
              </div>

              {filtered.length === 0 ? (
                <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-8 text-center">
                  <span className="material-symbols-outlined text-3xl text-tertiary mb-2 block">verified</span>
                  <p className="text-sm text-on-surface">Rien à afficher dans cette vue.</p>
                  {view !== 'all' && (
                    <button className="mt-3 text-xs text-primary underline" onClick={() => setSbomFilter('all')}>
                      Voir toutes les dépendances ({counts.all})
                    </button>
                  )}
                </div>
              ) : (
                <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] overflow-hidden shadow-2xl">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-surface-container-low/30 border-b border-outline-variant/[0.1]">
                        <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest">Paquet</th>
                        <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest">Pourquoi</th>
                        <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[16%]">Que faire</th>
                        <th className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest w-[16%]">Supply chain</th>
                      </tr>
                    </thead>
                    <tbody>
                      {shown.map((r, idx) => {
                        const pkg = r.pkg;
                        const isSelected = sbomSelectedPkg?.id === pkg.id;
                        const border = r.critical ? 'border-l-2 border-l-error' : r.priority <= 4 ? 'border-l-2 border-l-warning' : '';
                        const line = reasonLine(r);
                        return (
                          <React.Fragment key={pkg.id ?? idx}>
                            <tr
                              className={`border-b border-outline-variant/[0.07] cursor-pointer transition-all hover:bg-primary/5 ${isSelected ? 'bg-primary/[0.04]' : ''} ${border}`}
                              onClick={() => setSbomSelectedPkg(isSelected ? null : pkg)}
                            >
                              <td className="px-4 py-3">
                                <div className="flex items-center gap-2">
                                  <span className="text-sm font-headline text-on-surface break-all">{pkg.name}</span>
                                  <span className="px-1.5 py-0.5 rounded-md text-[10px] font-bold bg-surface-container-high text-on-surface-variant border border-outline-variant/[0.2]">{pkg.type || '—'}</span>
                                </div>
                                <p className="text-[11px] font-mono text-outline mt-0.5">{pkg.version || '—'}</p>
                              </td>
                              <td className="px-4 py-3 text-xs">
                                {r.worst && (
                                  <span className={`inline-block mr-2 px-2 py-0.5 rounded-full font-bold text-[10px] ${severityBadge(r.worst)}`}>{r.worst}</span>
                                )}
                                {line ? <span className="text-on-surface-variant">{line}</span> : <span className="text-tertiary">Aucun problème connu</span>}
                              </td>
                              <td className="px-4 py-3 text-xs">
                                {r.brief?.tier === 'KNOWN_MALICIOUS' || r.brief?.tier === 'HIGH_CONFIDENCE'
                                  ? <span className="text-error font-bold">Supprimer ce paquet</span>
                                  : r.fixedVersion
                                    ? <span className="text-tertiary font-bold">Mettre à jour vers {r.fixedVersion}</span>
                                    : r.cves.length > 0
                                      ? <span className="text-outline">Pas de correctif publié</span>
                                      : <span className="text-outline">—</span>}
                              </td>
                              <td className="px-4 py-3">
                                <SupplyChainCell brief={r.brief} supported={r.supplyCovered} pending={supplyPending} />
                              </td>
                            </tr>
                            {isSelected && (
                              <tr className="bg-surface-container/40 border-b border-outline-variant/[0.07]">
                                <td colSpan={4} className="px-6 py-4">
                                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4 text-sm">
                                    <div>
                                      <p className="text-[10px] text-outline uppercase font-bold mb-1">PURL</p>
                                      <p className="font-mono text-xs text-on-surface-variant break-all">{pkg.purl || '—'}</p>
                                    </div>
                                    <div>
                                      <p className="text-[10px] text-outline uppercase font-bold mb-1">Licence</p>
                                      <p className="text-xs text-on-surface-variant">{pkg.license || '—'}</p>
                                    </div>
                                    <div>
                                      <p className="text-[10px] text-outline uppercase font-bold mb-1">Localisation</p>
                                      <p className="font-mono text-xs text-on-surface-variant break-all">{pkg.location || '—'}</p>
                                    </div>
                                  </div>
                                  {r.flagged && (
                                    <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3">
                                      <p className="text-[10px] text-outline uppercase font-bold mb-1">Pourquoi ce paquet est signalé (supply chain)</p>
                                      <ul className="list-disc pl-5 text-xs text-on-surface-variant space-y-0.5">
                                        {r.flagged.reasons.map(x => <li key={x}>{x}</li>)}
                                      </ul>
                                    </div>
                                  )}
                                  {r.cves.length > 0 && (
                                    <div>
                                      <p className="text-[10px] text-outline uppercase font-bold mb-2">CVEs liées ({r.cves.length})</p>
                                      <div className="space-y-1.5">
                                        {[...r.cves].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)).map((v, vi) => (
                                          <div key={vi} className={`flex flex-wrap items-center gap-3 px-3 py-2 rounded-lg border text-xs ${v.severity === 'CRITICAL' ? 'bg-error/5 border-error/20' : 'bg-surface-container border-outline-variant/[0.1]'}`}>
                                            <span className={`px-2 py-0.5 rounded-full font-bold text-[10px] ${severityBadge(v.severity)}`}>{v.severity}</span>
                                            <span className="font-mono text-primary">{v.cveId || '—'}</span>
                                            {v.cvssScore != null && <span className="text-outline">CVSS {v.cvssScore.toFixed(1)}</span>}
                                            {v.kevListed && <span className="text-error font-bold text-[10px]">EXPLOITÉE (KEV)</span>}
                                            {!v.kevListed && v.exploitAvailable && <span className="text-error text-[10px]">exploit public</span>}
                                            <span className="text-on-surface-variant flex-1 min-w-[160px] truncate">{v.description?.slice(0, 100) || '—'}</span>
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
                  {filtered.length > shown.length && (
                    <div className="flex justify-center py-3 border-t border-outline-variant/[0.1]">
                      <button
                        className="px-4 py-2 rounded-lg text-xs font-bold border border-primary/30 text-primary hover:bg-primary/10"
                        onClick={() => setSbomLimit(l => l + DEP_PAGE)}
                      >
                        Afficher {Math.min(DEP_PAGE, filtered.length - shown.length)} de plus ({filtered.length - shown.length} restants)
                      </button>
                    </div>
                  )}
                </div>
              )}

              <details className="mt-6 glass-panel rounded-2xl border border-outline-variant/[0.15] px-4 py-3">
                <summary className="text-sm text-on-surface cursor-pointer">Vérifier un paquet avant de l'installer</summary>
                <div className="mt-3"><PackageChecker /></div>
              </details>
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
      </section>

      {/* Floating Intelligence Card — only on CVE tab when a row is selected */}
      {!showLogs && (activeTab === 'cve' || activeTab === 'code') && selected && (isCodeWeakness(selected) === (activeTab === 'code')) && (() => {
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
                    {formatSources(selected.sources, selected.source)}
                  </span>
                  {selected.fixAvailable && (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-emerald-600/20 text-emerald-300 border border-emerald-500/30">
                      FIX AVAILABLE
                    </span>
                  )}
                  {selected.cweId && (
                    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-bold bg-surface-container-highest text-outline border border-outline-variant/[0.15] font-mono">
                      {selected.cweId}
                    </span>
                  )}
                  {isDevOnly(selected) && (
                    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-bold bg-slate-600/30 text-slate-300 border border-slate-500/30" title="Dépendance de développement uniquement (dev/test)">
                      DEV-ONLY
                    </span>
                  )}
                  {selected.exploitAvailable && (
                    <a
                      href={selected.exploitUrl || `https://www.exploit-db.com/search?cve=${selected.cveId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-error text-on-error hover:opacity-80 transition-opacity"
                      title="PoC public (Exploit-DB) : un code d'attaque a été publié. Pas une exploitation confirmée — voir CISA KEV."
                    >
                      <span className="material-symbols-outlined text-xs">bug_report</span>
                      PoC public
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
                  {selected.kevListed && (
                    <span
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-red-600 text-white"
                      title="CISA KEV — déjà exploitée dans le monde réel, correctif urgent"
                    >
                      URGENT
                    </span>
                  )}
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
                    <h3 className="text-lg font-bold font-headline text-on-surface leading-tight break-all">{selected.canonicalId || selected.cveId || 'Unknown'}</h3>
                    {formatAliases(selected) && (
                      <p className="text-[10px] text-slate-500 mt-0.5 font-mono truncate" title={formatAliases(selected)}>Aliases: {formatAliases(selected)}</p>
                    )}
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
                      {selected.canonicalId && selected.canonicalId !== selected.cveId && (
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-500">Canonical</span>
                          <span className="text-on-surface font-mono">{selected.canonicalId}</span>
                        </div>
                      )}
                      {formatAliases(selected) && (
                        <div className="flex justify-between text-xs gap-3">
                          <span className="text-slate-500 shrink-0">Aliases</span>
                          <span className="text-on-surface font-mono text-right break-all">{formatAliases(selected)}</span>
                        </div>
                      )}
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-500">Installed</span>
                        <span className="text-on-surface font-mono">{selected.packageVersion || '—'}</span>
                      </div>
                      {cves.filter(c =>
                        (c.canonicalId || c.cveId) === (selected.canonicalId || selected.cveId)
                        && (c.packageName || '') === (selected.packageName || '')
                        && (c.packageVersion || '') !== (selected.packageVersion || '')
                        && c.id !== selected.id
                      ).length > 0 && (
                        <div className="flex justify-between text-xs gap-3">
                          <span className="text-slate-500 shrink-0">Autres copies</span>
                          <span className="text-on-surface font-mono text-right">
                            {cves.filter(c =>
                              (c.canonicalId || c.cveId) === (selected.canonicalId || selected.cveId)
                              && (c.packageName || '') === (selected.packageName || '')
                              && (c.packageVersion || '') !== (selected.packageVersion || '')
                              && c.id !== selected.id
                            ).map(c => `${c.packageName}@${c.packageVersion}`).join(', ')}
                          </span>
                        </div>
                      )}
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-500">Fixed In</span>
                        <span className={`font-mono font-semibold ${selected.fixAvailable && selected.fixedVersion ? 'text-tertiary' : 'text-error'}`}>
                          {selected.fixAvailable && selected.fixedVersion ? selected.fixedVersion : 'No fix available'}
                        </span>
                      </div>
                      <div className="flex justify-between text-xs">
                        <span className="text-slate-500">Source</span>
                        <span className="text-on-surface font-semibold uppercase tracking-wide">{formatSources(selected.sources, selected.source)}</span>
                      </div>
                      {selected.confirmedBy >= 2 && (
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-500">Confirmation</span>
                          <span className="text-emerald-400 font-semibold">{selected.confirmedBy}× · {formatSources(selected.sources, selected.source)}</span>
                        </div>
                      )}
                      {selected.cweId && (
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-500">CWE</span>
                          <span className="text-on-surface font-mono">{selected.cweId}</span>
                        </div>
                      )}
                      {selected.target && (
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-500">Target</span>
                          <span className="text-on-surface font-mono truncate ml-4">{selected.target}</span>
                        </div>
                      )}
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-slate-500">CISA KEV</span>
                        <span className={selected.kevListed ? 'text-amber-400 font-bold' : 'text-on-surface'}>
                          {selected.kevListed ? 'Oui — déjà exploitée' : 'Non — pas d\'exploitation confirmée'}
                        </span>
                      </div>
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
                        <span className="text-on-surface uppercase">{formatSources(selected.sources, selected.source)}</span>
                      </div>
                      {selected.cweId && (
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-500">CWE</span>
                          <span className="text-on-surface font-mono">{selected.cweId}</span>
                        </div>
                      )}
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

                {/* Journal CVE — politique chef + reco (aligné /cve-journal) */}
                {isPackageBased && selected.cveId && (
                  <div className="space-y-2 rounded-xl border border-tertiary/25 bg-tertiary/5 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <h4 className="text-[10px] font-bold font-headline text-tertiary uppercase tracking-widest flex items-center gap-1">
                        <span className="material-symbols-outlined text-xs">menu_book</span>
                        Journal CVE
                      </h4>
                      <Link
                        to="/cve-journal"
                        className="text-[10px] text-primary hover:underline shrink-0"
                      >
                        Ouvrir le journal →
                      </Link>
                    </div>
                    {chefPolicyVersion ? (
                      <div className="space-y-1">
                        <p className="text-sm text-on-surface">
                          Version officielle (chef) :{" "}
                          <span className="font-mono font-bold text-tertiary">{chefPolicyVersion}</span>
                        </p>
                        {chefPolicyMeta?.officialUpdatedBy && (
                          <p className="text-[10px] text-outline">
                            définie par {chefPolicyMeta.officialUpdatedBy}
                          </p>
                        )}
                        {chefPolicyMeta?.officialComment && (
                          <p className="text-xs text-on-surface-variant italic line-clamp-2">
                            « {chefPolicyMeta.officialComment} »
                          </p>
                        )}
                        <p className="text-[10px] text-tertiary/80">
                          L’autofix utilise cette version en priorité sur Fixed In.
                        </p>
                      </div>
                    ) : (
                      <p className="text-xs text-on-surface-variant">
                        Aucune version officielle.{" "}
                        <Link to="/cve-journal" className="text-primary hover:underline">
                          Définir dans le Journal CVE
                        </Link>
                      </p>
                    )}
                    {(journalRecLoading || journalRecommendation?.recommendedVersion) && (
                      <div className="rounded-lg bg-surface-container-high px-2.5 py-2 space-y-1">
                        <p className="text-[10px] uppercase tracking-wider text-outline">
                          Recommandation IA {journalRecommendation?.source === "LLM" ? `(${journalRecommendation.aiProvider || "IA"})` : ""}
                        </p>
                        {journalRecLoading ? (
                          <p className="text-[11px] text-outline flex items-center gap-1">
                            <span className="material-symbols-outlined text-sm animate-spin">progress_activity</span>
                            Analyse…
                          </p>
                        ) : journalRecommendation?.recommendedVersion ? (
                          <>
                            <p className="text-sm">
                              <span className="font-mono font-bold text-primary">
                                {journalRecommendation.recommendedVersion}
                              </span>
                              {chefPolicyVersion
                                && chefPolicyVersion !== journalRecommendation.recommendedVersion && (
                                <span className="text-[10px] text-amber-400 ml-2">
                                  (différente de la politique chef)
                                </span>
                              )}
                            </p>
                            {journalRecommendation.rationale && (
                              <p className="text-[11px] text-on-surface-variant line-clamp-3">
                                {journalRecommendation.rationale}
                              </p>
                            )}
                          </>
                        ) : journalRecommendation?.aiError ? (
                          <p className="text-[11px] text-error">{journalRecommendation.aiError}</p>
                        ) : null}
                      </div>
                    )}
                  </div>
                )}

                {/* Q3 — Action Recommandée pour TOUS les CVEs */}
                <div className="space-y-2 rounded-xl bg-primary/5 border border-primary/15 p-3">
                  <h4 className="text-[10px] font-bold font-headline text-primary/70 uppercase tracking-widest flex items-center gap-1">
                    <span className="material-symbols-outlined text-xs">bolt</span>
                    Action Recommandée
                  </h4>
                  <div className="text-sm text-on-surface-variant leading-relaxed">
                    {isPackageBased ? (
                      <RemediationPlanView
                        cve={selected}
                        fixVersion={chefPolicyVersion
                          || pickPreferredFixVersion(parseFixedVersionList(selected.fixedVersion), selected.packageVersion)
                          || selected.fixedVersion?.split(/[,;|/]/)[0].trim()
                          || null}
                      />
                    ) : (
                      <CodeFixView
                        cve={selected}
                        fallback={(() => {
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
                      />
                    )}
                  </div>
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
                    <h4 className="text-[10px] font-bold font-headline text-slate-400 uppercase tracking-widest">PoC public (Exploit-DB)</h4>
                    <a
                      href={selected.exploitUrl || `https://www.exploit-db.com/search?cve=${selected.cveId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-error/10 border border-error/20 text-error text-xs font-semibold hover:bg-error/20 transition-colors w-full"
                    >
                      <span className="material-symbols-outlined text-sm">bug_report</span>
                      Voir le PoC sur Exploit-DB
                      <span className="material-symbols-outlined text-xs ml-auto">open_in_new</span>
                    </a>
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                      Quelqu'un a publié un code d'attaque (preuve de concept). Ça ne veut pas dire que la faille est déjà exploitée en production — ça, c'est uniquement le badge KEV.
                      {(selected.severity || selected.epssScore != null) ? ` Ici : ${selected.severity || '—'} = impact CVSS${selected.cvssScore != null ? ` ${selected.cvssScore.toFixed(1)}` : ''}${selected.epssScore != null ? ` · EPSS ${(selected.epssScore * 100).toFixed(1)}% = faible probabilité d'exploitation dans les 30 jours` : ''}.` : ''}
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
                {!selected.kevListed && (
                  <div className="space-y-2">
                    <h4 className="text-[10px] font-bold font-headline text-slate-400 uppercase tracking-widest">CISA KEV</h4>
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                      Pas dans le catalogue CISA KEV — CISA n'a pas confirmé d'exploitation active. {selected.exploitAvailable ? 'Un PoC public (Exploit-DB) n\'est pas une attaque en cours. ' : ''}MEDIUM / HIGH / CRITICAL = impact CVSS, pas « déjà exploitée ».
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

                {/* ── Composant vulnérable (SBOM enrichment) ── */}
                {(selected.componentName || selected.directOrTransitive || selected.purl || selected.ecosystem) && (
                  <div className="space-y-2">
                    <h4 className="text-[10px] font-bold font-headline text-slate-400 uppercase tracking-widest">Composant vulnérable</h4>

                    {/* Direct / Transitive / Unknown badge */}
                    <div className="flex flex-wrap gap-2 items-center">
                      {selected.directOrTransitive === 'DIRECT' && (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-primary/20 text-primary border border-primary/30">
                          <span className="material-symbols-outlined text-[11px]">link</span>
                          Dépendance directe
                        </span>
                      )}
                      {selected.directOrTransitive === 'TRANSITIVE' && (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-secondary/20 text-secondary border border-secondary/30"
                          style={{ color: '#d1bcff', borderColor: 'rgba(209,188,255,0.3)', backgroundColor: 'rgba(209,188,255,0.12)' }}>
                          <span className="material-symbols-outlined text-[11px]">account_tree</span>
                          Dépendance transitive
                        </span>
                      )}
                      {(!selected.directOrTransitive || selected.directOrTransitive === 'UNKNOWN') && (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-surface-container-high text-outline border border-outline-variant/30">
                          <span className="material-symbols-outlined text-[11px]">help_outline</span>
                          Relation inconnue
                        </span>
                      )}
                      {selected.dependencyDepth != null && selected.dependencyDepth > 0 && (
                        <span className="text-[10px] text-outline">profondeur {selected.dependencyDepth}</span>
                      )}
                    </div>

                    {/* Low confidence warning */}
                    {selected.dependencyConfidence === 'LOW' && (
                      <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-700">
                        <span className="material-symbols-outlined text-sm text-amber-500 shrink-0 mt-0.5">info</span>
                        Relation déduite avec faible confiance — SBOM absent ou composant non résolu dans le graphe.
                      </div>
                    )}

                    {/* Dependency path */}
                    {selected.dependencyPath && (
                      <div className="px-3 py-2 rounded-lg bg-surface-container-highest border border-outline-variant/[0.15]">
                        <p className="text-[10px] text-outline uppercase font-bold mb-1">Chemin de dépendance</p>
                        <p className="text-xs font-mono text-on-surface-variant break-all">{selected.dependencyPath}</p>
                      </div>
                    )}

                    {/* Details grid */}
                    <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs px-1">
                      {selected.codeUsage && selected.codeUsage !== 'UNKNOWN' && (
                        <>
                          <span className="text-outline">Usage dans le code</span>
                          <span
                            className={`font-semibold ${selected.codeUsage === 'YES' ? 'text-orange-300' : 'text-on-surface-variant'}`}
                            title={selected.usageFiles?.join(', ')}
                          >
                            {selected.codeUsage === 'YES' ? 'Importé' : selected.codeUsage === 'TEST_ONLY' ? 'Tests seulement' : 'Aucun import'}
                            {selected.usageFiles?.length ? ` · ${selected.usageFiles[0]}` : ''}
                          </span>
                        </>
                      )}
                      {selected.componentName && (
                        <>
                          <span className="text-outline">Composant</span>
                          <span className="text-on-surface-variant font-mono truncate" title={selected.componentName}>
                            {selected.componentName}{selected.componentVersion ? `@${selected.componentVersion}` : ''}
                          </span>
                        </>
                      )}
                      {selected.ecosystem && (
                        <>
                          <span className="text-outline">Écosystème</span>
                          <span className="text-on-surface-variant">{selected.ecosystem}</span>
                        </>
                      )}
                      {selected.packageManager && (
                        <>
                          <span className="text-outline">Gestionnaire</span>
                          <span className="text-on-surface-variant">{selected.packageManager}</span>
                        </>
                      )}
                      {selected.moduleName && (
                        <>
                          <span className="text-outline">Module</span>
                          <span className="text-on-surface-variant font-mono truncate" title={selected.moduleName}>{selected.moduleName}</span>
                        </>
                      )}
                      {selected.manifestFile && (
                        <>
                          <span className="text-outline">Manifeste</span>
                          <span className="text-on-surface-variant font-mono text-[10px] truncate" title={selected.manifestFile}>{selected.manifestFile}</span>
                        </>
                      )}
                      {selected.dependencyScope && selected.dependencyScope !== 'unknown' && (
                        <>
                          <span className="text-outline">Scope</span>
                          <span className="text-on-surface-variant">{selected.dependencyScope}</span>
                        </>
                      )}
                      {selected.dependencyConfidence && (
                        <>
                          <span className="text-outline">Confiance</span>
                          <span className={`font-semibold ${
                            selected.dependencyConfidence === 'HIGH' ? 'text-teal-400' :
                            selected.dependencyConfidence === 'MEDIUM' ? 'text-amber-400' :
                            'text-outline'
                          }`}>{selected.dependencyConfidence}</span>
                        </>
                      )}
                    </div>

                    {/* PURL */}
                    {selected.purl && (
                      <div className="px-3 py-2 rounded-lg bg-surface-container-highest border border-outline-variant/[0.15] mt-1">
                        <p className="text-[10px] text-outline uppercase font-bold mb-0.5">Package URL (PURL)</p>
                        <p className="text-[10px] font-mono text-on-surface-variant break-all">{selected.purl}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* ── Auto-fix button ── dependency CVEs with Fixed In OR chef policy */}
                {isPackageBased && (selected.fixedVersion || chefPolicyVersion) && extractRepoFullName(currentScan?.repoUrl ?? '', currentScan?.gitProvider) && (
                  <div className="space-y-2 pt-1">
                    <h4 className="text-[10px] font-bold font-headline text-slate-400 uppercase tracking-widest">Correctif automatique</h4>
                    {chefPolicyVersion && (
                      <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-tertiary/10 border border-tertiary/25 text-xs text-tertiary">
                        <span className="material-symbols-outlined text-sm shrink-0">verified</span>
                        <span>
                          Cible autofix : <span className="font-mono font-bold">{chefPolicyVersion}</span> (politique Journal CVE)
                        </span>
                      </div>
                    )}
                    {groupCount > 1 && (
                      <div className="flex items-start gap-2 px-3 py-2.5 rounded-lg bg-primary/10 border border-primary/20 text-xs">
                        <span className="material-symbols-outlined text-sm text-primary shrink-0 mt-0.5">auto_awesome</span>
                        <div>
                          <p className="font-semibold text-primary">Même paquet — {groupCount} failles distinctes</p>
                          <p className="text-slate-500 mt-0.5 leading-relaxed">
                            Un bump de version corrige aussi : {selectedGroup.filter(c => c.id !== selected.id).map(c => c.canonicalId || c.cveId).join(', ')}
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
                    {applySuccess && !applySuccess.startsWith('http') && !fixedCveIds.has(selected.id) && (
                      <div className="flex items-start gap-2 px-3 py-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs">
                        <span className="material-symbols-outlined text-sm shrink-0 mt-0.5">hourglass_top</span>
                        <span className="break-words">{applySuccess}</span>
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
        const diff = computeDiff(fixPreview.originalLines, activeFixedLines);
        const changedCount = diff.filter(l => l.type !== 'unchanged').length;

        // Live counters taking the user's inline edits into account.
        const editedAddedCount = diff.filter((l, i) => l.type === 'added'   && !fixDeletedAdds.has(i)).length;
        const keptRemovedCount = diff.filter((l, i) => l.type === 'removed' && fixRestoredRemovals.has(i)).length;
        const editedLinesCount = Object.keys(fixLineEdits).length;
        const human = fixPreview.humanKnowledge;
        const advice = fixPreview.llmAdvice;

        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <div className="w-full max-w-4xl max-h-[90vh] flex flex-col glass-panel rounded-2xl border border-outline-variant/[0.2] shadow-2xl overflow-hidden">

              {/* Modal header */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-outline-variant/[0.1] bg-surface-container-highest/40 shrink-0">
                <div className="flex items-center gap-3">
                  <span className="material-symbols-outlined text-primary">auto_fix_high</span>
                  <div>
                    <p className="font-bold font-headline text-on-surface text-sm">Correctif automatique — {fixPreview.filePath}</p>
                    <p className="text-[10px] text-slate-500">
                      {changedCount} ligne(s) modifiée(s) · {fixPreview.repoFullName}
                      {fixHasEdits && <span className="text-amber-400 font-semibold"> · modifié par vous</span>}
                    </p>
                    {(chefPolicyVersion || fixPreview.officialStableVersion) && (
                      <p className="text-[10px] text-tertiary mt-0.5">
                        Politique Journal CVE :{" "}
                        <span className="font-mono font-bold">
                          {chefPolicyVersion || fixPreview.officialStableVersion}
                        </span>
                      </p>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => { setFixPreview(null); setApplySuccess(null); setFixError(null); setApplyError(null); setFixLineEdits({}); setFixDeletedAdds(new Set()); setFixRestoredRemovals(new Set()); setFixChoice('AI'); setFixReason(''); setShowReasonModal(false); }}
                  className="p-1.5 rounded-lg hover:bg-surface-container-high transition-colors text-outline hover:text-on-surface"
                >
                  <span className="material-symbols-outlined text-lg">close</span>
                </button>
              </div>

              {/* Assisted-fix agent: AI vs human memory */}
              {applySuccess ? null : fixPreview.hasHumanKnowledge && human ? (
                <div className="px-6 py-3 border-b border-outline-variant/[0.08] bg-surface-container-lowest/40 shrink-0 space-y-3">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <button
                      type="button"
                      onClick={() => selectFixChoice('AI')}
                      className={`text-left rounded-xl border px-3 py-2.5 transition-all ${
                        fixChoice === 'AI'
                          ? 'border-primary/50 bg-primary/10'
                          : 'border-outline-variant/20 bg-surface-container-high/40 hover:border-outline-variant/40'
                      }`}
                    >
                      <p className="text-[11px] font-bold text-primary">Suggestion IA / moteur</p>
                      <p className="text-[10px] text-on-surface-variant mt-1">
                        Correctif calculé maintenant pour ce scan.
                      </p>
                    </button>
                    <button
                      type="button"
                      onClick={() => selectFixChoice('HUMAN')}
                      className={`text-left rounded-xl border px-3 py-2.5 transition-all ${
                        fixChoice === 'HUMAN'
                          ? 'border-tertiary/50 bg-tertiary/10'
                          : 'border-outline-variant/20 bg-surface-container-high/40 hover:border-outline-variant/40'
                      }`}
                    >
                      <p className="text-[11px] font-bold text-tertiary">Correction connue (humain)</p>
                      <p className="text-[10px] text-on-surface-variant mt-1">
                        {human.toVersion ? `Version ${human.toVersion}` : 'Version mémorisée'}
                        {human.createdByLogin ? ` · ${human.createdByLogin}` : ''}
                      </p>
                      <p className="text-[10px] text-amber-200/90 mt-1 line-clamp-2">
                        « {human.reason} »
                      </p>
                      <p className="text-[9px] text-slate-500 mt-1">
                        Succès: {human.successCount} · Utilisé: {human.usageCount}
                      </p>
                    </button>
                  </div>
                  {advice && (
                    <div className="rounded-xl border border-primary/25 bg-primary/5 px-3 py-2 text-[10px] text-on-surface-variant space-y-1">
                      <p className="font-semibold text-primary flex items-center gap-1.5">
                        <span className="material-symbols-outlined text-sm">smart_toy</span>
                        Avis agent LLM
                        {advice.recommendation && (
                          <span className="ml-1 px-1.5 py-0.5 rounded bg-primary/15 text-primary font-bold">
                            {advice.recommendation === 'HUMAN' ? '→ Humain' : advice.recommendation === 'AI' ? '→ IA' : '→ À revoir'}
                          </span>
                        )}
                        {typeof advice.confidence === 'number' && (
                          <span className="text-slate-500 font-normal">
                            ({Math.round(advice.confidence * 100)}%)
                          </span>
                        )}
                      </p>
                      <p className="text-on-surface">{advice.summary}</p>
                      <p>{advice.why}</p>
                      {advice.risks && <p className="text-amber-300/90">Risques : {advice.risks}</p>}
                    </div>
                  )}
                </div>
              ) : applySuccess ? null : (
                <div className="px-6 py-2 border-b border-outline-variant/[0.08] bg-surface-container-lowest/30 shrink-0">
                  <p className="text-[10px] text-slate-500">
                    Aucune correction humaine mémorisée pour ce CVE/package. Si vous modifiez le diff, indiquez pourquoi — l’agent s’en souviendra.
                  </p>
                </div>
              )}

              {/* Diff legend + inline-edit notice */}
              <div className="flex flex-wrap items-center gap-4 px-6 py-2 border-b border-outline-variant/[0.08] bg-surface-container-lowest/60 shrink-0">
                <div className="flex gap-1.5 items-center text-[10px] text-red-400"><span className="w-3 h-3 rounded-sm bg-red-500/20 border border-red-500/40 inline-block" /> Supprimé</div>
                <div className="flex gap-1.5 items-center text-[10px] text-emerald-400"><span className="w-3 h-3 rounded-sm bg-emerald-500/20 border border-emerald-500/40 inline-block" /> Ajouté</div>
                <div className="flex gap-1.5 items-center text-[10px] text-slate-500"><span className="w-3 h-3 rounded-sm bg-surface-container-highest inline-block border border-outline-variant/20" /> Inchangé</div>
                <span className="ml-auto text-[10px] text-slate-500">{diff.filter(l => l.type === 'removed').length} suppression(s) · {editedAddedCount} ajout(s)</span>
              </div>
              {/* Inline edit instructions */}
              {applySuccess ? null : (
                <div className="flex items-center gap-2 px-6 py-2 border-b border-outline-variant/[0.08] bg-amber-500/5 shrink-0">
                  <span className="material-symbols-outlined text-amber-400 text-sm">edit_note</span>
                  <p className="text-[10px] text-amber-300">
                    Vous pouvez <span className="font-semibold">modifier les lignes ajoutées (+) par l'IA</span> directement, <span className="font-semibold">supprimer</span> une ligne ajoutée, ou <span className="font-semibold">restaurer</span> une ligne supprimée si l'IA s'est trompée.
                  </p>
                </div>
              )}
              {fixPreview.lockFilePath && (
                <div className="flex items-center gap-2 px-6 py-2 border-b border-outline-variant/[0.08] bg-teal-500/5 shrink-0">
                  <span className="material-symbols-outlined text-teal-400 text-sm">lock</span>
                  <p className="text-[10px] text-teal-300">
                    <span className="font-semibold">Lock file automatiquement patché :</span>{' '}
                    <span className="font-mono">{fixPreview.lockFilePath}</span> sera aussi mis à jour — le prochain scan ne détectera plus ce CVE.
                  </p>
                </div>
              )}

              {/* Diff viewer — inline editable */}
              <div className="flex-1 overflow-y-auto custom-scrollbar font-mono text-xs bg-surface-container-lowest/80">
                {diff.map((line, i) => {
                  const isEditedAdded   = line.type === 'added'   && fixDeletedAdds.has(i);
                  const isRestoredRemoval = line.type === 'removed' && fixRestoredRemovals.has(i);
                  const rowBg =
                    isEditedAdded     ? 'bg-amber-500/[0.07] line-through opacity-60' :
                    isRestoredRemoval ? 'bg-primary/[0.06]' :
                    line.type === 'removed' ? 'bg-red-500/[0.08]' :
                    line.type === 'added'   ? 'bg-emerald-500/[0.08]' : '';
                  const sign =
                    line.type === 'removed' ? (isRestoredRemoval ? '±' : '−') :
                    line.type === 'added'   ? (isEditedAdded ? '×' : '+') : ' ';
                  const signColor =
                    line.type === 'removed' ? 'text-red-400' :
                    line.type === 'added'   ? 'text-emerald-400' : 'text-slate-700';
                  return (
                    <div
                      key={i}
                      className={`flex items-start gap-0 border-b border-outline-variant/[0.04] group ${rowBg}`}
                    >
                      {/* Gutter: line number + sign */}
                      <span className="shrink-0 w-10 py-1 px-2 text-right text-slate-600 text-[10px] select-none border-r border-outline-variant/[0.08]">
                        {line.lineNo}
                      </span>
                      <span className={`shrink-0 w-6 py-1 text-center select-none font-bold text-sm ${signColor}`}>
                        {sign}
                      </span>

                      {/* Line content — editable only for added/removed lines, and only before the fix is applied */}
                      {applySuccess ? (
                        <span className={`flex-1 py-1 pl-2 pr-4 whitespace-pre-wrap break-all leading-relaxed ${
                          line.type === 'removed' ? 'text-red-300' :
                          line.type === 'added'   ? 'text-emerald-300' : 'text-on-surface-variant'
                        }`}>
                          {line.line}
                        </span>
                      ) : line.type === 'added' ? (
                        isEditedAdded ? (
                          <span className="flex-1 py-1 pl-2 pr-4 text-amber-400 italic text-[11px] flex items-center gap-2">
                            <span className="material-symbols-outlined text-xs">remove_circle_outline</span>
                            ligne supprimée par vous (ne sera pas appliquée)
                          </span>
                        ) : (
                          <input
                            type="text"
                            value={fixLineEdits[i] ?? line.line}
                            onChange={(e) => setFixLineEdits(prev => ({ ...prev, [i]: e.target.value }))}
                            spellCheck={false}
                            className="flex-1 py-1 pl-2 pr-4 bg-transparent text-emerald-200 whitespace-pre-wrap break-all leading-relaxed outline-none focus:bg-emerald-500/10 focus:ring-1 focus:ring-emerald-400/40 rounded-r"
                            title="Cliquez pour modifier la ligne suggérée par l'IA"
                          />
                        )
                      ) : line.type === 'removed' ? (
                        <span className={`flex-1 py-1 pl-2 pr-4 whitespace-pre-wrap break-all leading-relaxed ${
                          isRestoredRemoval ? 'text-emerald-300' : 'text-red-300'
                        }`}>
                          {isRestoredRemoval
                            ? <><span className="material-symbols-outlined text-xs align-middle mr-1">add_circle_outline</span>{line.line} <span className="text-[10px] text-primary italic">(restaurée par vous)</span></>
                            : line.line}
                        </span>
                      ) : (
                        <span className="flex-1 py-1 pl-2 pr-4 whitespace-pre-wrap break-all leading-relaxed text-on-surface-variant">
                          {line.line}
                        </span>
                      )}

                      {/* Per-line edit actions */}
                      {applySuccess ? null : line.type === 'added' ? (
                        <button
                          onClick={() => {
                            if (isEditedAdded) {
                              setFixDeletedAdds(prev => { const n = new Set(prev); n.delete(i); return n; });
                              setFixLineEdits(prev => { const n = { ...prev }; delete n[i]; return n; });
                            } else {
                              setFixDeletedAdds(prev => new Set(prev).add(i));
                            }
                          }}
                          title={isEditedAdded ? "Restaurer cette ligne" : "Supprimer cette ligne ajoutée"}
                          className="shrink-0 px-2 py-1 text-outline opacity-0 group-hover:opacity-100 hover:text-amber-400 transition-opacity"
                        >
                          <span className="material-symbols-outlined text-sm">{isEditedAdded ? 'undo' : 'delete'}</span>
                        </button>
                      ) : line.type === 'removed' ? (
                        <button
                          onClick={() => {
                            if (isRestoredRemoval) {
                              setFixRestoredRemovals(prev => { const n = new Set(prev); n.delete(i); return n; });
                            } else {
                              setFixRestoredRemovals(prev => new Set(prev).add(i));
                            }
                          }}
                          title={isRestoredRemoval ? "Supprimer à nouveau cette ligne" : "Restaurer cette ligne supprimée par l'IA"}
                          className="shrink-0 px-2 py-1 text-outline opacity-0 group-hover:opacity-100 hover:text-emerald-400 transition-opacity"
                        >
                          <span className="material-symbols-outlined text-sm">{isRestoredRemoval ? 'undo' : 'restore'}</span>
                        </button>
                      ) : null}
                    </div>
                  );
                })}
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
                          {knowledgeSavedNote && (
                            <p className="text-[10px] text-amber-300 mt-1 ml-6">
                              Correction mémorisée pour l’agent — elle apparaîtra sur les autres scans avec ce CVE/package.
                            </p>
                          )}
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
                      onClick={() => { setFixPreview(null); setFixError(null); setApplyError(null); setFixLineEdits({}); setFixDeletedAdds(new Set()); setFixRestoredRemovals(new Set()); setFixChoice('AI'); setFixReason(''); setShowReasonModal(false); }}
                      className="px-4 py-2 rounded-xl text-sm text-outline hover:text-on-surface hover:bg-surface-container-high transition-all"
                    >
                      Annuler
                    </button>
                    {fixHasEdits && (
                      <button
                        onClick={() => { setFixLineEdits({}); setFixDeletedAdds(new Set()); setFixRestoredRemovals(new Set()); }}
                        title="Revenir à la suggestion de l'IA"
                        className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs text-amber-400 border border-amber-500/30 bg-amber-500/10 hover:bg-amber-500/20 transition-all"
                      >
                        <span className="material-symbols-outlined text-sm">restart_alt</span>
                        Réinitialiser mes modifs
                      </button>
                    )}
                    <div className="flex-1 text-xs text-slate-500 text-center min-w-0">
                      {applyError ? (
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-error/10 border border-error/30 text-error text-xs text-left">
                          <span className="material-symbols-outlined text-sm shrink-0">error</span>
                          <span className="break-words">{applyError}</span>
                        </div>
                      ) : (
                        <>
                          <div className="truncate">
                            Fichier : <span className="text-primary font-mono">{fixPreview.filePath}</span> · Dépôt : <span className="text-primary">{fixPreview.repoFullName}</span>
                          </div>
                          {fixHasEdits && (
                            <div className="text-[10px] text-amber-400 font-semibold mt-0.5">
                              {editedLinesCount > 0 && `${editedLinesCount} ligne(s) modifiée(s)`}
                              {editedLinesCount > 0 && (fixDeletedAdds.size > 0 || keptRemovedCount > 0) ? ' · ' : ''}
                              {fixDeletedAdds.size > 0 && `${fixDeletedAdds.size} supprimée(s)`}
                              {fixDeletedAdds.size > 0 && keptRemovedCount > 0 ? ' · ' : ''}
                              {keptRemovedCount > 0 && `${keptRemovedCount} restaurée(s)`}
                            </div>
                          )}
                        </>
                      )}
                    </div>
                    <button
                      onClick={handleApplyFix}
                      disabled={applyLoading || versionCheckLoading || changedCount === 0}
                      className="flex items-center gap-2 px-5 py-2 rounded-xl bg-tertiary text-on-tertiary text-sm font-bold hover:opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {applyLoading || versionCheckLoading
                        ? <><span className="material-symbols-outlined text-sm animate-spin">progress_activity</span> {versionCheckLoading ? 'Vérification version…' : 'Application...'}</>
                        : <><span className="material-symbols-outlined text-sm">commit</span>{
                            fixHasEdits
                              ? 'Appliquer ma version'
                              : fixChoice === 'HUMAN'
                                ? 'Appliquer version humaine'
                                : 'Appliquer le commit'
                          }</>
                      }
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Double vérification version (après édition manuelle) */}
      {showVersionCheckModal && versionCheck && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-2xl border border-outline-variant/30 bg-surface-container p-5 space-y-4 shadow-2xl">
            <div className="flex items-start gap-3">
              <span className={`material-symbols-outlined ${
                versionCheck.verdict === 'RISKY' ? 'text-error' :
                versionCheck.verdict === 'OK' ? 'text-tertiary' : 'text-amber-400'
              }`}>
                {versionCheck.verdict === 'RISKY' ? 'warning' : versionCheck.verdict === 'OK' ? 'verified' : 'help'}
              </span>
              <div className="min-w-0">
                <h3 className="font-headline font-bold text-on-surface text-base">
                  {versionCheck.title || 'Double vérification de version'}
                </h3>
                <p className="text-xs text-on-surface-variant mt-1">
                  Vérification par rapport à la liste Fixed In de ce CVE (et à votre branche actuelle).
                </p>
              </div>
            </div>

            <div className={`rounded-xl border px-3 py-2 text-xs space-y-1 ${
              versionCheck.verdict === 'RISKY'
                ? 'border-error/40 bg-error/10 text-error'
                : versionCheck.verdict === 'OK'
                  ? 'border-tertiary/40 bg-tertiary/10 text-tertiary'
                  : 'border-amber-500/40 bg-amber-500/10 text-amber-200'
            }`}>
              <p className="font-bold">
                Verdict : {versionCheck.verdict}
                {versionCheck.riskLevel ? ` · risque ${versionCheck.riskLevel}` : ''}
              </p>
              <p className="text-on-surface">{versionCheck.summary}</p>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div className="rounded-lg bg-surface-container-high px-3 py-2">
                <p className="text-outline uppercase tracking-wider text-[9px]">Version choisie</p>
                <p className="font-mono text-on-surface mt-0.5 text-sm font-bold">
                  {versionCheck.chosenVersion || '—'}
                </p>
              </div>
              <div className="rounded-lg bg-surface-container-high px-3 py-2">
                <p className="text-outline uppercase tracking-wider text-[9px]">
                  {chefPolicyVersion || fixPreview?.officialStableVersion
                    ? 'Version chef (politique)'
                    : 'Version idéale (votre branche)'}
                </p>
                <p className="font-mono text-on-surface mt-0.5 text-sm font-bold">
                  {versionCheck.recommendedVersion || '—'}
                </p>
              </div>
            </div>

            {versionCheck.details?.some(d => d.toLowerCase().includes('fixed in')) && (
              <p className="text-[10px] text-emerald-300/90">
                {versionCheck.details.find(d => d.toLowerCase().includes('fixed in'))}
              </p>
            )}

            {versionCheck.currentVersion && (
              <p className="text-[10px] text-slate-500">
                Version vulnérable actuelle : <span className="font-mono text-on-surface">{versionCheck.currentVersion}</span>
              </p>
            )}

            {versionCheck.verdict === 'RISKY' && (
              <div className="rounded-lg border border-error/30 bg-error/5 px-3 py-2 text-[11px] text-error">
                ⚠ Warning : cette version peut encore être vulnérable. Acceptez seulement si vous avez une raison métier.
              </div>
            )}

            {!!versionCheck.details?.length && (
              <ul className="text-[11px] text-on-surface-variant space-y-1 list-disc pl-4">
                {versionCheck.details.map((d, i) => <li key={i}>{d}</li>)}
              </ul>
            )}
            {versionCheck.advice && (
              <p className="text-[11px] text-primary">Conseil : {versionCheck.advice}</p>
            )}

            <div className="flex flex-wrap justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => { setShowVersionCheckModal(false); setVersionCheck(null); }}
                className="px-4 py-2 rounded-xl text-sm text-outline hover:text-on-surface"
              >
                Modifier la version
              </button>
              <button
                type="button"
                onClick={() => {
                  const risky = versionCheck.verdict === 'RISKY'
                    || (versionCheck.title || '').toLowerCase().includes('écart')
                    || (versionCheck.title || '').toLowerCase().includes('politique');
                  setPendingRiskAccepted(risky);
                  setShowVersionCheckModal(false);
                  setShowReasonModal(true);
                }}
                className={`px-4 py-2 rounded-xl text-sm font-bold ${
                  versionCheck.verdict === 'RISKY'
                    ? 'bg-error text-on-error'
                    : 'bg-tertiary text-on-tertiary'
                }`}
              >
                {versionCheck.verdict === 'RISKY'
                  ? 'J’accepte le risque, continuer'
                  : 'Accepter et continuer'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reason modal — agent memory AND/OR policy deviation (chef approval) */}
      {showReasonModal && fixPreview && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-2xl border border-outline-variant/30 bg-surface-container p-5 space-y-4 shadow-2xl">
            <div className="flex items-start gap-3">
              <span className="material-symbols-outlined text-amber-400">
                {pendingRiskAccepted ? 'gavel' : 'psychology'}
              </span>
              <div>
                <h3 className="font-headline font-bold text-on-surface text-base">
                  {pendingRiskAccepted
                    ? 'Motif de dérogation (validation chef)'
                    : 'Pourquoi cette correction ?'}
                </h3>
                <p className="text-xs text-on-surface-variant mt-1">
                  {pendingRiskAccepted
                    ? 'Votre version diffère de la politique chef. Indiquez le motif : une notification sera envoyée aux comptes Journal CVE. Si un chef accepte, le commit partira automatiquement avec VOTRE compte Git.'
                    : 'Obligatoire pour mémoriser. Ensuite l’agent affichera votre version + ce motif à côté de la suggestion IA.'}
                </p>
              </div>
            </div>
            {!pendingRiskAccepted && (
              <label className="flex items-center gap-2 text-xs text-on-surface-variant">
                <input
                  type="checkbox"
                  checked={memorizeFix}
                  onChange={(e) => setMemorizeFix(e.target.checked)}
                  className="rounded border-outline-variant"
                />
                Mémoriser pour l’agent (recommandé)
              </label>
            )}
            <textarea
              value={fixReason}
              onChange={(e) => setFixReason(e.target.value)}
              rows={4}
              placeholder={
                pendingRiskAccepted
                  ? 'Ex. : 4.0.10 requise pour compatibilité module X validée en staging…'
                  : 'Ex. : version 6.2.18 validée en staging ; 6.2.17 cassait les tests…'
              }
              className="w-full rounded-xl border border-outline-variant/25 bg-surface-container-high px-3 py-2 text-sm text-on-surface outline-none focus:border-primary/50"
            />
            {applyError && (
              <p className="text-xs text-error">{applyError}</p>
            )}
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowReasonModal(false)}
                className="px-4 py-2 rounded-xl text-sm text-outline hover:text-on-surface"
                disabled={applyLoading}
              >
                Retour
              </button>
              <button
                type="button"
                disabled={
                  applyLoading
                  || !fixReason.trim()
                  || (!pendingRiskAccepted && memorizeFix && !fixReason.trim())
                }
                onClick={() => {
                  if (!fixReason.trim()) return;
                  void doApplyFix(fixReason);
                }}
                className={`px-4 py-2 rounded-xl text-sm font-bold disabled:opacity-50 ${
                  pendingRiskAccepted
                    ? 'bg-error text-on-error'
                    : 'bg-tertiary text-on-tertiary'
                }`}
              >
                {applyLoading
                  ? 'Envoi…'
                  : pendingRiskAccepted
                    ? 'Envoyer aux chefs (pas de commit immédiat)'
                    : 'Enregistrer & committer'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Vulnerabilities;

