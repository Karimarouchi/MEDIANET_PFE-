import type { SslResultDto } from '../services/api';

export type HeaderBadge =
  | 'conforme'
  | 'partiel'
  | 'observation'
  | 'a_corriger'
  | 'recommande'
  | 'contextuel'
  | 'non_requis'
  | 'non_teste'
  | 'non_detecte'
  | 'presence_nc';

export type HeaderPriority = 'critique' | 'haute' | 'moyenne' | 'basse' | 'contextuelle';
export type HeaderKind = 'main' | 'contextual';
export type HeaderRequirement = 'obligatoire' | 'recommande' | 'contextuel';

export type HeaderPresentation = {
  id: string;
  kind: HeaderKind;
  name: string;
  abbr: string;
  icon: string;
  utility: string;
  badge: HeaderBadge;
  statusLabel: string;
  shortValue: string | null;
  conclusion?: string;
  priority: HeaderPriority;
  requirement: HeaderRequirement;
  observedValue: string | null;
  headerName: string;
  role: string;
  risk: string;
  when: string;
  impact: string;
  recommendation: string;
  nginx: string;
  apache: string;
  verifyCommand: string;
  configPathHint: string;
  reloadCommand: { nginx: string; apache: string };
  details: Record<string, string | string[] | boolean | null | undefined>;
  scoreMax: number;
  scoreEarned: number;
};

export type HeadersSummary = {
  mainScore: number; // /100
  categoryScore: number; // /20 for global grade
  conformes: number;
  partielles: number;
  observations: number;
  contextuelles: number;
  nonTestees: number;
  isolationLabel: string;
  primaryPriority: string;
  conclusion: string;
  items: HeaderPresentation[];
  mainItems: HeaderPresentation[];
  contextualItems: HeaderPresentation[];
};

const BADGE_LABEL: Record<HeaderBadge, string> = {
  conforme: 'Conforme',
  partiel: 'Partiel',
  observation: 'Mode observation',
  a_corriger: 'À corriger',
  recommande: 'Recommandé',
  contextuel: 'Contextuel',
  non_requis: 'Non requis',
  non_teste: 'Non testé',
  non_detecte: 'Non détecté',
  presence_nc: 'Présence non confirmée',
};

export function badgeLabel(b: HeaderBadge) {
  return BADGE_LABEL[b];
}

function parseMaxAge(hsts?: string | null): number | null {
  if (!hsts) return null;
  const m = hsts.match(/max-age\s*=\s*(\d+)/i);
  return m ? Number(m[1]) : null;
}

function cspHasFrameAncestors(csp?: string | null): boolean {
  if (!csp) return false;
  return /frame-ancestors\b/i.test(csp);
}

function analyzeCsp(value: string | null, enforced: boolean, reportOnly: boolean) {
  const flags: string[] = [];
  if (!value) return { flags, weak: false };
  const v = value.toLowerCase();
  if (v.includes("'unsafe-inline'")) flags.push("Présence de 'unsafe-inline'");
  if (v.includes("'unsafe-eval'")) flags.push("Présence de 'unsafe-eval'");
  if (/\*\s*;|\*\s*$|^\s*\*/.test(v) || v.includes(' * ') || v.includes(" *")) flags.push('Wildcard * détecté');
  if (/https:\s*(;|$)/.test(v)) flags.push('Source trop large https:');
  if (!/object-src\b/i.test(value)) flags.push('object-src absent');
  if (!/base-uri\b/i.test(value)) flags.push('base-uri absent');
  if (!/frame-ancestors\b/i.test(value)) flags.push('frame-ancestors absent');
  if (!/report-to\b|report-uri\b/i.test(value)) flags.push('Endpoint de rapport absent');
  return { flags, weak: flags.length >= 3 && enforced };
}

function parsePermissions(value: string | null): { feature: string; state: string }[] {
  if (!value) return [];
  return value.split(',').map(part => {
    const t = part.trim();
    const m = t.match(/^([^=]+)=\s*(.*)$/);
    if (!m) return { feature: t, state: 'non définie' };
    const feat = m[1].trim();
    const raw = m[2].trim();
    if (raw === '()' || raw === '') return { feature: feat, state: 'bloquée' };
    if (raw.includes('*')) return { feature: feat, state: 'autorisée (*)' };
    return { feature: feat, state: `autorisée (${raw})` };
  }).filter(x => x.feature);
}

export function computeHeadersSummary(result: SslResultDto): HeadersSummary {
  const tested = result.headersLiveChecked === true;
  const url = result.headersCheckedUrl || (result.domain ? `https://${result.domain}/` : null);
  const httpStatus = result.headersHttpStatus != null ? String(result.headersHttpStatus) : null;
  const source = result.headersLiveChecked ? 'Contrôle HTTP live' : 'Snapshot scan Kali / SSLyze';
  const checkedAt = result.sslyzeScanStarted || 'Non disponible';

  const items: HeaderPresentation[] = [];

  // ── HSTS ────────────────────────────────────────────────────────────
  {
    const value = result.hstsValue || null;
    const maxAge = parseMaxAge(value);
    const hasInclude = !!(value && /includeSubDomains/i.test(value));
    const hasPreload = !!(value && /preload/i.test(value));
    let badge: HeaderBadge = 'a_corriger';
    let statusLabel = 'Absent';
    let scoreEarned = 0;
    let priority: HeaderPriority = 'haute';
    let conclusion: string | undefined;

    if (!tested && !result.hsts && !value) {
      badge = 'non_teste';
      statusLabel = 'Non testé';
      priority = 'haute';
    } else if (result.hsts && !value) {
      badge = 'presence_nc';
      statusLabel = 'Présence non confirmée';
      scoreEarned = 2;
      priority = 'moyenne';
    } else if (!result.hsts && !value) {
      badge = 'a_corriger';
      statusLabel = 'Absent';
      scoreEarned = 0;
      priority = 'haute';
    } else if (maxAge == null) {
      badge = 'partiel';
      statusLabel = 'Invalide';
      scoreEarned = 1;
      priority = 'haute';
      conclusion = 'L’en-tête HSTS est présent mais max-age est illisible ou invalide.';
    } else if (maxAge < 300) {
      badge = 'partiel';
      statusLabel = 'Actif — durée de test';
      scoreEarned = 2;
      priority = 'moyenne';
      conclusion = `max-age=${maxAge} est trop court pour une protection durable.`;
    } else if (maxAge < 15552000) {
      badge = 'partiel';
      statusLabel = 'Actif — durée de test';
      scoreEarned = 3;
      priority = 'moyenne';
      conclusion = `HSTS actif avec max-age=${maxAge}. Augmentez progressivement après validation.`;
    } else if (hasInclude && hasPreload) {
      badge = 'conforme';
      statusLabel = 'Conforme';
      scoreEarned = 5;
      priority = 'basse';
      conclusion = 'HSTS long terme avec includeSubDomains et preload. Vérifiez que tous les sous-domaines sont exclusivement en HTTPS.';
    } else {
      badge = 'conforme';
      statusLabel = 'Conforme';
      scoreEarned = 5;
      priority = 'basse';
      conclusion = 'HSTS configuré avec une durée durable. includeSubDomains/preload restent facultatifs.';
    }

    items.push({
      id: 'hsts',
      kind: 'main',
      name: 'Strict-Transport-Security',
      abbr: 'HSTS',
      icon: 'lock',
      utility: 'Force le navigateur à utiliser HTTPS lors des prochaines visites.',
      badge,
      statusLabel,
      shortValue: value ? (maxAge != null ? `max-age=${maxAge}` : value.slice(0, 48)) : null,
      conclusion,
      priority,
      requirement: 'obligatoire',
      observedValue: value,
      headerName: 'Strict-Transport-Security',
      role: 'Indique au navigateur de n’accepter que HTTPS pendant la durée max-age.',
      risk: 'Sans HSTS, une première requête HTTP peut être détournée (SSL stripping).',
      when: 'Dès que le site est servi exclusivement en HTTPS. Déployer progressivement.',
      impact: 'Faible si déployé par étapes ; includeSubDomains peut casser des sous-domaines HTTP.',
      recommendation:
        'Étape 1 : max-age=300. Étape 2 : max-age=86400. Étape 3 : max-age=31536000. Étape 4 facultative : includeSubDomains puis preload uniquement si tous les sous-domaines sont en HTTPS.',
      nginx: 'add_header Strict-Transport-Security "max-age=300" always;',
      apache: 'Header always set Strict-Transport-Security "max-age=300"',
      verifyCommand: `curl -sI https://${result.domain || 'exemple.com'} | grep -i strict-transport-security`,
      configPathHint: 'nginx: server { } · Apache: VirtualHost SSL',
      reloadCommand: { nginx: 'nginx -t && systemctl reload nginx', apache: 'apachectl configtest && systemctl reload apache2' },
      details: {
        maxAge: maxAge != null ? String(maxAge) : null,
        includeSubDomains: hasInclude,
        preload: hasPreload,
        note: 'includeSubDomains ne doit être activé que si tous les sous-domaines fonctionnent exclusivement en HTTPS. Le preload doit être considéré comme une étape finale et volontaire.',
      },
      scoreMax: 5,
      scoreEarned,
    });
  }

  // ── CSP ─────────────────────────────────────────────────────────────
  {
    const value = result.cspValue || null;
    const enforced = !!result.contentSecurityPolicy;
    const reportOnly = !!result.cspReportOnly && !enforced;
    const analysis = analyzeCsp(value, enforced, reportOnly);
    let badge: HeaderBadge = 'a_corriger';
    let statusLabel = 'Absente';
    let scoreEarned = 0;
    let priority: HeaderPriority = 'haute';
    let conclusion: string | undefined;

    if (!tested && !enforced && !reportOnly && !value) {
      badge = 'non_teste';
      statusLabel = 'Non testée';
    } else if ((enforced || reportOnly) && !value) {
      badge = 'presence_nc';
      statusLabel = 'Présence non confirmée';
      scoreEarned = 2;
    } else if (reportOnly) {
      badge = 'observation';
      statusLabel = 'Mode observation';
      scoreEarned = 2;
      priority = 'haute';
      conclusion = 'Les violations sont surveillées, mais aucune règle n’est encore bloquée.';
    } else if (enforced && analysis.weak) {
      badge = 'partiel';
      statusLabel = 'Présente mais faible';
      scoreEarned = 3;
      priority = 'haute';
      conclusion = 'CSP appliquée mais trop permissive (unsafe-inline, wildcards, etc.).';
    } else if (enforced) {
      badge = 'conforme';
      statusLabel = 'Appliquée';
      scoreEarned = 5;
      priority = 'basse';
    } else {
      badge = 'a_corriger';
      statusLabel = 'Absente';
      scoreEarned = 0;
      priority = 'haute';
    }

    items.push({
      id: 'csp',
      kind: 'main',
      name: 'Content-Security-Policy',
      abbr: 'CSP',
      icon: 'policy',
      utility: 'Limite les sources de scripts, styles, images et autres ressources autorisées par la page.',
      badge,
      statusLabel,
      shortValue: reportOnly
        ? 'Content-Security-Policy-Report-Only'
        : (enforced ? 'Content-Security-Policy' : null),
      conclusion,
      priority,
      requirement: 'obligatoire',
      observedValue: value
        ? `${reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy'}: ${value}`
        : null,
      headerName: reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy',
      role: 'Contrôle les origines autorisées pour chaque type de ressource afin de limiter XSS et injections.',
      risk: 'Sans CSP appliquée, un script injecté peut s’exécuter dans le contexte de la page.',
      when: 'Toujours pertinente pour une application web. Commencer en Report-Only, puis passer en mode appliqué.',
      impact: 'Une CSP trop stricte peut casser scripts, styles ou CDN légitimes.',
      recommendation:
        'La politique doit être adaptée aux domaines et ressources réellement utilisés par l’application. Ne pas adopter une CSP générique comme configuration finale.',
      nginx: `# Test :\n# add_header Content-Security-Policy-Report-Only "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;\n# Production (après validation) :\nadd_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'" always;`,
      apache: `Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"`,
      verifyCommand: `curl -sI https://${result.domain || 'exemple.com'} | grep -i content-security-policy`,
      configPathHint: 'Bloc server / location HTML',
      reloadCommand: { nginx: 'nginx -t && systemctl reload nginx', apache: 'apachectl configtest && systemctl reload apache2' },
      details: {
        mode: reportOnly ? 'Report-Only' : (enforced ? 'Appliquée' : 'Absente'),
        findings: analysis.flags,
        directivesNote: 'Analyser default-src, script-src, object-src, base-uri, frame-ancestors, form-action, report-to…',
      },
      scoreMax: 5,
      scoreEarned,
    });
  }

  // ── Anti-framing ────────────────────────────────────────────────────
  {
    const xfoVal = result.xFrameOptionsValue || null;
    const xfoPresent = !!result.xFrameOptions;
    const fa = cspHasFrameAncestors(result.cspValue);
    const protectedOk = (xfoPresent && !!xfoVal) || fa || (xfoPresent && !xfoVal);

    let badge: HeaderBadge = 'a_corriger';
    let statusLabel = 'Absente';
    let scoreEarned = 0;
    let conclusion: string | undefined;
    let shortValue: string | null = null;

    if (!tested && !xfoPresent && !fa) {
      badge = 'non_teste';
      statusLabel = 'Non testée';
    } else if (xfoPresent && !xfoVal && !fa) {
      badge = 'presence_nc';
      statusLabel = 'Présence non confirmée';
      scoreEarned = 2;
    } else if (fa && xfoPresent && xfoVal) {
      badge = 'conforme';
      statusLabel = 'Protection anti-framing conforme';
      scoreEarned = 4;
      shortValue = `frame-ancestors + X-Frame-Options`;
      conclusion = 'frame-ancestors est la politique principale ; X-Frame-Options assure la compatibilité historique.';
    } else if (fa) {
      badge = 'conforme';
      statusLabel = 'Protection anti-framing conforme';
      scoreEarned = 4;
      shortValue = 'CSP frame-ancestors';
    } else if (xfoPresent && xfoVal) {
      badge = 'conforme';
      statusLabel = 'Protection anti-framing conforme';
      scoreEarned = 4;
      shortValue = xfoVal;
    } else {
      badge = 'a_corriger';
      statusLabel = 'Absente';
      scoreEarned = 0;
      conclusion = 'Ni X-Frame-Options ni CSP frame-ancestors n’ont été confirmés.';
    }

    items.push({
      id: 'framing',
      kind: 'main',
      name: 'Protection anti-framing',
      abbr: 'XFO / FA',
      icon: 'picture_in_picture_off',
      utility: 'Empêche l’intégration de la page dans une iframe tierce (clickjacking).',
      badge,
      statusLabel,
      shortValue,
      conclusion,
      priority: protectedOk ? 'basse' : 'haute',
      requirement: 'obligatoire',
      observedValue: xfoVal
        ? `X-Frame-Options: ${xfoVal}${fa ? ' · CSP frame-ancestors présent' : ''}`
        : (fa ? 'CSP frame-ancestors (via Content-Security-Policy)' : null),
      headerName: 'X-Frame-Options / CSP frame-ancestors',
      role: 'Contrôle les contextes d’embedding de la page.',
      risk: 'Sans protection, un site tiers peut superposer votre page pour du clickjacking.',
      when: 'Sur toutes les pages HTML sensibles. Préférer frame-ancestors ; conserver X-Frame-Options pour l’historique.',
      impact: 'DENY / frame-ancestors none empêche tout embedding légitime (widgets).',
      recommendation: 'Utiliser frame-ancestors \'none\' (ou \'self\') et X-Frame-Options: DENY (ou SAMEORIGIN) de façon cohérente.',
      nginx: 'add_header X-Frame-Options "DENY" always;\n# et dans la CSP : frame-ancestors \'none\'',
      apache: 'Header always set X-Frame-Options "DENY"',
      verifyCommand: `curl -sI https://${result.domain || 'exemple.com'} | grep -iE 'x-frame-options|content-security-policy'`,
      configPathHint: 'Réponses HTML',
      reloadCommand: { nginx: 'nginx -t && systemctl reload nginx', apache: 'apachectl configtest && systemctl reload apache2' },
      details: {
        xFrameOptions: xfoVal || (xfoPresent ? 'Présence non confirmée' : 'Absent'),
        frameAncestors: fa ? 'Présent dans CSP' : 'Absent',
      },
      scoreMax: 4,
      scoreEarned,
    });
  }

  // ── X-Content-Type-Options ──────────────────────────────────────────
  {
    const value = result.xContentTypeOptionsValue || null;
    const ok = !!result.xContentTypeOptions;
    let badge: HeaderBadge = 'a_corriger';
    let statusLabel = 'Absent';
    let scoreEarned = 0;
    if (!tested && !ok) { badge = 'non_teste'; statusLabel = 'Non testé'; }
    else if (ok && !value) { badge = 'presence_nc'; statusLabel = 'Présence non confirmée'; scoreEarned = 2; }
    else if (ok && value && /nosniff/i.test(value)) { badge = 'conforme'; statusLabel = 'Conforme'; scoreEarned = 3; }
    else if (ok) { badge = 'partiel'; statusLabel = 'Partiel'; scoreEarned = 2; }
    else { badge = 'recommande'; statusLabel = 'Absent'; scoreEarned = 0; }

    items.push({
      id: 'xcto',
      kind: 'main',
      name: 'X-Content-Type-Options',
      abbr: 'XCTO',
      icon: 'fingerprint',
      utility: 'Empêche le navigateur de « deviner » un type MIME différent de celui déclaré.',
      badge,
      statusLabel,
      shortValue: value || (ok ? null : null),
      priority: ok ? 'basse' : 'moyenne',
      requirement: 'recommande',
      observedValue: value ? `X-Content-Type-Options: ${value}` : null,
      headerName: 'X-Content-Type-Options',
      role: 'Force le respect du Content-Type déclaré (nosniff).',
      risk: 'Sans nosniff, un fichier peut être interprété comme script alors qu’il est servi comme image.',
      when: 'Sur toutes les réponses HTTP, y compris assets et erreurs.',
      impact: 'Très faible sur les applications correctement typées.',
      recommendation: 'Ajouter X-Content-Type-Options: nosniff sur toutes les réponses.',
      nginx: 'add_header X-Content-Type-Options "nosniff" always;',
      apache: 'Header always set X-Content-Type-Options "nosniff"',
      verifyCommand: `curl -sI https://${result.domain || 'exemple.com'} | grep -i x-content-type-options`,
      configPathHint: 'server / VirtualHost',
      reloadCommand: { nginx: 'nginx -t && systemctl reload nginx', apache: 'apachectl configtest && systemctl reload apache2' },
      details: {},
      scoreMax: 3,
      scoreEarned,
    });
  }

  // ── Referrer-Policy ─────────────────────────────────────────────────
  {
    const value = result.referrerPolicyValue || null;
    const ok = !!result.referrerPolicy;
    const valid = [
      'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
      'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url',
    ];
    const normalized = value?.split(',')[0]?.trim().toLowerCase() || null;
    let badge: HeaderBadge = 'recommande';
    let statusLabel = 'Absente';
    let scoreEarned = 0;
    if (!tested && !ok) { badge = 'non_teste'; statusLabel = 'Non testée'; }
    else if (ok && !value) { badge = 'presence_nc'; statusLabel = 'Présence non confirmée'; scoreEarned = 1; }
    else if (value && normalized && !valid.includes(normalized)) {
      badge = 'partiel'; statusLabel = 'Valeur invalide'; scoreEarned = 0;
    } else if (value) {
      badge = 'conforme'; statusLabel = 'Conforme'; scoreEarned = 2;
    } else {
      badge = 'recommande'; statusLabel = 'Absente'; scoreEarned = 0;
    }

    items.push({
      id: 'referrer',
      kind: 'main',
      name: 'Referrer-Policy',
      abbr: 'RP',
      icon: 'visibility_off',
      utility: 'Contrôle les informations d’URL envoyées aux sites tiers via l’en-tête Referer.',
      badge,
      statusLabel,
      shortValue: value,
      priority: value ? 'basse' : 'moyenne',
      requirement: 'recommande',
      observedValue: value ? `Referrer-Policy: ${value}` : null,
      headerName: 'Referrer-Policy',
      role: 'Limite les fuites d’URL (tokens, chemins sensibles) vers des origines externes.',
      risk: 'Sans politique, des URLs sensibles peuvent fuiter dans les logs de sites tiers.',
      when: 'Recommandée dès qu’il existe des navigations ou ressources cross-origin.',
      impact: 'Certaines analytics peuvent recevoir moins de détail de chemin.',
      recommendation: 'Valeur souvent adaptée : strict-origin-when-cross-origin. Afficher et conserver la valeur réellement reçue.',
      nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
      apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
      verifyCommand: `curl -sI https://${result.domain || 'exemple.com'} | grep -i referrer-policy`,
      configPathHint: 'server / VirtualHost',
      reloadCommand: { nginx: 'nginx -t && systemctl reload nginx', apache: 'apachectl configtest && systemctl reload apache2' },
      details: {
        privacy: normalized === 'no-referrer' ? 'Maximale'
          : normalized?.includes('strict-origin') ? 'Élevée'
          : normalized === 'unsafe-url' ? 'Faible' : 'Variable',
      },
      scoreMax: 2,
      scoreEarned,
    });
  }

  // ── Permissions-Policy ──────────────────────────────────────────────
  {
    const value = result.permissionsPolicyValue || null;
    const ok = !!result.permissionsPolicy;
    const features = parsePermissions(value);
    let badge: HeaderBadge = 'recommande';
    let statusLabel = 'Absente';
    let scoreEarned = 0;
    if (!tested && !ok) { badge = 'non_teste'; statusLabel = 'Non testée'; }
    else if (ok && !value) { badge = 'presence_nc'; statusLabel = 'Présence non confirmée'; scoreEarned = 1; }
    else if (value && features.length === 0) { badge = 'partiel'; statusLabel = 'Partielle'; scoreEarned = 1; }
    else if (value) {
      const blocked = features.filter(f => f.state.startsWith('bloquée')).length;
      badge = blocked > 0 ? 'conforme' : 'partiel';
      statusLabel = blocked > 0 ? 'Conforme' : 'Présente';
      scoreEarned = 1;
    }

    items.push({
      id: 'permissions',
      kind: 'main',
      name: 'Permissions-Policy',
      abbr: 'PP',
      icon: 'tune',
      utility: 'Restreint l’accès aux fonctionnalités du navigateur (caméra, micro, géolocalisation…).',
      badge,
      statusLabel,
      shortValue: value ? (value.length > 42 ? `${value.slice(0, 42)}…` : value) : null,
      conclusion: value
        ? 'La simple présence ne suffit pas : une politique stricte doit restreindre explicitement les capacités inutiles.'
        : undefined,
      priority: value ? 'basse' : 'moyenne',
      requirement: 'recommande',
      observedValue: value ? `Permissions-Policy: ${value}` : null,
      headerName: 'Permissions-Policy',
      role: 'Déclare quelles API navigateur sont autorisées pour la page et ses iframes.',
      risk: 'Sans restriction, des scripts tiers peuvent tenter d’accéder à des capteurs sensibles.',
      when: 'Recommandée dès qu’il existe des scripts tiers ou des pages publiques.',
      impact: 'Une politique trop stricte peut bloquer une fonctionnalité légitime (paiement, géoloc…).',
      recommendation: 'Inventorier les permissions nécessaires, bloquer le reste avec =().',
      nginx: 'add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()" always;',
      apache: 'Header always set Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()"',
      verifyCommand: `curl -sI https://${result.domain || 'exemple.com'} | grep -i permissions-policy`,
      configPathHint: 'server / VirtualHost',
      reloadCommand: { nginx: 'nginx -t && systemctl reload nginx', apache: 'apachectl configtest && systemctl reload apache2' },
      details: {
        features: features.map(f => `${f.feature}: ${f.state}`),
      },
      scoreMax: 1,
      scoreEarned,
    });
  }

  // ── Contextual: COOP / CORP / COEP ──────────────────────────────────
  const contextualDefs: Array<{
    id: string;
    name: string;
    abbr: string;
    icon: string;
    utility: string;
    role: string;
    risk: string;
    when: string;
    impact: string;
    flag: boolean | undefined;
    value: string | null | undefined;
    headerName: string;
    nginx: string;
    apache: string;
    extra?: string;
  }> = [
    {
      id: 'coop',
      name: 'Cross-Origin-Opener-Policy',
      abbr: 'COOP',
      icon: 'door_front',
      utility: 'Isole la fenêtre principale des documents ouverts depuis d’autres origines.',
      role: 'Isole la fenêtre principale des documents ouverts depuis d’autres origines. Peut modifier certains popups et parcours d’authentification.',
      risk: 'Sans COOP, window.opener peut rester lié à une origine tierce.',
      when: 'Utile pour l’isolation renforcée et crossOriginIsolated. Non obligatoire pour tous les sites.',
      impact: 'Peut casser des popups OAuth ou des parcours d’authentification cross-origin.',
      flag: result.crossOriginOpenerPolicy,
      value: result.crossOriginOpenerPolicyValue,
      headerName: 'Cross-Origin-Opener-Policy',
      nginx: 'add_header Cross-Origin-Opener-Policy "same-origin" always;',
      apache: 'Header always set Cross-Origin-Opener-Policy "same-origin"',
    },
    {
      id: 'corp',
      name: 'Cross-Origin-Resource-Policy',
      abbr: 'CORP',
      icon: 'shield_lock',
      utility: 'Contrôle les sites autorisés à charger une ressource en mode no-cors.',
      role: 'Contrôle les sites autorisés à charger une ressource en mode no-cors.',
      risk: 'Sans CORP, des sites tiers peuvent embarquer certaines ressources sensibles.',
      when: 'Pertinent pour les ressources sensibles. Une politique trop stricte peut bloquer le chargement légitime de ressources externes.',
      impact: 'Peut bloquer CDN, images ou scripts légitimes.',
      flag: result.crossOriginResourcePolicy,
      value: result.crossOriginResourcePolicyValue,
      headerName: 'Cross-Origin-Resource-Policy',
      nginx: 'add_header Cross-Origin-Resource-Policy "same-origin" always;',
      apache: 'Header always set Cross-Origin-Resource-Policy "same-origin"',
      extra: 'Une politique trop stricte peut bloquer le chargement légitime de ressources externes.',
    },
    {
      id: 'coep',
      name: 'Cross-Origin-Embedder-Policy',
      abbr: 'COEP',
      icon: 'hub',
      utility: 'Active une isolation avancée des ressources cross-origin pour certaines fonctionnalités du navigateur.',
      role: 'Exige que les ressources cross-origin autorisent explicitement leur chargement. Principalement utile pour l’isolation cross-origin complète.',
      risk: 'Sans COEP, crossOriginIsolated / SharedArrayBuffer restent indisponibles.',
      when: 'Ne pas activer require-corp sans analyser images externes, scripts tiers, polices, iframes, paiements, auth externe, CDN et API.',
      impact: 'Très élevé sur les sites avec dépendances cross-origin.',
      flag: result.crossOriginEmbedderPolicy,
      value: result.crossOriginEmbedderPolicyValue,
      headerName: 'Cross-Origin-Embedder-Policy',
      nginx: '# Uniquement si crossOriginIsolated / SharedArrayBuffer est requis\n# add_header Cross-Origin-Embedder-Policy "require-corp" always;',
      apache: '# Uniquement si nécessaire\n# Header always set Cross-Origin-Embedder-Policy "require-corp"',
    },
  ];

  for (const c of contextualDefs) {
    const value = c.value || null;
    let badge: HeaderBadge = 'contextuel';
    let statusLabel = 'Non configuré — contextuel';
    if (!tested && !c.flag) {
      badge = 'non_teste';
      statusLabel = 'Non testé';
    } else if (c.flag && !value) {
      badge = 'presence_nc';
      statusLabel = 'Présence non confirmée';
    } else if (value) {
      badge = 'contextuel';
      statusLabel = c.id === 'coep' ? 'Contextuel' : 'Configuré — contextuel';
    } else {
      badge = 'contextuel';
      statusLabel = 'Non configuré — contextuel';
    }

    items.push({
      id: c.id,
      kind: 'contextual',
      name: c.name,
      abbr: c.abbr,
      icon: c.icon,
      utility: c.utility,
      badge,
      statusLabel,
      shortValue: value,
      conclusion: c.extra || (c.id === 'coep'
        ? 'Non obligatoire sauf si l’application utilise crossOriginIsolated, SharedArrayBuffer ou une fonctionnalité équivalente.'
        : 'Fonctionnalité contextuelle : n’affecte pas automatiquement le score des protections HTTP principales.'),
      priority: 'contextuelle',
      requirement: 'contextuel',
      observedValue: value ? `${c.headerName}: ${value}` : null,
      headerName: c.headerName,
      role: c.role,
      risk: c.risk,
      when: c.when,
      impact: c.impact,
      recommendation: 'Évaluer le besoin applicatif avant activation. Ne pas imposer require-corp / same-origin par défaut.',
      nginx: c.nginx,
      apache: c.apache,
      verifyCommand: `curl -sI https://${result.domain || 'exemple.com'} | grep -i ${c.headerName.toLowerCase()}`,
      configPathHint: 'server / VirtualHost',
      reloadCommand: { nginx: 'nginx -t && systemctl reload nginx', apache: 'apachectl configtest && systemctl reload apache2' },
      details: {
        url,
        httpStatus,
        source,
        checkedAt,
      },
      scoreMax: 0,
      scoreEarned: 0,
    });
  }

  // Attach common evidence meta on all items
  for (const it of items) {
    it.details = {
      ...it.details,
      analyzedUrl: url,
      httpStatus,
      source,
      checkedAt,
      live: result.headersLiveChecked ? 'oui' : 'non',
    };
  }

  const mainItems = items.filter(i => i.kind === 'main');
  const contextualItems = items.filter(i => i.kind === 'contextual');
  const scoreMax = mainItems.reduce((s, i) => s + i.scoreMax, 0) || 20;
  const scoreEarned = mainItems.reduce((s, i) => s + i.scoreEarned, 0);
  const mainScore = Math.round((scoreEarned / scoreMax) * 100);
  const categoryScore = Math.min(20, Math.round((scoreEarned / scoreMax) * 20));

  const conformes = mainItems.filter(i => i.badge === 'conforme').length;
  const partielles = mainItems.filter(i => i.badge === 'partiel' || i.badge === 'presence_nc').length;
  const observations = mainItems.filter(i => i.badge === 'observation').length;
  const nonTestees = items.filter(i => i.badge === 'non_teste').length;
  const contextuelles = contextualItems.length;

  const anyContextualConfigured = contextualItems.some(i => !!i.observedValue || i.badge === 'presence_nc');
  const isolationLabel = anyContextualConfigured
    ? 'Partiellement configurée — politiques contextuelles'
    : 'Non configurée — fonctionnalité contextuelle';

  const cspItem = items.find(i => i.id === 'csp');
  const hstsItem = items.find(i => i.id === 'hsts');
  let primaryPriority = 'Maintenir les protections HTTP actuelles.';
  if (cspItem?.badge === 'observation') primaryPriority = 'Passer progressivement la CSP en mode appliqué.';
  else if (cspItem?.badge === 'a_corriger') primaryPriority = 'Définir une Content-Security-Policy adaptée à l’application.';
  else if (hstsItem?.badge === 'a_corriger') primaryPriority = 'Activer HSTS progressivement (max-age=300 puis augmentation).';
  else if (hstsItem?.badge === 'partiel') primaryPriority = 'Augmenter progressivement la durée HSTS après validation.';
  else if (items.find(i => i.id === 'framing')?.badge === 'a_corriger') {
    primaryPriority = 'Activer la protection anti-framing (frame-ancestors ou X-Frame-Options).';
  }

  const conclusionParts: string[] = [];
  if (conformes >= 4 && observations === 0 && partielles === 0) {
    conclusionParts.push('Les principales protections HTTP sont présentes et conformes.');
  } else {
    conclusionParts.push('Les principales protections HTTP sont partiellement en place.');
  }
  if (hstsItem?.badge === 'partiel') conclusionParts.push('HSTS est encore configuré avec une durée de test.');
  if (cspItem?.badge === 'observation') conclusionParts.push('La CSP fonctionne uniquement en mode observation.');
  conclusionParts.push('Les politiques COOP, CORP et COEP sont contextuelles et ne constituent pas automatiquement des défauts de sécurité.');

  return {
    mainScore,
    categoryScore,
    conformes,
    partielles,
    observations,
    contextuelles,
    nonTestees,
    isolationLabel,
    primaryPriority,
    conclusion: conclusionParts.join(' '),
    items,
    mainItems,
    contextualItems,
  };
}

/** Score /20 for global grade — main HTTP protections only (no OCSP, no COOP/CORP/COEP). */
export function computeHttpHeadersCategoryScore(result: SslResultDto): {
  score: number;
  penalties: Array<{ label: string; points: number; category: 'headers' }>;
} {
  const summary = computeHeadersSummary(result);
  const penalties: Array<{ label: string; points: number; category: 'headers' }> = [];
  for (const item of summary.mainItems) {
    const missing = item.scoreMax - item.scoreEarned;
    if (missing > 0) {
      penalties.push({
        label: `${item.abbr} — ${item.statusLabel}`,
        points: missing,
        category: 'headers',
      });
    }
  }
  return { score: summary.categoryScore, penalties };
}
