import type { SslResultDto } from '../services/api';
import { computeHeadersSummary } from '../components/sslHeaderModel';
import { getVulnStatus, type SourceValue, type VulnStatus } from './sslScore';

/**
 * What the SSL result page shows first: one list of problems (what, the flaw if it is not fixed, how to fix it on
 * nginx / Apache, who saw it) and the checks that passed. Same detection rules as the score (utils/sslScore): a
 * problem listed here is a problem that costs points or caps the grade.
 */

export type FindingSeverity = 'critique' | 'élevée' | 'moyenne' | 'faible';

export type Finding = {
  id: string;
  title: string;
  severity: FindingSeverity;
  /** Seen by one tool only (another one said no or could not test): to confirm before acting on it. */
  toConfirm: boolean;
  cve?: string;
  /** What an attacker can do, or what breaks, while this is not fixed. */
  risk: string;
  /** What to do, in words. */
  fix: string;
  nginx?: string;
  apache?: string;
  /** "SSLyze, SSL Labs" */
  seenBy: string;
};

export type PassedCheck = { id: string; label: string; singleSource: boolean };

export type SslFindings = { findings: Finding[]; passed: PassedCheck[]; untested: string[] };

const SEVERITY_ORDER: FindingSeverity[] = ['critique', 'élevée', 'moyenne', 'faible'];

// ── Configuration lines (Mozilla "intermediate" profile) ──
const NGINX_PROTOCOLS = 'ssl_protocols TLSv1.2 TLSv1.3;';
const APACHE_PROTOCOLS = 'SSLProtocol -all +TLSv1.2 +TLSv1.3';
const CIPHERS = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:'
  + 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
const NGINX_CIPHERS = `ssl_ciphers ${CIPHERS};\nssl_prefer_server_ciphers off;`;
const APACHE_CIPHERS = `SSLCipherSuite ${CIPHERS}\nSSLHonorCipherOrder off`;
const OPENSSL_UPDATE = 'Mettre à jour OpenSSL (apt update && apt upgrade openssl), puis redémarrer le serveur web.';

function sources(names: Array<[string, boolean | null | undefined]>): string {
  const seen = names.filter(([, v]) => v === true).map(([n]) => n);
  return seen.length ? seen.join(', ') : 'analyse du scan';
}

function isPositive(st: VulnStatus): boolean {
  return st === 'confirmed' || st === 'to_confirm';
}

function keyBits(r: SslResultDto): number {
  if (r.sslyzeStatus === 'READY' && r.sslyzeKeySize > 0) return r.sslyzeKeySize;
  const m = String(r.certKeySize ?? '').match(/(\d+)/);
  return m ? Number(m[1]) : 0;
}

function isRsa(r: SslResultDto): boolean {
  const alg = `${r.certificateDetail?.publicKeyAlgorithm ?? ''} ${r.certificateDetail?.keyType ?? ''}`.toUpperCase();
  return /RSA/.test(alg) || !/EC|ED25519|ED448/.test(alg);
}

/** Multi-source checks: status from both tools, and whether only one tool answered. */
function vuln(values: SourceValue[]): { status: VulnStatus; single: boolean } {
  const tested = values.filter((v) => v === true || v === false).length;
  return { status: getVulnStatus(values), single: tested === 1 };
}

export function sslFindings(r: SslResultDto): SslFindings {
  const findings: Finding[] = [];
  const passed: PassedCheck[] = [];
  const untested: string[] = [];
  const add = (f: Omit<Finding, 'toConfirm'> & { toConfirm?: boolean }) => findings.push({ toConfirm: false, ...f });
  const ok = (id: string, label: string, singleSource = false) => passed.push({ id, label, singleSource });
  const sslyzeReady = r.sslyzeStatus === 'READY';
  const labsReady = r.ssllabsStatus === 'READY';
  const labsGrade = labsReady ? (r.ssllabsGrade ?? '') : '';
  const domain = r.domain || 'votre-domaine';

  // ───────────── Certificate ─────────────
  const expired = !!r.certExpired || (sslyzeReady && r.sslyzeDaysLeft < 0) || r.certificateDetail?.validityStatus === 'EXPIRED';
  const days = sslyzeReady && r.sslyzeDaysLeft != null ? r.sslyzeDaysLeft : r.certDaysLeft;
  if (expired) {
    add({ id: 'cert_expired', title: 'Certificat expiré', severity: 'critique',
      risk: 'Les navigateurs bloquent le site par une page d’alerte. Les visiteurs qui prennent l’habitude d’ignorer ces alertes ne verront plus la différence avec un faux site.',
      fix: 'Renouveler le certificat, puis automatiser le renouvellement (certbot renouvelle tout seul s’il est planifié).',
      nginx: 'certbot renew && systemctl reload nginx', apache: 'certbot renew && systemctl reload apache2',
      seenBy: sources([['Kali', r.certExpired], ['SSLyze', sslyzeReady && r.sslyzeDaysLeft < 0]]) });
  } else if (days != null && days >= 0 && days <= 30) {
    add({ id: 'cert_expiring', title: `Certificat qui expire dans ${days} jour${days > 1 ? 's' : ''}`, severity: days <= 7 ? 'élevée' : 'moyenne',
      risk: 'À l’expiration, les navigateurs bloqueront le site. Un certificat Let’s Encrypt qui arrive à moins de 30 jours veut souvent dire que le renouvellement automatique ne marche pas.',
      fix: 'Renouveler maintenant et vérifier le renouvellement automatique (certbot renew --dry-run).',
      nginx: 'certbot renew --dry-run && certbot renew && systemctl reload nginx', apache: 'certbot renew --dry-run && certbot renew && systemctl reload apache2',
      seenBy: 'Kali, SSLyze' });
  } else if (days != null && days > 30) {
    ok('cert_valid', `Certificat valide encore ${days} jours`);
  }

  if ((sslyzeReady && !r.sslyzeChainTrusted) || labsGrade === 'T' || r.certificateDetail?.selfSigned) {
    add({ id: 'cert_untrusted', title: 'Certificat non reconnu par les navigateurs', severity: 'critique',
      risk: 'Certificat auto-signé ou d’une autorité inconnue : chaque visiteur voit une alerte. Un attaquant sur le réseau peut présenter son propre certificat sans que personne ne fasse la différence.',
      fix: 'Installer un certificat d’une autorité reconnue, par exemple Let’s Encrypt (gratuit).',
      nginx: `certbot --nginx -d ${domain}`, apache: `certbot --apache -d ${domain}`,
      seenBy: sources([['SSLyze', sslyzeReady && !r.sslyzeChainTrusted], ['SSL Labs', labsGrade === 'T']]) });
  } else if (!sslyzeReady && r.scanStatus === 'COMPLETED' && r.chainComplete === false) {
    add({ id: 'cert_chain', title: 'Chaîne de certificats incomplète', severity: 'moyenne',
      risk: 'Le certificat intermédiaire n’est pas envoyé : certains navigateurs, mobiles et outils (curl, API) refusent la connexion alors qu’elle marche sur votre poste.',
      fix: 'Servir le certificat complet (fullchain) au lieu du certificat seul.',
      nginx: `ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;`,
      apache: `SSLCertificateFile /etc/letsencrypt/live/${domain}/fullchain.pem`, seenBy: 'Kali' });
  } else if (sslyzeReady || r.chainComplete) {
    ok('cert_trusted', 'Certificat reconnu par les navigateurs, chaîne complète');
  }

  if (r.certificateDetail?.hostnameMatch === 'MISMATCH' || labsGrade === 'M') {
    add({ id: 'cert_name', title: 'Le certificat ne couvre pas ce nom de site', severity: 'critique',
      risk: `Le certificat est émis pour un autre nom que ${domain} : les navigateurs affichent une alerte, et le site ne peut pas prouver son identité.`,
      fix: 'Émettre un certificat qui couvre ce nom (et sa variante www si elle est utilisée).',
      nginx: `certbot --nginx -d ${domain}`, apache: `certbot --apache -d ${domain}`,
      seenBy: sources([['Kali', r.certificateDetail?.hostnameMatch === 'MISMATCH'], ['SSL Labs', labsGrade === 'M']]) });
  }

  const bits = keyBits(r);
  if (bits > 0 && bits < 2048 && isRsa(r)) {
    add({ id: 'weak_key', title: `Clé RSA trop courte (${bits} bits)`, severity: bits < 1024 ? 'critique' : 'élevée',
      risk: bits < 1024 ? 'Une clé de cette taille se casse : un attaquant peut retrouver la clé privée et se faire passer pour le site.'
        : 'En dessous de 2048 bits, la clé n’offre plus une marge de sécurité suffisante et n’est plus acceptée par les autorités.',
      fix: 'Générer un nouveau certificat avec une clé ECDSA (ou RSA 2048 bits minimum).',
      nginx: `certbot --nginx --key-type ecdsa -d ${domain}`, apache: `certbot --apache --key-type ecdsa -d ${domain}`,
      seenBy: sslyzeReady ? 'SSLyze' : 'Kali' });
  } else if (bits >= 2048 || (bits > 0 && !isRsa(r))) {
    ok('key', `Clé ${isRsa(r) ? `RSA ${bits} bits` : 'ECDSA'} suffisante`);
  }

  const stapling = r.ocspStapling || r.sslyzeOcspStapling || r.certificateDetail?.ocspStaplingStatus === 'CONFORME';
  if (!stapling) {
    add({ id: 'ocsp', title: 'OCSP Stapling non activé', severity: 'faible',
      risk: 'Chaque navigateur doit interroger l’autorité pour savoir si le certificat est révoqué : la première connexion est plus lente, et un certificat révoqué peut rester accepté si cette vérification échoue.',
      fix: 'Activer l’OCSP Stapling : le serveur joint lui-même la preuve de validité.',
      nginx: 'ssl_stapling on;\nssl_stapling_verify on;\nresolver 1.1.1.1 8.8.8.8 valid=300s;',
      apache: 'SSLUseStapling on\nSSLStaplingCache "shmcb:logs/ssl_stapling(32768)"', seenBy: 'Kali, SSLyze' });
  } else {
    ok('ocsp', 'OCSP Stapling activé');
  }

  // ───────────── Protocols ─────────────
  if (r.sslyzeSupportsSSL20) {
    add({ id: 'ssl2', title: 'SSL 2.0 activé', severity: 'critique',
      risk: 'Protocole cassé depuis 1995 : il permet l’attaque DROWN, qui déchiffre aussi les connexions TLS modernes faites avec le même certificat.',
      fix: 'N’autoriser que TLS 1.2 et TLS 1.3.', nginx: NGINX_PROTOCOLS, apache: APACHE_PROTOCOLS, seenBy: 'SSLyze' });
  }
  if (r.sslyzeSupportsSSL30 || r.poodle) {
    add({ id: 'ssl3', title: 'SSL 3.0 activé (POODLE)', severity: 'élevée', cve: 'CVE-2014-3566',
      risk: 'Un attaquant sur le même réseau (Wi-Fi public, opérateur) peut forcer SSL 3.0 puis déchiffrer octet par octet des cookies de session.',
      fix: 'N’autoriser que TLS 1.2 et TLS 1.3.', nginx: NGINX_PROTOCOLS, apache: APACHE_PROTOCOLS,
      seenBy: sources([['SSLyze', r.sslyzeSupportsSSL30], ['Kali', r.poodle]]) });
  } else if (sslyzeReady) {
    ok('ssl', 'SSL 2.0 et 3.0 désactivés');
  }
  const tls10 = !!(r.tls10 || r.sslyzeSupportsTLS10);
  const tls11 = !!(r.tls11 || r.sslyzeSupportsTLS11);
  if (tls10 || tls11) {
    add({ id: 'old_tls', title: `${[tls10 && 'TLS 1.0', tls11 && 'TLS 1.1'].filter(Boolean).join(' et ')} encore accepté${tls10 && tls11 ? 's' : ''}`, severity: 'élevée',
      risk: 'Versions abandonnées depuis 2021. Un attaquant sur le réseau peut forcer le navigateur à les utiliser, puis exploiter leurs failles connues (BEAST, chiffrements faibles). Les normes PCI-DSS les interdisent.',
      fix: 'N’autoriser que TLS 1.2 et TLS 1.3.', nginx: NGINX_PROTOCOLS, apache: APACHE_PROTOCOLS,
      seenBy: sources([['Kali', !!(r.tls10 || r.tls11)], ['SSLyze', !!(r.sslyzeSupportsTLS10 || r.sslyzeSupportsTLS11)]]) });
  } else {
    ok('old_tls', 'TLS 1.0 et 1.1 désactivés');
  }
  const tls12 = !!(r.tls12 || r.sslyzeSupportsTLS12);
  const tls13 = !!(r.tls13 || r.sslyzeSupportsTLS13);
  if (sslyzeReady && !tls12 && !tls13) {
    add({ id: 'no_modern_tls', title: 'Ni TLS 1.2 ni TLS 1.3 disponibles', severity: 'élevée',
      risk: 'Seules des versions obsolètes sont proposées : les navigateurs récents refusent la connexion, et les autres utilisent un chiffrement faible.',
      fix: 'Activer TLS 1.2 et TLS 1.3 (OpenSSL 1.1.1 minimum pour TLS 1.3).', nginx: NGINX_PROTOCOLS, apache: APACHE_PROTOCOLS, seenBy: 'SSLyze' });
  } else if (!tls13 && tls12) {
    add({ id: 'no_tls13', title: 'TLS 1.3 non activé', severity: 'faible',
      risk: 'Pas de faille directe, mais TLS 1.3 est plus rapide (connexion en un aller-retour) et retire d’office les chiffrements faibles.',
      fix: 'Ajouter TLS 1.3 aux protocoles autorisés.', nginx: NGINX_PROTOCOLS, apache: APACHE_PROTOCOLS, seenBy: 'Kali, SSLyze' });
  } else if (tls13) {
    ok('tls13', tls12 ? 'TLS 1.2 et 1.3 activés' : 'TLS 1.3 activé');
  }

  // ───────────── Ciphers ─────────────
  if (r.rc4) {
    add({ id: 'rc4', title: 'Chiffrement RC4 accepté', severity: 'élevée', cve: 'CVE-2015-2808',
      risk: 'RC4 a des biais statistiques : en observant beaucoup de connexions, un attaquant peut retrouver des mots de passe ou des cookies.',
      fix: 'Ne garder que des suites modernes (AES-GCM, ChaCha20).', nginx: NGINX_CIPHERS, apache: APACHE_CIPHERS, seenBy: 'Kali' });
  }
  if (r.has3des || r.sweet32 || r.ssllabsHas3des) {
    add({ id: '3des', title: 'Chiffrement 3DES accepté (SWEET32)', severity: 'moyenne', cve: 'CVE-2016-2183',
      risk: 'Sur une connexion longue (téléchargement, session gardée ouverte), un attaquant qui enregistre le trafic peut récupérer des cookies de session.',
      fix: 'Ne garder que des suites modernes (AES-GCM, ChaCha20).', nginx: NGINX_CIPHERS, apache: APACHE_CIPHERS,
      seenBy: sources([['Kali', r.has3des || r.sweet32], ['SSL Labs', r.ssllabsHas3des]]) });
  }
  if (!r.rc4 && !(r.has3des || r.sweet32 || r.ssllabsHas3des)) ok('ciphers', 'Pas de chiffrement faible (RC4, 3DES)');
  if (labsReady && r.ssllabsForwardSecrecy === false && labsGrade !== '' && labsGrade !== '?') {
    add({ id: 'forward_secrecy', title: 'Pas de confidentialité persistante pour tous les navigateurs', severity: 'moyenne',
      risk: 'Si la clé privée du serveur fuit un jour, tout le trafic enregistré avant pourra être déchiffré.',
      fix: 'Privilégier les suites ECDHE.', nginx: NGINX_CIPHERS, apache: APACHE_CIPHERS, seenBy: 'SSL Labs' });
  } else if (labsReady && r.ssllabsForwardSecrecy) {
    ok('forward_secrecy', 'Confidentialité persistante (Forward Secrecy)');
  }

  // ───────────── Known TLS attacks ─────────────
  const known: Array<{ id: string; name: string; cve: string; check: { status: VulnStatus; single: boolean };
    severity: FindingSeverity; risk: string; fix: string; nginx?: string; apache?: string; seenBy: string }> = [
    { id: 'heartbleed', name: 'Heartbleed', cve: 'CVE-2014-0160', check: vuln([r.heartbleed ?? undefined, r.sslyzeHeartbleed ?? undefined]),
      severity: 'critique', risk: 'N’importe qui sur Internet peut lire la mémoire du serveur : clé privée, mots de passe et cookies des utilisateurs, sans laisser de trace.',
      fix: `${OPENSSL_UPDATE} Remplacez ensuite le certificat et sa clé, et changez les mots de passe : ils ont pu fuiter.`,
      seenBy: sources([['Kali', r.heartbleed], ['SSLyze', r.sslyzeHeartbleed]]) },
    { id: 'robot', name: 'ROBOT', cve: 'CVE-2017-13099', check: vuln([r.robot ?? undefined, r.sslyzeRobot ?? undefined]),
      severity: 'critique', risk: 'Un attaquant peut déchiffrer des connexions enregistrées ou signer à la place du serveur, grâce à l’échange de clé RSA.',
      fix: 'Retirer les suites à échange de clé RSA (TLS_RSA_*) et ne garder que ECDHE.', nginx: NGINX_CIPHERS, apache: APACHE_CIPHERS,
      seenBy: sources([['Kali', r.robot], ['SSLyze', r.sslyzeRobot]]) },
    { id: 'drown', name: 'DROWN', cve: 'CVE-2016-0800', check: vuln([r.drown ?? undefined, r.ssllabsDrown ?? undefined]),
      severity: 'critique', risk: 'Un serveur qui accepte encore SSL 2.0 avec la même clé (même un autre service, comme la messagerie) permet de déchiffrer les connexions TLS de ce site.',
      fix: 'Désactiver SSL 2.0 sur tous les serveurs qui utilisent ce certificat ou cette clé.', nginx: NGINX_PROTOCOLS, apache: APACHE_PROTOCOLS,
      seenBy: sources([['Kali', r.drown], ['SSL Labs', r.ssllabsDrown]]) },
    { id: 'ccs', name: 'Injection CCS', cve: 'CVE-2014-0224', check: { status: r.sslyzeCcsInjection ? 'to_confirm' : sslyzeReady ? 'secure' : 'not_tested', single: true },
      severity: 'critique', risk: 'Un attaquant sur le réseau peut imposer une clé de chiffrement faible et lire ou modifier le trafic.',
      fix: OPENSSL_UPDATE, seenBy: 'SSLyze' },
    { id: 'crime', name: 'CRIME', cve: 'CVE-2012-4929', check: vuln([r.crime ?? undefined, r.sslyzeCompression ?? undefined]),
      severity: 'moyenne', risk: 'La compression TLS laisse deviner le contenu chiffré : un attaquant peut retrouver un cookie de session en quelques milliers de requêtes.',
      fix: 'Désactiver la compression TLS (désactivée d’office avec un OpenSSL récent).', apache: 'SSLCompression off',
      nginx: '# Compression TLS désactivée d’office avec OpenSSL ≥ 1.1 : mettre à jour OpenSSL et nginx',
      seenBy: sources([['Kali', r.crime], ['SSLyze', r.sslyzeCompression]]) },
    { id: 'freak', name: 'FREAK', cve: 'CVE-2015-0204', check: { status: r.freak ? 'to_confirm' : r.freak === false ? 'secure' : 'not_tested', single: true },
      severity: 'moyenne', risk: 'Un attaquant peut forcer un chiffrement « export » de 512 bits, cassable en quelques heures, puis lire le trafic.',
      fix: 'Retirer les suites EXPORT et mettre à jour OpenSSL.', nginx: NGINX_CIPHERS, apache: APACHE_CIPHERS, seenBy: 'Kali' },
    { id: 'logjam', name: 'Logjam', cve: 'CVE-2015-4000', check: { status: r.logjam ? 'to_confirm' : r.logjam === false ? 'secure' : 'not_tested', single: true },
      severity: 'moyenne', risk: 'Un attaquant peut forcer un échange de clé Diffie-Hellman trop faible et déchiffrer la connexion.',
      fix: 'Retirer les suites DHE faibles (ne garder que ECDHE).', nginx: NGINX_CIPHERS, apache: APACHE_CIPHERS, seenBy: 'Kali' },
    { id: 'beast', name: 'BEAST', cve: 'CVE-2011-3389', check: { status: r.beast ? 'to_confirm' : r.beast === false ? 'secure' : 'not_tested', single: true },
      severity: 'faible', risk: 'Avec TLS 1.0 et un chiffrement CBC, un attaquant sur le réseau peut retrouver un cookie. Les navigateurs actuels contournent déjà cette attaque.',
      fix: 'Désactiver TLS 1.0.', nginx: NGINX_PROTOCOLS, apache: APACHE_PROTOCOLS, seenBy: 'Kali' },
  ];
  for (const k of known) {
    if (isPositive(k.check.status)) {
      add({ id: k.id, title: k.name, cve: k.cve, severity: k.severity, toConfirm: k.check.status === 'to_confirm' && !k.check.single,
        risk: k.risk, fix: k.fix, nginx: k.nginx, apache: k.apache, seenBy: k.seenBy });
    } else if (k.check.status === 'secure') {
      ok(k.id, k.name, k.check.single);
    } else {
      untested.push(k.name);
    }
  }

  // ───────────── HTTP security headers ─────────────
  const HEADER_FIX: Record<string, { severity: FindingSeverity; risk: string; fix: string; nginx: string; apache: string }> = {
    hsts: { severity: 'moyenne',
      risk: 'À la première visite en http://, un attaquant sur le réseau peut intercepter la redirection et garder la victime en HTTP non chiffré (« SSL stripping »), puis voler identifiants et cookies.',
      fix: 'Demander au navigateur de n’utiliser que HTTPS pendant un an.',
      nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
      apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"' },
    csp: { severity: 'moyenne',
      risk: 'Sans politique de contenu, un script injecté (faille XSS, bibliothèque compromise) peut s’exécuter et voler les sessions ou les données saisies.',
      fix: 'Déclarer d’où le site peut charger scripts et ressources (à adapter aux CDN et polices utilisés, tester d’abord en Report-Only).',
      nginx: 'add_header Content-Security-Policy "default-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\'" always;',
      apache: 'Header always set Content-Security-Policy "default-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\'"' },
    framing: { severity: 'moyenne',
      risk: 'Un autre site peut afficher le vôtre dans un cadre invisible et faire cliquer l’utilisateur à son insu (« clickjacking ») : validation, suppression, paiement.',
      fix: 'Interdire l’affichage du site dans un cadre.',
      nginx: 'add_header X-Frame-Options "DENY" always;', apache: 'Header always set X-Frame-Options "DENY"' },
    xcto: { severity: 'faible',
      risk: 'Le navigateur peut interpréter un fichier envoyé (image, texte) comme du script, ce qui facilite certaines attaques XSS.',
      fix: 'Interdire au navigateur de deviner le type des fichiers.',
      nginx: 'add_header X-Content-Type-Options "nosniff" always;', apache: 'Header always set X-Content-Type-Options "nosniff"' },
    referrer: { severity: 'faible',
      risk: 'L’adresse complète des pages (avec parfois un jeton ou un identifiant dans l’URL) est transmise aux sites externes vers lesquels pointent vos liens.',
      fix: 'Limiter l’information envoyée aux autres sites.',
      nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;', apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"' },
    permissions: { severity: 'faible',
      risk: 'Un script tiers ou une page intégrée peut demander la caméra, le micro ou la position au nom de votre site.',
      fix: 'Bloquer les fonctions du navigateur que le site n’utilise pas.',
      nginx: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;', apache: 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"' },
  };
  const headers = computeHeadersSummary(r);
  for (const item of headers.mainItems) {
    const meta = HEADER_FIX[item.id];
    if (!meta) continue;
    if (item.badge === 'non_teste') {
      // Not seen, not proven absent: it still costs points (and HSTS caps the grade), so it is listed, to confirm.
      add({ id: `header_${item.id}`, title: `${item.abbr} : non détecté`, severity: meta.severity, toConfirm: true,
        risk: meta.risk, fix: meta.fix, nginx: meta.nginx, apache: meta.apache,
        seenBy: 'Kali (le contrôle HTTP direct n’a pas pu joindre la page)' });
    } else if (item.scoreEarned < item.scoreMax && item.badge !== 'conforme') {
      add({ id: `header_${item.id}`, title: `${item.abbr} : ${item.statusLabel.toLowerCase()}`, severity: meta.severity,
        risk: meta.risk, fix: item.conclusion ? `${meta.fix} ${item.conclusion}` : meta.fix, nginx: meta.nginx, apache: meta.apache,
        seenBy: r.headersLiveChecked ? 'contrôle HTTP direct' : 'Kali' });
    } else {
      ok(`header_${item.id}`, `${item.abbr} présent`);
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    || Number(a.toConfirm) - Number(b.toConfirm));
  return { findings, passed, untested };
}

/** Which configuration to show: the detected server, or both when it is unknown. */
export function fixTargets(webServer: string | null | undefined): Array<'nginx' | 'apache'> {
  if (webServer === 'nginx') return ['nginx'];
  if (webServer === 'apache') return ['apache'];
  return ['nginx', 'apache'];
}
