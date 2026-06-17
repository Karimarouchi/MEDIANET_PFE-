import React, { useRef, useState, useEffect } from 'react';
import { startSslScan, getSslResult, getAllScans, deleteScan, SslResultDto, ScanResultDto, getSslAiAnalysis } from '../services/api';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

/* ═══════════════════════════════════════════════════════════════════════
   Types
═══════════════════════════════════════════════════════════════════════ */
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
   Vulnerability definitions (educational)
═══════════════════════════════════════════════════════════════════════ */
const VULNS = [
  {
    key: 'heartbleed' as keyof SslResultDto,
    name: 'Heartbleed',
    cve: 'CVE-2014-0160',
    icon: 'favorite',
    severity: 'CRITICAL',
    what: 'Bug dans OpenSSL – permet à un attaquant de lire jusqu\'à 64 Ko de mémoire serveur par requête.',
    impact: 'Vol de clés privées SSL, mots de passe, cookies de session.',
    fix: 'Mettre à jour OpenSSL ≥ 1.0.1g et régénérer les certificats.',
  },
  {
    key: 'sweet32' as keyof SslResultDto,
    name: 'SWEET32',
    cve: 'CVE-2016-2183',
    icon: '32',
    severity: 'HIGH',
    what: 'Collision de bloc sur 3DES/Blowfish (bloc 64-bit) après ~32 Go de trafic.',
    impact: 'Déchiffrement de cookies de session HTTP dans une longue session.',
    fix: 'Désactiver les cipher suites 3DES (DES-CBC3-SHA). Préférer AES-GCM.',
  },
  {
    key: 'crime' as keyof SslResultDto,
    name: 'CRIME',
    cve: 'CVE-2012-4929',
    icon: 'compress',
    severity: 'HIGH',
    what: 'Exploite la compression TLS : un attaquant injecte du contenu et mesure la taille compressée.',
    impact: 'Vol de cookies de session (ex: tokens d\'authentification).',
    fix: 'Désactiver la compression TLS côté serveur (zlib/deflate).',
  },
  {
    key: 'has3des' as keyof SslResultDto,
    name: 'Cipher 3DES',
    cve: null,
    icon: 'key_off',
    severity: 'MEDIUM',
    what: 'Le serveur supporte 3DES, un algorithme de chiffrement obsolète (clé 112-bit effective).',
    impact: 'Susceptible à SWEET32, performances réduites, non conforme PCI-DSS.',
    fix: 'Supprimer toutes les cipher suites contenant "3DES" ou "DES-CBC3".',
  },
  {
    key: 'poodle' as keyof SslResultDto,
    name: 'POODLE',
    cve: 'CVE-2014-3566',
    icon: 'pets',
    severity: 'CRITICAL',
    what: 'SSLv3 actif + algorithme CBC → un attaquant MITM peut déchiffrer 1 octet par ~256 requêtes injectes.',
    impact: 'Vol de cookies de session et tokens d’authentification en quelques minutes.',
    fix: 'Désactiver complètement SSLv3. Utiliser TLS 1.2+ uniquement.',
  },
  {
    key: 'beast' as keyof SslResultDto,
    name: 'BEAST',
    cve: 'CVE-2011-3389',
    icon: 'security_key_off',
    severity: 'HIGH',
    what: 'TLS 1.0 + cipher CBC : un attaquant sur le réseau peut deviner le contenu de paquets chiffrés par analyse de blocs.',
    impact: 'Déchiffrement de cookies HTTPS (sessions, tokens) via attaque MITM active.',
    fix: 'Désactiver TLS 1.0. Préférer TLS 1.2+ avec cipher suites AEAD (AES-GCM).',
  },
  {
    key: 'robot' as keyof SslResultDto,
    name: 'ROBOT',
    cve: 'CVE-2017-13099',
    icon: 'smart_toy',
    severity: 'CRITICAL',
    what: 'Return Of Bleichenbacher’s Oracle Threat : l’attaquant interroge le serveur comme oracle pour casser RSA PKCS#1 v1.5.',
    impact: 'Déchiffrement de sessions TLS passées enregistrées. Signature RSA arbitraire.',
    fix: 'Désactiver les cipher suites RSA key exchange (RSA_WITH_*). Utiliser ECDHE/DHE.',
  },
  {
    key: 'freak' as keyof SslResultDto,
    name: 'FREAK',
    cve: 'CVE-2015-0204',
    icon: 'vpn_key_off',
    severity: 'HIGH',
    what: 'Le serveur accepte des cipher suites « export-grade » RSA (512 bits) imposées par les règlements US des années 90.',
    impact: 'Cassable en quelques heures sur CPU ordinaire → déchiffrement complet de la session.',
    fix: 'Supprimer toutes les cipher suites EXPORT et RSA < 2048 bits.',
  },
  {
    key: 'logjam' as keyof SslResultDto,
    name: 'LOGJAM',
    cve: 'CVE-2015-4000',
    icon: 'lock_open',
    severity: 'HIGH',
    what: 'Clef Diffie-Hellman < 2048 bits ou usage de paramètres DH communs → attaque de downgrade vers DHE_EXPORT.',
    impact: 'Un attaquant MITM peut casser DH 512-bit et déchiffrer le trafic en temps réel.',
    fix: 'Générer des paramètres DH uniques ≥ 2048 bits. Préférer ECDHE (courbes elliptiques).',
  },
  {
    key: 'rc4' as keyof SslResultDto,
    name: 'RC4',
    cve: 'CVE-2013-2566',
    icon: 'no_encryption',
    severity: 'HIGH',
    what: 'RC4 est un algorithme de chiffrement par flot présentant des biais statistiques connus depuis 2001.',
    impact: 'Après ~16 millions de connexions, un attaquant peut récupérer le plaintext (cookies, mots de passe).',
    fix: 'Supprimer toutes les cipher suites RC4 (RC4-SHA, RC4-MD5). Utiliser AES-GCM.',
  },
  {
    key: 'drown' as keyof SslResultDto,
    name: 'DROWN',
    cve: 'CVE-2016-0800',
    icon: 'water_damage',
    severity: 'CRITICAL',
    what: 'SSLv2 actif sur le même couple IP/clé : un attaquant exploite des sessions SSLv2 enregistrées pour casser TLS 1.2.',
    impact: 'Déchiffrement de sessions TLS modernes en ~8 heures avec ~40 000 requêtes SSLv2.',
    fix: 'Désactiver complètement SSLv2 sur TOUS les services utilisant la même clé privée.',
  },
];

/* ═══════════════════════════════════════════════════════════════════════
   Server config snippets per vulnerability
═══════════════════════════════════════════════════════════════════════ */
const VULN_CONFIGS: Record<string, { apacheConf: string; nginxConf: string }> = {
  heartbleed: {
    apacheConf: `# Heartbleed est une vuln OpenSSL — mettre à jour le paquet\napt update && apt install --only-upgrade openssl\n# Redémarrer Apache puis régénérer le certificat SSL\nsystemctl restart apache2`,
    nginxConf:  `# Même procédure — vulnérabilité dans OpenSSL, pas nginx\napt update && apt install --only-upgrade openssl\nsystemctl restart nginx`,
  },
  sweet32: {
    apacheConf: `SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\n              ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:!3DES:!DES\nSSLHonorCipherOrder on`,
    nginxConf:  `ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\n             ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:!3DES:!DES';\nssl_prefer_server_ciphers on;`,
  },
  crime: {
    apacheConf: `# CRIME exploite la compression TLS — désactiver :\nSSLCompression off\n# (Généralement désactivée par défaut dans OpenSSL >= 1.0.0)`,
    nginxConf:  `# nginx désactive la compression TLS par défaut depuis v1.1.6\n# Vérifier : nginx -V 2>&1 | grep compression\n# Si présent, passer à nginx >= 1.1.6`,
  },
  has3des: {
    apacheConf: `SSLCipherSuite HIGH:!3DES:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5\nSSLHonorCipherOrder on`,
    nginxConf:  `ssl_ciphers 'HIGH:!3DES:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5';\nssl_prefer_server_ciphers on;`,
  },
  poodle: {
    apacheConf: `SSLProtocol all -SSLv2 -SSLv3`,
    nginxConf:  `ssl_protocols TLSv1.2 TLSv1.3;`,
  },
  beast: {
    apacheConf: `SSLProtocol all -SSLv2 -SSLv3 -TLSv1\nSSLCipherSuite ECDHE+AESGCM:DHE+AESGCM:HIGH:!3DES:!MD5:!aNULL:!eNULL\nSSLHonorCipherOrder on`,
    nginxConf:  `ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers on;`,
  },
  robot: {
    apacheConf: `# Supprimer les suites RSA key-exchange (pas d'ECDHE) :\nSSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\n              ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\nSSLHonorCipherOrder on`,
    nginxConf:  `ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';\nssl_prefer_server_ciphers on;`,
  },
  freak: {
    apacheConf: `SSLCipherSuite HIGH:!EXPORT:!aNULL:!eNULL:!DES:!MD5\nSSLHonorCipherOrder on`,
    nginxConf:  `ssl_ciphers 'HIGH:!EXPORT:!aNULL:!eNULL:!DES:!MD5';\nssl_prefer_server_ciphers on;`,
  },
  logjam: {
    apacheConf: `# 1. Générer des params DH uniques (>= 2048 bits) :\nopenssl dhparam -out /etc/ssl/certs/dhparam.pem 2048\n# 2. Dans VirtualHost :\nSSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"\n# 3. Préférer ECDHE :\nSSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384`,
    nginxConf:  `# 1. Générer des params DH :\nopenssl dhparam -out /etc/nginx/dhparam.pem 2048\n# 2. Dans nginx.conf (bloc server) :\nssl_dhparam /etc/nginx/dhparam.pem;\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers on;`,
  },
  rc4: {
    apacheConf: `SSLCipherSuite HIGH:!RC4:!aNULL:!eNULL:!MD5:!EXPORT\nSSLHonorCipherOrder on`,
    nginxConf:  `ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:!RC4';\nssl_prefer_server_ciphers on;`,
  },
  drown: {
    apacheConf: `SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\n# Vérifier aussi les autres ports (SMTP, IMAP) utilisant la même clé privée`,
    nginxConf:  `ssl_protocols TLSv1.2 TLSv1.3;\n# Vérifier tous les server blocks utilisant le même certificat/clé`,
  },
};

/* ═══════════════════════════════════════════════════════════════════════
   Component
═══════════════════════════════════════════════════════════════════════ */
const SSLAnalysis: React.FC = () => {
  const [domain, setDomain]     = useState('');
  const [scanning, setScanning] = useState(false);
  const [done, setDone]         = useState(false);
  const [logs, setLogs]         = useState<LogLine[]>([]);
  const [result, setResult]     = useState<SslResultDto | null>(null);
  const [error, setError]       = useState<string | null>(null);
  const [expanded, setExpanded]       = useState<string | null>(null);
  const [showAllVulns, setShowAllVulns] = useState(false);
  const [confTab, setConfTab]         = useState<'apache' | 'nginx'>('apache');
  const [expandedTool, setExpandedTool] = useState<string | null>(null);
  const [aiAnalysis, setAiAnalysis]   = useState<{ summary: string; keyRisks: string[]; recommendations: string[] } | null>(null);
  const [aiLoading, setAiLoading]     = useState(false);
  const [aiOpen, setAiOpen]           = useState(false);
  const evtRef                  = useRef<EventSource | null>(null);
  const logRef                  = useRef<HTMLDivElement>(null);

  // ── SSL scan history ────────────────────────────────────────────
  const [history, setHistory]               = useState<ScanResultDto[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);

  useEffect(() => {
    setLoadingHistory(true);
    getAllScans()
      .then(res => {
        const sslScans = res.data.filter(s => s.scanMode === 'ssl-only');
        setHistory(sslScans);
      })
      .catch(() => {})
      .finally(() => setLoadingHistory(false));
  }, []);

  const loadHistoryScan = async (scan: ScanResultDto) => {
    setSelectedScanId(scan.id);
    setDomain(scan.targetDomain || scan.repoUrl.replace('ssl://', ''));
    setDone(false); setResult(null); setLogs([]); setError(null);
    setAiAnalysis(null); setAiOpen(false); setExpandedTool(null);
    try {
      const r = await getSslResult(scan.id);
      setResult(r.data);
      setDone(true);
      // If any external source is still pending, auto-refresh every 20s
    if (r.data.ssllabsStatus === 'PENDING' || r.data.censysStatus === 'PENDING' || r.data.sslyzeStatus === 'PENDING') {
      startExternalPoller(scan.id);
    }
    } catch {
      setError('Impossible de charger ce résultat.');
    }
  };

  // ── External sources poller: refresh result every 20s while any source is PENDING ─
  const labsPollerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startExternalPoller = (scanId: number) => {
    if (labsPollerRef.current) clearInterval(labsPollerRef.current);
    labsPollerRef.current = setInterval(async () => {
      try {
        const r = await getSslResult(scanId);
        setResult(r.data);
        const allDone = r.data.ssllabsStatus !== 'PENDING' && r.data.censysStatus !== 'PENDING' && r.data.sslyzeStatus !== 'PENDING';
        if (allDone) {
          clearInterval(labsPollerRef.current!);
          labsPollerRef.current = null;
        }
      } catch { /* ignore */ }
    }, 20_000);
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
      result.xFrameOptions && 'X-Frame-Options',
      result.xContentTypeOptions && 'X-Content-Type-Options',
      result.referrerPolicy && 'Referrer-Policy',
      result.permissionsPolicy && 'Permissions-Policy',
      result.ocspStapling && 'OCSP Stapling',
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

      const es = new EventSource(`http://localhost:8080/api/ssl/scan/${scanId}/logs`);
      evtRef.current = es;

      es.onmessage = (e) => {
        if (e.data === '%%SCAN_COMPLETE%%') {
          es.close(); evtRef.current = null;
          // Fetch result
          getSslResult(scanId).then(r => {
            setResult(r.data); setDone(true); setScanning(false);
            // Start polling if any external source is still working
            if (r.data.ssllabsStatus === 'PENDING' || r.data.censysStatus === 'PENDING' || r.data.sslyzeStatus === 'PENDING') {
              startExternalPoller(scanId);
            }
            // Refresh history list with the new scan
            getAllScans().then(res => setHistory(res.data.filter(s => s.scanMode === 'ssl-only'))).catch(() => {});
          });
          return;
        }
        const line = parseLog(e.data);
        setLogs(prev => [...prev, line]);
        setTimeout(() => logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: 'smooth' }), 50);
      };

      es.onerror = () => {
        es.close(); evtRef.current = null;
        // Try to fetch whatever result exists
        getSslResult(scanId).then(r => { setResult(r.data); }).catch(() => {});
        setDone(true); setScanning(false);
      };

    } catch {
      setError('Impossible de démarrer le scan. Le backend est-il en cours d\'exécution ?');
      setScanning(false);
    }
  };

  const handleExportPDF = () => {
    if (!result) return;
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 14;
    const cW = pageW - margin * 2;
    let y = 0;

    // ── Palette ──────────────────────────────────────────────────
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

    // ── Page header / footer helpers ─────────────────────────────
    const pageNum = { v: 1 };

    const drawHeader = (n: number) => {
      doc.setFillColor(...navy);
      doc.rect(0, 0, pageW, 16, 'F');
      // accent bar
      doc.setFillColor(...teal);
      doc.rect(0, 16, pageW, 1.5, 'F');
      // App name
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(...blue);
      doc.text('VULNIX', margin, 11);
      // subtitle
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(...white);
      doc.text('Rapport SSL / TLS complet', margin + 20, 11);
      // right: domain + date
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(...teal);
      doc.text(result!.domain, pageW - margin, 7.5, { align: 'right' });
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(...midGray);
      doc.text(`Page ${n}  ·  ${new Date().toLocaleDateString('fr-FR')}`, pageW - margin, 13.5, { align: 'right' });
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

    // ══════════════════════════════════════════════════════════════
    // PAGE 1 — Cover
    // ══════════════════════════════════════════════════════════════
    drawHeader(1);
    y = 24;

    // Domain hero block
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
    doc.text('Rapport d\'analyse SSL/TLS complet', margin + 9, y + 18.5);
    doc.setFontSize(7);
    doc.text(`Généré le ${new Date().toLocaleString('fr-FR')}  ·  ${result.sourcesReady ?? '?'}/${result.sourcesTotal ?? 4} sources prêtes`, margin + 9, y + 23.5);
    y += 32;

    // Combined grade card
    const cg = result.combinedGrade ?? result.grade ?? '?';
    const cgc = gcPdf(cg);
    // Grade circle
    doc.setFillColor(...cgc);
    doc.roundedRect(margin, y, 34, 34, 3, 3, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(cg.length > 1 ? 20 : 24);
    doc.setTextColor(...navy);
    doc.text(cg, margin + 17, y + 22, { align: 'center' });
    // Info panel
    doc.setFillColor(...offWhite);
    doc.roundedRect(margin + 37, y, cW - 37, 34, 3, 3, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(...darkText);
    doc.text('Note Combinée (SSL / TLS)', margin + 42, y + 10);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(...midGray);
    doc.text(gradeLabel(cg), margin + 42, y + 18);
    doc.setFontSize(7.5);
    doc.text('Pondération : Kali 20 % · SSL Labs 30 % · Censys 30 % · SSLyze 20 %', margin + 42, y + 25);
    doc.setFontSize(7);
    doc.text(`${result.sourcesReady ?? '?'} source(s) complète(s) sur ${result.sourcesTotal ?? 4}`, margin + 42, y + 31);
    y += 40;

    // ── SOURCES ──────────────────────────────────────────────────
    sectionTitle('SOURCES D\'ANALYSE');

    const kaliStatus = (result.scanStatus === 'COMPLETED' || result.scanStatus === 'FAILED')
      ? (result.grade !== '?' ? 'PRÊT' : 'ERREUR') : 'EN COURS';

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Source', 'Poids', 'Note', 'Statut', 'IP / Infos']],
      body: [
        ['Kali Linux (Scan interne)', '20 %', result.grade ?? '?', kaliStatus, result.sslyzeIpAddress || '-'],
        ['SSL Labs (Qualys)', '30 %', result.ssllabsGrade ?? '?', result.ssllabsStatus === 'READY' ? 'PRÊT' : result.ssllabsStatus ?? '-', result.ssllabsIpAddress || '-'],
        ['Censys', '30 %', result.censysGrade ?? '?', result.censysStatus === 'READY' ? 'PRÊT' : result.censysStatus ?? '-', result.censysIpAddress || '-'],
        ['SSLyze', '20 %', result.sslyzeGrade ?? '?', result.sslyzeStatus === 'READY' ? 'PRÊT' : result.sslyzeStatus ?? '-', result.sslyzeIpAddress || '-'],
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
          const g = d.cell.text[0];
          d.cell.styles.textColor = gcPdf(g);
        }
        if (d.section === 'body' && d.column.index === 3) {
          const s = d.cell.text[0];
          d.cell.styles.textColor = s === 'PRÊT' ? [0,160,80] : s === 'EN COURS' ? [60,120,200] : [200,60,60];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    // ── GEMINI AI ANALYSIS ────────────────────────────────────────
    if (aiAnalysis && (aiAnalysis.summary || aiAnalysis.keyRisks.length > 0 || aiAnalysis.recommendations.length > 0)) {
      sectionTitle('ANALYSE IA — GEMINI SSL ASSESSMENT');

      if (aiAnalysis.summary) {
        guard(8);
        doc.setFont('helvetica', 'italic');
        doc.setFontSize(8);
        doc.setTextColor(...darkText);
        const lines = doc.splitTextToSize(aiAnalysis.summary, cW - 6);
        lines.forEach((l: string) => { guard(5.5); doc.text(l, margin + 3, y); y += 5; });
        y += 4;
      }

      if (aiAnalysis.keyRisks.length > 0) {
        guard(10);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(...red);
        doc.text('Risques identifiés', margin + 3, y);
        y += 5;
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...darkText);
        aiAnalysis.keyRisks.forEach((r) => {
          const ls = doc.splitTextToSize(`• ${r}`, cW - 10);
          ls.forEach((l: string) => { guard(5); doc.text(l, margin + 5, y); y += 4.5; });
        });
        y += 3;
      }

      if (aiAnalysis.recommendations.length > 0) {
        guard(10);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(...teal);
        doc.text('Recommandations prioritaires', margin + 3, y);
        y += 5;
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...darkText);
        aiAnalysis.recommendations.forEach((r) => {
          const ls = doc.splitTextToSize(`→ ${r}`, cW - 10);
          ls.forEach((l: string) => { guard(5); doc.text(l, margin + 5, y); y += 4.5; });
        });
        y += 4;
      }
    }

    // ── PROTOCOLS ─────────────────────────────────────────────────
    sectionTitle('PROTOCOLES TLS / SSL');

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Protocole', 'État', 'Niveau de risque']],
      body: [
        ['SSL 2.0', result.sslyzeSupportsSSL20 ? 'ACTIF' : 'Inactif', result.sslyzeSupportsSSL20 ? 'CRITIQUE' : 'OK'],
        ['SSL 3.0', result.sslyzeSupportsSSL30 ? 'ACTIF' : 'Inactif', result.sslyzeSupportsSSL30 ? 'CRITIQUE' : 'OK'],
        ['TLS 1.0', (result.tls10 || result.sslyzeSupportsTLS10) ? 'ACTIF' : 'Inactif', (result.tls10 || result.sslyzeSupportsTLS10) ? 'ÉLEVÉ' : 'OK'],
        ['TLS 1.1', (result.tls11 || result.sslyzeSupportsTLS11) ? 'ACTIF' : 'Inactif', (result.tls11 || result.sslyzeSupportsTLS11) ? 'ÉLEVÉ' : 'OK'],
        ['TLS 1.2', (result.tls12 || result.sslyzeSupportsTLS12) ? 'Actif' : 'Inactif', (result.tls12 || result.sslyzeSupportsTLS12) ? 'OK' : 'AVERTISSEMENT'],
        ['TLS 1.3', (result.tls13 || result.sslyzeSupportsTLS13) ? 'Actif' : 'Absent', (result.tls13 || result.sslyzeSupportsTLS13) ? 'OK' : 'AVERTISSEMENT'],
      ],
      styles: { fontSize: 8, cellPadding: 3.5, textColor: darkText },
      headStyles: { fillColor: navy, textColor: white, fontStyle: 'bold', fontSize: 8 },
      alternateRowStyles: { fillColor: rowAlt },
      columnStyles: { 0: { cellWidth: 35 }, 1: { cellWidth: 35 }, 2: { halign: 'center' } },
      didParseCell: (d) => {
        if (d.section === 'body' && d.column.index === 2) {
          const s = d.cell.text[0];
          d.cell.styles.textColor = s === 'OK' ? [0,150,80] : s === 'AVERTISSEMENT' ? [180,130,0] : [200,50,50];
          d.cell.styles.fontStyle = 'bold';
        }
        if (d.section === 'body' && d.column.index === 1) {
          const s = d.cell.text[0];
          d.cell.styles.textColor = s === 'Inactif' ? [0,150,80] : [200,50,50];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    // ── CERTIFICATE ───────────────────────────────────────────────
    sectionTitle('CERTIFICAT SSL');

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      body: [
        ['Sujet', result.certSubject || result.sslyzeCertSubject || '-'],
        ['Émetteur', result.certIssuer || result.sslyzeCertIssuer || '-'],
        ['Algorithme de signature', result.certSignatureAlg || '-'],
        ['Taille de clé', result.certKeySize ? `${result.certKeySize} bits` : (result.sslyzeKeySize ? `${result.sslyzeKeySize} bits` : '-')],
        ['Validité', result.certExpired ? 'EXPIRÉ ✗' : `Valide — ${result.certDaysLeft > 0 ? result.certDaysLeft + ' jours restants' : 'inconnu'}`],
        ['Date d\'expiration', result.certNotAfterStr || '-'],
        ['Certificate Transparency', (result.certTransparency || result.censysCtPresent) ? 'Présent ✓' : 'Absent ⚠'],
        ['OCSP Stapling', (result.ocspStapling || result.sslyzeOcspStapling) ? 'Actif ✓' : 'Inactif'],
        ['Certificat wildcard', result.certWildcard ? 'Oui' : 'Non'],
        ['Nombre de SAN', result.certSansCount ? String(result.certSansCount) : (result.censysSansCount ? String(result.censysSansCount) : '-')],
        ['Chaîne de confiance', (result.chainComplete || result.sslyzeChainTrusted) ? 'Complète ✓' : 'Incomplète ✗'],
      ],
      styles: { fontSize: 8, cellPadding: 3.5, textColor: darkText },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 58, fillColor: [230, 236, 248] as [number,number,number] },
      },
      alternateRowStyles: { fillColor: rowAlt },
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    // ── VULNERABILITIES ───────────────────────────────────────────
    sectionTitle('VULNÉRABILITÉS SSL / TLS');

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Vulnérabilité', 'CVE', 'État', 'Sévérité']],
      body: [
        ['Heartbleed',       'CVE-2014-0160', result.heartbleed || result.sslyzeHeartbleed ? 'VULNÉRABLE' : 'OK', result.heartbleed || result.sslyzeHeartbleed ? 'CRITIQUE' : 'OK'],
        ['POODLE',           'CVE-2014-3566', result.poodle ? 'VULNÉRABLE' : 'OK',             result.poodle ? 'ÉLEVÉ' : 'OK'],
        ['DROWN',            'CVE-2016-0800', (result.drown || result.ssllabsDrown) ? 'VULNÉRABLE' : 'OK', (result.drown || result.ssllabsDrown) ? 'CRITIQUE' : 'OK'],
        ['BEAST',            'CVE-2011-3389', result.beast ? 'VULNÉRABLE' : 'OK',             result.beast ? 'MOYEN' : 'OK'],
        ['CRIME',            'CVE-2012-4929', (result.crime || result.sslyzeCompression) ? 'VULNÉRABLE' : 'OK', (result.crime || result.sslyzeCompression) ? 'ÉLEVÉ' : 'OK'],
        ['ROBOT',            '—',             (result.robot || result.sslyzeRobot) ? 'VULNÉRABLE' : 'OK', (result.robot || result.sslyzeRobot) ? 'ÉLEVÉ' : 'OK'],
        ['FREAK',            'CVE-2015-0204', result.freak ? 'VULNÉRABLE' : 'OK',             result.freak ? 'ÉLEVÉ' : 'OK'],
        ['LOGJAM',           'CVE-2015-4000', result.logjam ? 'VULNÉRABLE' : 'OK',            result.logjam ? 'ÉLEVÉ' : 'OK'],
        ['SWEET32',          'CVE-2016-2183', result.sweet32 ? 'VULNÉRABLE' : 'OK',           result.sweet32 ? 'MOYEN' : 'OK'],
        ['RC4',              'CVE-2015-2808', result.rc4 ? 'VULNÉRABLE' : 'OK',               result.rc4 ? 'MOYEN' : 'OK'],
        ['CCS Injection',    'CVE-2014-0224', result.sslyzeCcsInjection ? 'VULNÉRABLE' : 'OK', result.sslyzeCcsInjection ? 'ÉLEVÉ' : 'OK'],
        ['Renégociation',    '—',             result.sslyzeInsecureRenegotiation ? 'Non sécurisée' : 'Sécurisée', result.sslyzeInsecureRenegotiation ? 'MOYEN' : 'OK'],
      ],
      styles: { fontSize: 7.5, cellPadding: 3, textColor: darkText },
      headStyles: { fillColor: navy, textColor: white, fontStyle: 'bold', fontSize: 8 },
      alternateRowStyles: { fillColor: rowAlt },
      columnStyles: {
        0: { cellWidth: 40 },
        1: { cellWidth: 32 },
        2: { cellWidth: 44 },
        3: { halign: 'center', fontStyle: 'bold' },
      },
      didParseCell: (d) => {
        if (d.section === 'body' && d.column.index === 2) {
          d.cell.styles.textColor = d.cell.text[0] === 'OK' ? [0,150,80] : [200,50,50];
        }
        if (d.section === 'body' && d.column.index === 3) {
          const s = d.cell.text[0];
          d.cell.styles.textColor = s === 'OK' ? [0,150,80] : s === 'CRITIQUE' ? [200,30,30] : s === 'ÉLEVÉ' ? [200,80,30] : [180,130,0];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    // ── HTTP HEADERS ──────────────────────────────────────────────
    sectionTitle('EN-TÊTES DE SÉCURITÉ HTTP');

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['En-tête HTTP', 'Présent', 'Impact si absent']],
      body: [
        ['Strict-Transport-Security (HSTS)',    result.hsts ? 'Oui ✓' : 'Non ✗', result.hsts ? 'OK' : 'Élevé'],
        ['Content-Security-Policy (CSP)',       result.contentSecurityPolicy ? 'Oui ✓' : 'Non ✗', result.contentSecurityPolicy ? 'OK' : 'Élevé'],
        ['X-Frame-Options',                    result.xFrameOptions ? 'Oui ✓' : 'Non ✗', result.xFrameOptions ? 'OK' : 'Moyen'],
        ['X-Content-Type-Options',             result.xContentTypeOptions ? 'Oui ✓' : 'Non ✗', result.xContentTypeOptions ? 'OK' : 'Moyen'],
        ['Referrer-Policy',                    result.referrerPolicy ? 'Oui ✓' : 'Non ✗', result.referrerPolicy ? 'OK' : 'Faible'],
        ['Permissions-Policy',                 result.permissionsPolicy ? 'Oui ✓' : 'Non ✗', result.permissionsPolicy ? 'OK' : 'Faible'],
        ['OCSP Stapling',                      (result.ocspStapling || result.sslyzeOcspStapling) ? 'Oui ✓' : 'Non ✗', 'Révocation certificat'],
      ],
      styles: { fontSize: 8, cellPadding: 3.5, textColor: darkText },
      headStyles: { fillColor: navy, textColor: white, fontStyle: 'bold', fontSize: 8 },
      alternateRowStyles: { fillColor: rowAlt },
      columnStyles: {
        0: { cellWidth: 80 },
        1: { cellWidth: 24, halign: 'center' },
        2: { halign: 'center', fontStyle: 'bold' },
      },
      didParseCell: (d) => {
        if (d.section === 'body' && d.column.index === 1) {
          d.cell.styles.textColor = d.cell.text[0].startsWith('Oui') ? [0,150,80] : [200,50,50];
          d.cell.styles.fontStyle = 'bold';
        }
        if (d.section === 'body' && d.column.index === 2) {
          const s = d.cell.text[0];
          d.cell.styles.textColor = s === 'OK' ? [0,150,80] : s === 'Élevé' ? [200,50,50] : s === 'Moyen' ? [180,100,0] : [120,120,120];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    // ── FOOTER on every page ──────────────────────────────────────
    const total = (doc as any).internal.getNumberOfPages();
    for (let p = 1; p <= total; p++) {
      doc.setPage(p);
      drawFooter();
    }

    doc.save(`rapport-ssl-${result.domain}-${new Date().toISOString().slice(0, 10)}.pdf`);
  };

  return (
    <div className="max-w-6xl mx-auto print:max-w-none">
      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="mb-8 flex flex-col md:flex-row md:items-end justify-between gap-6 print:hidden">
        <div>
          <h1 className="text-4xl font-headline font-bold tracking-tight text-on-surface mb-1">SSL / TLS Analysis</h1>
          <p className="text-on-surface-variant text-sm max-w-lg">
            Inspection complète du certificat, des protocoles et des vulnérabilités connues d'un domaine.
          </p>
        </div>
        {done && result && (
          <button onClick={handleExportPDF}
            className="flex items-center gap-2 px-5 py-3 rounded-xl bg-surface-container border border-outline-variant/20 text-on-surface-variant hover:text-on-surface hover:border-primary/40 transition-all text-sm font-headline font-semibold">
            <span className="material-symbols-outlined text-base">picture_as_pdf</span>
            Exporter PDF
          </button>
        )}
      </div>

      {/* ── Domain Input ─────────────────────────────────────────────── */}
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
        </div>
        {error && (
          <div className="mt-3 flex items-center gap-3 px-4 py-3 rounded-xl bg-error/10 border border-error/20">
            <span className="material-symbols-outlined text-error text-base">error</span>
            <p className="text-sm text-error">{error}</p>
          </div>
        )}
      </div>

      {/* ── Scan History ──────────────────────────────────────────────── */}
      {!scanning && (
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
                    onClick={() => loadHistoryScan(s)}
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
                          if (selectedScanId === s.id) { setSelectedScanId(null); setResult(null); }
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
      {(scanning || logs.length > 0) && (
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

      {/* ── Results ──────────────────────────────────────────────────── */}
      {result && (
        <div className="space-y-6">

          {/* ── Combined Grade Banner (full-width, most prominent) ─────── */}
          {(() => {
            const cg = result.combinedGrade ?? '?';
            const cgc = gradeColor(cg);
            const ready = result.sourcesReady ?? 0;
            const total = result.sourcesTotal ?? 4;
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
                    {cg}
                  </span>
                </div>
                {/* Text */}
                <div className="flex-1 text-center md:text-left">
                  <div className="text-[10px] font-headline font-bold uppercase tracking-[0.25em] text-outline mb-1 flex items-center gap-1.5 justify-center md:justify-start">
                    <span className="material-symbols-outlined text-[13px]">hub</span>
                    Note combinée — 4 sources fusionnées
                  </div>
                  <h2 className="text-3xl font-headline font-extrabold text-on-surface mb-1">{gradeLabel(cg)}</h2>
                  <p className="text-sm text-outline">
                    Résultat pondéré de{' '}
                    <span className="font-bold" style={{ color: cgc.ring }}>{ready}/{total} sources</span>{' '}
                    disponibles · Kali&nbsp;20&nbsp;% · SSL&nbsp;Labs&nbsp;30&nbsp;% · Censys&nbsp;30&nbsp;% · SSLyze&nbsp;20&nbsp;%
                  </p>
                  {ready < total && (
                    <div className="mt-2 flex items-center gap-1.5 text-[10px] text-primary">
                      <span className="material-symbols-outlined text-[12px] animate-spin">progress_activity</span>
                      {total - ready} source(s) encore en cours d'analyse — la note se mettra à jour automatiquement
                    </div>
                  )}
                </div>
                {/* Domain badge */}
                <div className="flex-shrink-0 px-4 py-2 rounded-xl bg-surface-container/50 border border-outline-variant/20 font-mono text-sm text-on-surface-variant">
                  {result.domain}
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
                Sources d'analyse · Cliquer sur Détails pour voir les findings
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
                      <div className="flex items-center gap-0.5 text-[9px] font-bold text-primary/70 hover:text-primary">
                        Détails<span className={`material-symbols-outlined text-[13px] transition-transform ${isExp ? 'rotate-180' : ''}`}>expand_more</span>
                      </div>
                    </div>
                    {isExp && (
                      <div className="px-5 pb-3 pt-2 bg-surface-container-low/50 border-t border-outline-variant/[0.08]">
                        {findings.length === 0
                          ? <p className="text-[10px] text-outline italic">{status === 'PENDING' ? 'Scan Kali en cours…' : 'Aucun détail disponible.'}</p>
                          : <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
                              {findings.map((f, i) => (
                                <div key={i} className="flex items-center gap-2 text-[10px] py-0.5">
                                  <span className={`shrink-0 font-bold ${f.type === 'ok' ? 'text-tertiary' : f.type === 'warn' ? 'text-[#ffe066]' : 'text-error'}`}>{f.type === 'ok' ? '✓' : f.type === 'warn' ? '⚠' : '✗'}</span>
                                  <span className={f.type === 'ok' ? 'text-outline' : f.type === 'warn' ? 'text-[#ffe066]/80' : 'text-error/80'}>{f.text}</span>
                                </div>
                              ))}
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
                      <div className="flex items-center gap-0.5 text-[9px] font-bold text-primary/70 hover:text-primary">
                        Détails<span className={`material-symbols-outlined text-[13px] transition-transform ${isExp ? 'rotate-180' : ''}`}>expand_more</span>
                      </div>
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
                          : <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
                              {findings.map((f, i) => (
                                <div key={i} className="flex items-center gap-2 text-[10px] py-0.5">
                                  <span className={`shrink-0 font-bold ${f.type === 'ok' ? 'text-tertiary' : f.type === 'warn' ? 'text-[#ffe066]' : 'text-error'}`}>{f.type === 'ok' ? '✓' : f.type === 'warn' ? '⚠' : '✗'}</span>
                                  <span className={f.type === 'ok' ? 'text-outline' : f.type === 'warn' ? 'text-[#ffe066]/80' : 'text-error/80'}>{f.text}</span>
                                </div>
                              ))}
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
                      <div className="flex items-center gap-0.5 text-[9px] font-bold text-primary/70 hover:text-primary">
                        Détails<span className={`material-symbols-outlined text-[13px] transition-transform ${isExp ? 'rotate-180' : ''}`}>expand_more</span>
                      </div>
                    </div>
                    {isExp && (
                      <div className="px-5 pb-3 pt-2 bg-surface-container-low/50 border-t border-outline-variant/[0.08]">
                        {findings.length === 0
                          ? <p className="text-[10px] text-outline italic">{s === 'PENDING' ? 'Analyse Censys en cours…' : 'Aucun détail disponible.'}</p>
                          : <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
                              {findings.map((f, i) => (
                                <div key={i} className="flex items-center gap-2 text-[10px] py-0.5">
                                  <span className={`shrink-0 font-bold ${f.type === 'ok' ? 'text-tertiary' : f.type === 'warn' ? 'text-[#ffe066]' : 'text-error'}`}>{f.type === 'ok' ? '✓' : f.type === 'warn' ? '⚠' : '✗'}</span>
                                  <span className={f.type === 'ok' ? 'text-outline' : f.type === 'warn' ? 'text-[#ffe066]/80' : 'text-error/80'}>{f.text}</span>
                                </div>
                              ))}
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
                      <div className="flex items-center gap-0.5 text-[9px] font-bold text-primary/70 hover:text-primary">
                        Détails<span className={`material-symbols-outlined text-[13px] transition-transform ${isExp ? 'rotate-180' : ''}`}>expand_more</span>
                      </div>
                    </div>
                    {isExp && (
                      <div className="px-5 pb-3 pt-2 bg-surface-container-low/50 border-t border-outline-variant/[0.08]">
                        {findings.length === 0
                          ? <p className="text-[10px] text-outline italic">{s === 'PENDING' ? 'Analyse SSLyze en cours…' : 'Aucun détail disponible.'}</p>
                          : <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
                              {findings.map((f, i) => (
                                <div key={i} className="flex items-center gap-2 text-[10px] py-0.5">
                                  <span className={`shrink-0 font-bold ${f.type === 'ok' ? 'text-tertiary' : f.type === 'warn' ? 'text-[#ffe066]' : 'text-error'}`}>{f.type === 'ok' ? '✓' : f.type === 'warn' ? '⚠' : '✗'}</span>
                                  <span className={f.type === 'ok' ? 'text-outline' : f.type === 'warn' ? 'text-[#ffe066]/80' : 'text-error/80'}>{f.text}</span>
                                </div>
                              ))}
                            </div>}
                        {s === 'READY' && result.sslyzeIpAddress && (
                          <div className="mt-2 text-[9px] text-outline/40 font-mono">{result.sslyzeIpAddress}</div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })()}

            </div>
          </div>

          {/* ── Detailed sections — visible only when all tools finished ──── */}
          {(() => {
            const kaliDone = result.scanStatus === 'COMPLETED' || result.scanStatus === 'FAILED';
            const allDone  = kaliDone
              && (result.ssllabsStatus ?? 'PENDING') !== 'PENDING'
              && (result.censysStatus  ?? 'PENDING') !== 'PENDING'
              && (result.sslyzeStatus  ?? 'PENDING') !== 'PENDING';

            if (!allDone) return (
              <div className="flex items-center gap-4 px-5 py-5 rounded-2xl bg-surface-container border border-outline-variant/20">
                <span className="material-symbols-outlined text-primary text-2xl animate-spin shrink-0">progress_activity</span>
                <div>
                  <div className="font-headline font-bold text-sm text-on-surface">Analyse en cours…</div>
                  <div className="text-xs text-outline mt-0.5">
                    Les sections détaillées (protocoles, certificat, vulnérabilités, en-têtes HTTP, score) s'afficheront
                    dès que tous les outils auront terminé leur analyse.
                  </div>
                </div>
              </div>
            );

            return (
              <div className="space-y-5">

                {/* ── Protocoles actifs ──────────────────────────────────── */}
                <div className="bg-surface-container rounded-2xl p-5">
                  <h2 className="font-headline font-bold text-sm flex items-center gap-2 mb-1">
                    <span className="material-symbols-outlined text-primary text-lg">shield</span>
                    Protocoles TLS/SSL supportés
                  </h2>
                  <p className="text-xs text-outline mb-4">Protocoles détectés comme <strong>actifs</strong> sur le serveur (synthèse Kali + SSLyze).</p>
                  {(() => {
                    const protos = [
                      result.sslyzeSupportsSSL20 && { label: 'SSL 2.0', desc: 'INTERDIT — DROWN', cl: 'border-error bg-error/10 text-error', icon: 'dangerous' },
                      result.sslyzeSupportsSSL30 && { label: 'SSL 3.0', desc: 'INTERDIT — POODLE', cl: 'border-error bg-error/10 text-error', icon: 'dangerous' },
                      (result.tls10 || result.sslyzeSupportsTLS10) && { label: 'TLS 1.0', desc: 'Obsolète — désactiver immédiatement', cl: 'border-error/60 bg-error/5 text-error', icon: 'warning' },
                      (result.tls11 || result.sslyzeSupportsTLS11) && { label: 'TLS 1.1', desc: 'Déprécié (RFC 8996) — désactiver', cl: 'border-[#ffaa40]/60 bg-[#ffaa40]/5 text-[#ffaa40]', icon: 'warning' },
                      (result.tls12 || result.sslyzeSupportsTLS12) && { label: 'TLS 1.2', desc: 'Acceptable — minimum recommandé', cl: 'border-[#a4e6ff]/60 bg-[#a4e6ff]/5 text-[#a4e6ff]', icon: 'check_circle' },
                      (result.tls13 || result.sslyzeSupportsTLS13) && { label: 'TLS 1.3', desc: 'Recommandé ✓ (2018+, le plus sûr)', cl: 'border-tertiary bg-tertiary/5 text-tertiary', icon: 'verified' },
                    ].filter(Boolean) as { label: string; desc: string; cl: string; icon: string }[];
                    const tls13missing = !result.tls13 && !result.sslyzeSupportsTLS13;
                    return (
                      <>
                        {protos.length === 0 && <p className="text-xs text-outline italic">Aucun protocole détecté.</p>}
                        <div className="flex flex-wrap gap-3">
                          {protos.map(p => (
                            <div key={p.label} className={`flex items-center gap-3 px-4 py-3 rounded-xl border-l-2 ${p.cl}`}>
                              <span className="material-symbols-outlined text-base" style={{ fontVariationSettings: "'FILL' 1" }}>{p.icon}</span>
                              <div>
                                <div className="font-headline font-bold text-sm text-on-surface">{p.label}</div>
                                <div className="text-[10px] opacity-70">{p.desc}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                        {tls13missing && (
                          <div className="mt-3 flex items-start gap-2 px-4 py-3 rounded-xl bg-[#ffe066]/5 border border-[#ffe066]/20">
                            <span className="material-symbols-outlined text-[#ffe066] text-base shrink-0 mt-0.5">info</span>
                            <p className="text-xs text-[#ffe066]/90 leading-relaxed">
                              <strong>TLS 1.3 non détecté.</strong> C'est la version la plus récente et sécurisée du protocole.
                              Elle réduit la latence du handshake et supprime les algorithmes dangereux.
                              Son activation est <em>fortement recommandée</em> — elle est rétrocompatible avec TLS 1.2.
                            </p>
                          </div>
                        )}
                      </>
                    );
                  })()}
                </div>

                {/* ── Détails du certificat ──────────────────────────────── */}
                <div className="bg-surface-container rounded-2xl p-5">
                  <h2 className="font-headline font-bold text-sm flex items-center gap-2 mb-3">
                    <span className="material-symbols-outlined text-secondary text-lg">verified</span>
                    Détails du certificat
                  </h2>
                  <div className="flex flex-wrap gap-1.5 mb-4">
                    {[
                      { label: result.certExpired ? '✗ Expirée' : '✓ Valide', ok: !result.certExpired },
                      { label: result.chainComplete ? '✓ Chaîne complète' : '✗ Chaîne incomplète', ok: result.chainComplete },
                      { label: `CT ${result.certTransparency ? '✓' : '✗'}`, ok: result.certTransparency },
                      result.sslyzeStatus === 'READY' ? { label: `SSLyze: ${result.sslyzeChainTrusted ? '✓ Fiable' : '✗ Non fiable'}`, ok: result.sslyzeChainTrusted } : null,
                      result.certEv ? { label: 'EV Cert', ok: true } : null,
                      result.certWildcard ? { label: 'Wildcard', ok: true } : null,
                    ].filter(Boolean).map((b: any, i) => (
                      <span key={i} className={`text-[10px] font-bold uppercase px-2 py-1 rounded-full ${b.ok ? 'bg-tertiary/15 text-tertiary' : 'bg-error/20 text-error'}`}>
                        {b.label}
                      </span>
                    ))}
                  </div>
                  {result.certDaysLeft >= 0 && (
                    <div className="mb-4">
                      <div className="flex justify-between text-[10px] text-outline uppercase tracking-widest mb-1.5">
                        <span>Validité restante</span>
                        <span className={result.certDaysLeft < 30 ? 'text-error font-bold' : result.certDaysLeft < 90 ? 'text-[#ffe066]' : 'text-tertiary'}>
                          {result.certDaysLeft} jours
                        </span>
                      </div>
                      <div className="h-1.5 w-full bg-surface-container-highest rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-all"
                          style={{ width: `${Math.min(100, Math.round(result.certDaysLeft / 365 * 100))}%`, background: result.certDaysLeft < 30 ? '#ffb4ab' : result.certDaysLeft < 90 ? '#ffe066' : '#00fc92' }} />
                      </div>
                    </div>
                  )}
                  <div className="space-y-0">
                    {[
                      { label: 'Sujet (CN)',       value: result.sslyzeCertSubject || result.certSubject },
                      { label: 'Émetteur (CA)',     value: result.sslyzeCertIssuer  || result.certIssuer },
                      { label: 'Algorithme',        value: result.certSignatureAlg },
                      { label: 'Taille de clé',     value: result.sslyzeKeySize > 0 ? `${result.sslyzeKeySize} bits` : result.certKeySize },
                      { label: "Date d'émission",   value: result.certNotBefore },
                      { label: 'Expiration',        value: result.certNotAfterStr },
                      { label: 'Domaines (SANs)',   value: result.certSansCount > 0 ? `${result.certSansCount} domaines` : '—' },
                      { label: 'Numéro de série',   value: result.certSerialNumber },
                    ].map(row => (
                      <div key={row.label} className="flex items-start justify-between py-1.5 border-b border-outline-variant/[0.08] gap-4">
                        <span className="text-xs text-outline shrink-0">{row.label}</span>
                        <span className="text-xs font-mono text-right break-all text-on-surface">{row.value || '—'}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* ── Vulnérabilités SSL/TLS ─────────────────────────────── */}
                <div className="bg-surface-container rounded-2xl p-6">
                  <h2 className="font-headline font-bold text-base flex items-center gap-2 mb-1">
                    <span className="material-symbols-outlined text-error text-lg">bug_report</span>
                    Vulnérabilités SSL/TLS connues
                  </h2>
                  <p className="text-xs text-outline mb-5">Synthèse des 4 sources. Cliquer pour l'explication, l'impact et la configuration Apache/nginx.</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {(showAllVulns ? VULNS : VULNS.slice(0, 4)).map(v => {
                      const affected = !!result[v.key];
                      const isOpen   = expanded === v.key;
                      return (
                        <div key={v.key}
                          onClick={() => setExpanded(isOpen ? null : v.key)}
                          className={`rounded-xl border cursor-pointer transition-all ${affected ? 'border-error/30 bg-error/5 hover:border-error/50' : 'border-outline-variant/10 bg-surface-container-low hover:border-tertiary/20'}`}>
                          <div className="flex items-center gap-3 p-4">
                            <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${affected ? 'bg-error/20' : 'bg-tertiary/10'}`}>
                              <span className={`material-symbols-outlined text-base ${affected ? 'text-error' : 'text-tertiary'}`} style={{ fontVariationSettings: "'FILL' 1" }}>
                                {affected ? 'warning' : 'check_circle'}
                              </span>
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-sm font-headline font-bold text-on-surface">{v.name}</span>
                                {v.cve && <span className="text-[9px] font-mono text-outline bg-surface-container-highest px-1.5 py-0.5 rounded">{v.cve}</span>}
                                <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ${v.severity === 'CRITICAL' ? 'bg-error/20 text-error' : v.severity === 'HIGH' ? 'bg-[#ff7b54]/20 text-[#ff7b54]' : 'bg-[#ffe066]/20 text-[#ffe066]'}`}>{v.severity}</span>
                              </div>
                              <p className="text-[11px] text-outline mt-0.5">{affected ? '⚠ Détecté sur ce serveur' : '✓ Non détecté'}</p>
                            </div>
                            <span className={`material-symbols-outlined text-outline text-base transition-transform ${isOpen ? 'rotate-180' : ''}`}>expand_more</span>
                          </div>
                          {isOpen && (
                            <div className="px-4 pb-4 space-y-3 border-t border-outline-variant/10 pt-3">
                              <div>
                                <div className="text-[10px] text-outline uppercase tracking-widest mb-1">Qu'est-ce que c'est ?</div>
                                <p className="text-xs text-on-surface-variant">{v.what}</p>
                              </div>
                              <div>
                                <div className="text-[10px] text-error uppercase tracking-widest mb-1">Impact</div>
                                <p className="text-xs text-on-surface-variant">{v.impact}</p>
                              </div>
                              <div>
                                <div className="text-[10px] text-tertiary uppercase tracking-widest mb-1">Correction</div>
                                <p className="text-xs text-on-surface-variant">{v.fix}</p>
                              </div>
                              {VULN_CONFIGS[v.key] && (
                                <div className="pt-1" onClick={e => e.stopPropagation()}>
                                  <div className="text-[10px] font-bold text-on-surface uppercase tracking-widest mb-2">Configuration serveur</div>
                                  <div className="flex gap-1 mb-2">
                                    {(['apache', 'nginx'] as const).map(tab => (
                                      <button key={tab}
                                        onClick={e => { e.stopPropagation(); setConfTab(tab); }}
                                        className={`px-3 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wide transition-colors ${confTab === tab ? 'bg-primary/20 text-primary border border-primary/30' : 'bg-surface-container-highest text-outline border border-outline-variant/20 hover:border-primary/20'}`}>
                                        {tab === 'apache' ? 'Apache' : 'nginx'}
                                      </button>
                                    ))}
                                  </div>
                                  <pre className="font-mono text-[10px] text-[#8b949e] bg-[#0d1117] px-3 py-2.5 rounded-lg overflow-x-auto border border-outline-variant/10 whitespace-pre-wrap leading-relaxed">
                                    {confTab === 'apache' ? VULN_CONFIGS[v.key].apacheConf : VULN_CONFIGS[v.key].nginxConf}
                                  </pre>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                  {VULNS.length > 4 && (
                    <button onClick={() => setShowAllVulns(p => !p)}
                      className="mt-4 w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border border-outline-variant/20 text-xs font-bold text-outline hover:text-on-surface hover:border-primary/30 hover:bg-primary/5 transition-all">
                      <span className="material-symbols-outlined text-base">{showAllVulns ? 'expand_less' : 'expand_more'}</span>
                      {showAllVulns ? 'Réduire' : `Voir tout (${VULNS.length} vulnérabilités)`}
                    </button>
                  )}
                </div>

                {/* ── En-têtes de sécurité HTTP ─────────────────────────── */}
                <div className="bg-surface-container rounded-2xl p-6">
                  <div className="flex items-start justify-between gap-4 mb-5">
                    <div>
                      <h2 className="font-headline font-bold text-base flex items-center gap-2 mb-1">
                        <span className="material-symbols-outlined text-secondary text-lg">http</span>
                        En-têtes de sécurité HTTP
                      </h2>
                      <p className="text-xs text-outline">Protection navigateur contre XSS, clickjacking, MIME sniffing et fuites d'informations.</p>
                    </div>
                    {(() => {
                      const hdrs = [result.hsts, result.contentSecurityPolicy, result.xFrameOptions, result.xContentTypeOptions, result.referrerPolicy, result.permissionsPolicy, result.ocspStapling];
                      const ok = hdrs.filter(Boolean).length;
                      const col = ok === hdrs.length ? 'border-tertiary/30 bg-tertiary/10' : ok >= 5 ? 'border-[#ffe066]/30 bg-[#ffe066]/10' : 'border-error/30 bg-error/10';
                      const tc  = ok === hdrs.length ? 'text-tertiary' : ok >= 5 ? 'text-[#ffe066]' : 'text-error';
                      return (
                        <div className={`flex-shrink-0 text-center px-4 py-2 rounded-xl border ${col}`}>
                          <div className={`text-2xl font-headline font-extrabold ${tc}`}>{ok}/{hdrs.length}</div>
                          <div className="text-[10px] text-outline uppercase tracking-widest">en-têtes</div>
                        </div>
                      );
                    })()}
                  </div>
                  <div className="space-y-2">
                    {([
                      { key: 'hsts', icon: 'lock', label: 'HSTS', subtitle: 'HTTP Strict Transport Security', good: result.hsts, category: 'Transport',
                        recommended: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                        what: 'Indique au navigateur de n\'utiliser que HTTPS pendant la durée spécifiée. Le préfixe preload permet d\'être intégré dans la liste HSTS des navigateurs.',
                        impact: 'Sans HSTS, un attaquant peut forcer une connexion HTTP initiale (SSL Stripping) et intercepter/voler les cookies de session.',
                        fix: 'Commencer avec max-age=300 pour tester, puis augmenter à 31536000 (1 an). Ne pas ajouter includeSubDomains si des sous-domaines ne sont pas en HTTPS.',
                        apacheConf: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
                        nginxConf:  'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;' },
                      { key: 'csp', icon: 'policy', label: 'Content-Security-Policy', subtitle: 'CSP — Prévention XSS et injections', good: result.contentSecurityPolicy, category: 'Injection',
                        recommended: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
                        what: 'Déclare les sources autorisées pour scripts, styles, images et ressources. Bloque toute ressource provenant de sources non déclarées.',
                        impact: 'Sans CSP, un attaquant peut injecter des scripts malveillants (XSS) exécutés dans le navigateur — vol de session, keylogging, défiguration.',
                        fix: 'Tester d\'abord avec Content-Security-Policy-Report-Only. Éviter unsafe-inline et unsafe-eval. Utiliser des nonces pour les scripts inline légitimes.',
                        apacheConf: "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'\"",
                        nginxConf:  "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'\" always;" },
                      { key: 'xFrameOptions', icon: 'picture_in_picture_off', label: 'X-Frame-Options', subtitle: 'Protection contre le clickjacking', good: result.xFrameOptions, category: 'Clickjacking',
                        recommended: 'X-Frame-Options: DENY',
                        what: 'Empêche la page d\'être intégrée dans une iframe d\'un autre domaine. DENY = jamais. SAMEORIGIN = domaine uniquement.',
                        impact: 'Sans cette protection, un attaquant peut superposer un iframe invisible sur un bouton pour piéger l\'utilisateur (clickjacking).',
                        fix: 'Utiliser DENY pour les pages sans iframes légitimes. Équivalent modern dans CSP : frame-ancestors \'none\'.',
                        apacheConf: 'Header always set X-Frame-Options "DENY"',
                        nginxConf:  'add_header X-Frame-Options "DENY" always;' },
                      { key: 'xContentTypeOptions', icon: 'fingerprint', label: 'X-Content-Type-Options', subtitle: 'Protection contre le MIME sniffing', good: result.xContentTypeOptions, category: 'MIME',
                        recommended: 'X-Content-Type-Options: nosniff',
                        what: 'Interdit au navigateur de deviner le type MIME d\'une ressource. Il respecte uniquement le Content-Type déclaré.',
                        impact: 'Sans nosniff, un attaquant peut servir un script JavaScript déguisé en image — le navigateur peut l\'exécuter.',
                        fix: 'Une seule valeur possible : nosniff. Ajouter systématiquement sur toutes les réponses HTTP.',
                        apacheConf: 'Header always set X-Content-Type-Options "nosniff"',
                        nginxConf:  'add_header X-Content-Type-Options "nosniff" always;' },
                      { key: 'referrerPolicy', icon: 'visibility_off', label: 'Referrer-Policy', subtitle: 'Contrôle des informations de provenance', good: result.referrerPolicy, category: 'Confidentialité',
                        recommended: 'Referrer-Policy: strict-origin-when-cross-origin',
                        what: 'Contrôle quelles informations d\'URL sont transmises dans l\'en-tête Referer lors d\'une navigation externe.',
                        impact: 'Sans cette politique, des URLs contenant tokens, IDs de session ou paramètres sensibles peuvent fuiter vers des sites tiers.',
                        fix: 'strict-origin-when-cross-origin : bon équilibre entre analytique (chemin sur même domaine) et confidentialité (origine seulement vers l\'externe).',
                        apacheConf: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
                        nginxConf:  'add_header Referrer-Policy "strict-origin-when-cross-origin" always;' },
                      { key: 'permissionsPolicy', icon: 'tune', label: 'Permissions-Policy', subtitle: 'Contrôle des fonctionnalités navigateur', good: result.permissionsPolicy, category: 'Fonctionnalités',
                        recommended: 'Permissions-Policy: geolocation=(), camera=(), microphone=()',
                        what: 'Déclare quelles fonctionnalités navigateur (géolocalisation, caméra, micro, USB…) peuvent être activées par la page et ses scripts.',
                        impact: 'Sans restriction, des scripts tiers (pub, analytics) peuvent accéder à des capteurs sensibles sans que l\'utilisateur le sache.',
                        fix: 'Inventorier les permissions nécessaires. Désactiver tout le reste avec () (interdiction totale). Tester progressivement.',
                        apacheConf: 'Header always set Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()"',
                        nginxConf:  'add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()" always;' },
                      { key: 'ocsp', icon: 'verified_user', label: 'OCSP Stapling', subtitle: 'Vérification de révocation du certificat', good: result.ocspStapling, category: 'Certificat',
                        recommended: 'ssl_stapling on; ssl_stapling_verify on;  # nginx',
                        what: 'Le serveur joint une réponse OCSP signée lors du handshake TLS, prouvant que le certificat n\'est pas révoqué — sans requête supplémentaire du client.',
                        impact: 'Sans OCSP Stapling, le navigateur contacte le CA séparément à chaque connexion : latence accrue et fuite d\'informations de navigation vers le CA.',
                        fix: 'S\'assurer d\'avoir la chaîne de certificats complète (ssl_trusted_certificate). Le résolveur DNS doit être accessible depuis le serveur.',
                        apacheConf: 'SSLUseStapling On\nSSLStaplingCache shmcb:/var/run/ocsp(128000)\n# Dans la config globale (hors VirtualHost) :\n# SSLStaplingReturnResponderErrors off',
                        nginxConf:  'ssl_stapling on;\nssl_stapling_verify on;\nssl_trusted_certificate /path/to/chain.pem;\nresolver 8.8.8.8 8.8.4.4 valid=300s;\nresolver_timeout 5s;' },
                    ] as { key: string; icon: string; label: string; subtitle: string; good: boolean; category: string; recommended: string; what: string; impact: string; fix: string; apacheConf: string; nginxConf: string }[]).map(h => {
                      const isOpen = expanded === h.key;
                      return (
                        <div key={h.key}
                          onClick={() => setExpanded(isOpen ? null : h.key)}
                          className={`rounded-xl border cursor-pointer transition-all select-none ${h.good ? 'border-tertiary/20 bg-tertiary/[0.04] hover:border-tertiary/40' : 'border-error/20 bg-error/[0.03] hover:border-error/40'}`}>
                          <div className="flex items-center gap-3 px-4 py-3">
                            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${h.good ? 'bg-tertiary' : 'bg-error'}`} />
                            <span className={`material-symbols-outlined text-base flex-shrink-0 ${h.good ? 'text-tertiary/80' : 'text-error/70'}`}>{h.icon}</span>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-headline font-bold text-sm text-on-surface">{h.label}</span>
                                <span className="text-[9px] font-mono text-outline bg-surface-container-highest px-1.5 py-0.5 rounded uppercase tracking-wide">{h.category}</span>
                              </div>
                              <span className="text-[10px] text-outline truncate block">{h.subtitle}</span>
                            </div>
                            <span className={`text-[10px] font-bold px-2.5 py-1 rounded-full flex-shrink-0 ${h.good ? 'bg-tertiary/15 text-tertiary' : 'bg-error/15 text-error'}`}>
                              {h.good ? 'Actif' : 'Absent'}
                            </span>
                            <span className={`material-symbols-outlined text-outline/50 text-base flex-shrink-0 transition-transform ${isOpen ? 'rotate-180' : ''}`}>expand_more</span>
                          </div>
                          {isOpen && (
                            <div className="px-4 pb-4 pt-1 border-t border-outline-variant/[0.08] space-y-3">
                              <div>
                                <div className="text-[10px] font-bold text-primary uppercase tracking-widest mb-1.5">Valeur recommandée</div>
                                <div className="font-mono text-[10px] text-primary/90 bg-surface-container-highest px-3 py-2 rounded-lg break-all border border-primary/10">{h.recommended}</div>
                              </div>
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
                                <div>
                                  <div className="text-[10px] font-bold text-outline uppercase tracking-widest mb-1">Rôle</div>
                                  <p className="text-xs text-on-surface-variant leading-relaxed">{h.what}</p>
                                </div>
                                <div>
                                  <div className="text-[10px] font-bold text-error uppercase tracking-widest mb-1">Sans cet en-tête</div>
                                  <p className="text-xs text-on-surface-variant leading-relaxed">{h.impact}</p>
                                </div>
                                <div>
                                  <div className="text-[10px] font-bold text-tertiary uppercase tracking-widest mb-1">Comment activer</div>
                                  <p className="text-xs text-on-surface-variant leading-relaxed">{h.fix}</p>
                                </div>
                              </div>
                              <div className="pt-1" onClick={e => e.stopPropagation()}>
                                <div className="text-[10px] font-bold text-on-surface uppercase tracking-widest mb-2">Directive de configuration</div>
                                <div className="flex gap-1 mb-2">
                                  {(['apache', 'nginx'] as const).map(tab => (
                                    <button key={tab}
                                      onClick={e => { e.stopPropagation(); setConfTab(tab); }}
                                      className={`px-3 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wide transition-colors ${confTab === tab ? 'bg-primary/20 text-primary border border-primary/30' : 'bg-surface-container-highest text-outline border border-outline-variant/20 hover:border-primary/20'}`}>
                                      {tab === 'apache' ? 'Apache' : 'nginx'}
                                    </button>
                                  ))}
                                </div>
                                <pre className="font-mono text-[10px] text-[#8b949e] bg-[#0d1117] px-3 py-2.5 rounded-lg overflow-x-auto border border-outline-variant/10 whitespace-pre-wrap leading-relaxed">
                                  {confTab === 'apache' ? h.apacheConf : h.nginxConf}
                                </pre>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* ── Score récapitulatif ────────────────────────────────── */}
                <div className="bg-surface-container rounded-2xl p-6">
                  <h2 className="font-headline font-bold text-base flex items-center gap-2 mb-5">
                    <span className="material-symbols-outlined text-primary text-lg">analytics</span>
                    Score récapitulatif
                  </h2>
                  {(() => {
                    let score = 100;
                    const items: { label: string; ok: boolean; penalty: number; desc: string; what: string; state: string }[] = [
                      { label: 'TLS 1.3', ok: result.tls13 || result.sslyzeSupportsTLS13,
                        penalty: 10, desc: '-10 pts si absent',
                        what: 'La version la plus récente et sécurisée du protocole (2018). Supprime les algorithmes dangereux, accélère le handshake, renforce la confidentialité persistante. Rétrocompatible avec TLS 1.2.',
                        state: (result.tls13 || result.sslyzeSupportsTLS13) ? 'Activé' : 'Non activé' },
                      { label: 'TLS 1.0 désactivé', ok: !result.tls10 && !result.sslyzeSupportsTLS10,
                        penalty: 20, desc: '-20 pts si actif',
                        what: 'TLS 1.0 (1999) est vulnérable à BEAST et POODLE. Abandonné par tous les navigateurs modernes depuis 2020. Son maintien expose les utilisateurs à des attaques de downgrade.',
                        state: (result.tls10 || result.sslyzeSupportsTLS10) ? 'Encore actif' : 'Désactivé' },
                      { label: 'TLS 1.1 désactivé', ok: !result.tls11 && !result.sslyzeSupportsTLS11,
                        penalty: 15, desc: '-15 pts si actif',
                        what: 'TLS 1.1 (2006) utilise des algorithmes dépassés (MD5/SHA-1). Formellement déprécié par l\'IETF via RFC 8996. Doit être désactivé dans toute configuration conforme.',
                        state: (result.tls11 || result.sslyzeSupportsTLS11) ? 'Encore actif' : 'Désactivé' },
                      { label: 'Pas de Heartbleed', ok: !result.heartbleed && !result.sslyzeHeartbleed,
                        penalty: 40, desc: '-40 pts (critique)',
                        what: 'CVE-2014-0160 — bug dans OpenSSL permettant de lire jusqu\'à 64 Ko de mémoire serveur par requête, exposant clés privées SSL, mots de passe et cookies.',
                        state: (result.heartbleed || result.sslyzeHeartbleed) ? 'VULNÉRABLE' : 'Sûr' },
                      { label: 'Pas de SWEET32', ok: !result.sweet32,
                        penalty: 20, desc: '-20 pts',
                        what: 'CVE-2016-2183 — collision de bloc sur 3DES (bloc 64-bit) après ~32 Go de trafic. Permet de déchiffrer des cookies de session HTTP sur une longue connexion.',
                        state: result.sweet32 ? 'Vulnérable' : 'Sûr' },
                      { label: 'Pas de CRIME', ok: !result.crime,
                        penalty: 20, desc: '-20 pts',
                        what: 'CVE-2012-4929 — exploite la compression TLS pour deviner le contenu de cookies chiffrés par analyse de la taille des paquets compressés.',
                        state: result.crime ? 'Vulnérable' : 'Sûr' },
                      { label: 'Pas de 3DES', ok: !result.has3des,
                        penalty: 10, desc: '-10 pts',
                        what: '3DES est un algorithme de chiffrement obsolète (112 bits effectifs). Non conforme PCI-DSS. Prédispose à SWEET32. Doit être retiré de toutes les suites de chiffrement.',
                        state: result.has3des ? 'Présent' : 'Absent' },
                      { label: 'HSTS activé', ok: result.hsts,
                        penalty: 10, desc: '-10 pts si absent',
                        what: 'Force le navigateur à utiliser uniquement HTTPS. Empêche SSL Stripping. Sans HSTS, la première requête HTTP peut être interceptée par un attaquant sur le réseau.',
                        state: result.hsts ? 'Activé' : 'Absent' },
                      { label: 'CSP définie', ok: result.contentSecurityPolicy,
                        penalty: 15, desc: '-15 pts si absent',
                        what: 'Content-Security-Policy restreint les sources de scripts, styles et ressources. Prévient les injections XSS. Sans CSP, des scripts malveillants peuvent s\'exécuter dans le navigateur.',
                        state: result.contentSecurityPolicy ? 'Définie' : 'Absente' },
                      { label: 'X-Frame-Options', ok: result.xFrameOptions,
                        penalty: 10, desc: '-10 pts si absent',
                        what: 'Bloque l\'intégration de la page dans des iframes de sites tiers. Protège contre le clickjacking — attaque qui superpose un iframe invisible pour piéger les clics utilisateur.',
                        state: result.xFrameOptions ? 'Présent' : 'Absent' },
                      { label: 'X-Content-Type-Options', ok: result.xContentTypeOptions,
                        penalty: 5, desc: '-5 pts si absent',
                        what: 'nosniff interdit au navigateur de deviner le type MIME. Empêche l\'exécution de fichiers mal typés — ex: un script JS servi comme image.',
                        state: result.xContentTypeOptions ? 'Présent' : 'Absent' },
                      { label: 'Referrer-Policy', ok: result.referrerPolicy,
                        penalty: 5, desc: '-5 pts si absent',
                        what: 'Contrôle les informations d\'URL partagées avec des sites tiers via l\'en-tête Referer. Sans restriction, des tokens ou IDs d\'URL peuvent fuiter vers des analytics ou CDNs tiers.',
                        state: result.referrerPolicy ? 'Définie' : 'Absente' },
                      { label: 'Permissions-Policy', ok: result.permissionsPolicy,
                        penalty: 5, desc: '-5 pts si absent',
                        what: 'Restreint l\'accès des scripts aux fonctionnalités navigateur sensibles (caméra, géolocalisation, microphone). Sans restriction, des scripts tiers peuvent les activer.',
                        state: result.permissionsPolicy ? 'Définie' : 'Absente' },
                      { label: 'Certificat valide', ok: !result.certExpired,
                        penalty: 30, desc: '-30 pts si expiré',
                        what: 'Un certificat expiré génère une erreur immédiate dans tous les navigateurs et expose la connexion aux attaques MITM. Le renouvellement doit être automatisé (ex: Let\'s Encrypt + Certbot).',
                        state: result.certExpired ? 'Expiré' : 'Valide' },
                      { label: 'Chaîne complète', ok: result.chainComplete,
                        penalty: 15, desc: '-15 pts',
                        what: 'La chaîne de certification doit relier le certificat serveur aux CAs intermédiaires puis au CA racine de confiance. Une chaîne incomplète cause des erreurs TLS sur certains clients.',
                        state: result.chainComplete ? 'Complète' : 'Incomplète' },
                    ];
                    items.forEach(it => { if (!it.ok) score = Math.max(0, score - it.penalty); });
                    const col = score >= 90 ? '#00fc92' : score >= 70 ? '#a4e6ff' : score >= 50 ? '#ffe066' : score >= 30 ? '#ffaa40' : '#ffb4ab';
                    const letter = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 45 ? 'D' : 'F';
                    return (
                      <div>
                        <div className="flex items-end gap-3 mb-4">
                          <span className="text-5xl font-headline font-extrabold" style={{ color: col }}>{score}</span>
                          <span className="text-xl text-outline mb-1">/100</span>
                          <span className="text-2xl font-headline font-bold ml-2 mb-1 px-3 py-0.5 rounded-lg"
                            style={{ color: col, background: `${col}15`, border: `1px solid ${col}33` }}>{letter}</span>
                        </div>
                        <div className="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden mb-6">
                          <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, background: col }} />
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {items.map(it => (
                            <div key={it.label} className={`p-3 rounded-xl border flex items-start gap-3 ${it.ok ? 'border-tertiary/15 bg-tertiary/[0.03]' : 'border-error/15 bg-error/[0.03]'}`}>
                              <span className={`material-symbols-outlined text-xl mt-0.5 shrink-0 ${it.ok ? 'text-tertiary' : 'text-error'}`}
                                style={{ fontVariationSettings: "'FILL' 1" }}>
                                {it.ok ? 'check_circle' : 'cancel'}
                              </span>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center justify-between gap-1 flex-wrap">
                                  <span className="text-xs font-bold text-on-surface">{it.label}</span>
                                  <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full ${it.ok ? 'text-tertiary bg-tertiary/10' : 'text-error bg-error/10'}`}>{it.state}</span>
                                </div>
                                <p className="text-[10px] text-outline mt-0.5 leading-relaxed">{it.what}</p>
                                {!it.ok && <p className="text-[9px] text-error/60 mt-0.5">{it.desc}</p>}
                              </div>
                            </div>
                          ))}
                        </div>
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
    </div>
  );
};

export default SSLAnalysis;
