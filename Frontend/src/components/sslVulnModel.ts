import type { SslResultDto } from '../services/api';

export type VulnResultStatus =
  | 'detected'
  | 'not_detected'
  | 'inconclusive'
  | 'not_tested'
  | 'test_error';

export type VulnConfidence = 'high' | 'medium' | 'low' | 'unknown';
export type TheoreticalSeverity = 'critical' | 'high' | 'medium' | 'low';
export type SourceValue = boolean | null | undefined | 'timeout' | 'error';

export type VulnToolResult = {
  toolName: string;
  toolLabel: string;
  version?: string | null;
  testedAt?: string | null;
  endpoint?: string | null;
  rawValue: SourceValue;
  status: VulnResultStatus;
  message: string;
  confidence: VulnConfidence;
  plugin?: string | null;
  command?: string | null;
  evidence?: string | null;
  error?: string | null;
};

export type VulnPresentation = {
  id: string;
  name: string;
  cve: string | null;
  published?: string | null;
  theoreticalSeverity: TheoreticalSeverity;
  status: VulnResultStatus;
  confidence: VulnConfidence;
  summary: string;
  description: string;
  impact: string;
  conditions: string;
  attackScenario: string;
  remediation: string;
  needsCertRotation: boolean;
  verifyCommand: string;
  restartRequired: boolean;
  securityGain: string;
  docsUrl: string | null;
  testedSources: number;
  concordantSources: number;
  availableSources: number;
  sourcesLabel: string;
  needsSecondSource: boolean;
  results: VulnToolResult[];
  serverConfigurations: { nginx: string; apache: string };
  icon: string;
};

type SourceDef = {
  name: string;
  tool: string;
  plugin?: string;
  command?: string;
  getValue: (r: SslResultDto) => SourceValue;
  getEvidence?: (r: SslResultDto) => string | null | undefined;
  getVersion?: (r: SslResultDto) => string | null | undefined;
};

type CatalogEntry = {
  id: string;
  key: keyof SslResultDto | string;
  name: string;
  cve: string | null;
  published?: string;
  theoreticalSeverity: TheoreticalSeverity;
  icon: string;
  summary: string;
  description: string;
  impact: string;
  conditions: string;
  attackScenario: string;
  remediation: string;
  needsCertRotation: boolean;
  verifyCommand: string;
  restartRequired: boolean;
  securityGain: string;
  docsUrl: string | null;
  nginx: string;
  apache: string;
  sources: SourceDef[];
};

const CATALOG: CatalogEntry[] = [
  {
    id: 'heartbleed',
    key: 'heartbleed',
    name: 'Heartbleed',
    cve: 'CVE-2014-0160',
    published: '2014-04-07',
    theoreticalSeverity: 'critical',
    icon: 'favorite',
    summary: 'Faille d’anciennes versions d’OpenSSL pouvant exposer une partie de la mémoire du serveur.',
    description:
      'Heartbleed provient d’une erreur de contrôle dans l’extension TLS Heartbeat d’OpenSSL. Un attaquant peut demander au serveur de renvoyer davantage de données que celles réellement envoyées et ainsi lire des fragments de mémoire contenant potentiellement des mots de passe, cookies, jetons de session ou clés privées.',
    impact: 'Divulgation de données sensibles présentes dans la mémoire du serveur.',
    conditions: 'Version vulnérable d’OpenSSL avec l’extension Heartbeat active.',
    attackScenario:
      'Un client malveillant envoie une requête Heartbeat falsifiée ; le serveur répond avec des octets de mémoire non initialisée.',
    remediation:
      'Mettre OpenSSL à jour et renouveler les certificats et secrets susceptibles d’avoir été exposés.',
    needsCertRotation: true,
    verifyCommand: 'nmap -p 443 --script ssl-heartbleed <hôte>',
    restartRequired: true,
    securityGain: 'Élimine la fuite mémoire OpenSSL Heartbeat.',
    docsUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2014-0160',
    nginx: `# Heartbleed est une faille OpenSSL — mettre à jour le paquet\napt update && apt install --only-upgrade openssl\nsystemctl restart nginx\n# Régénérer le certificat et faire tourner les secrets exposés`,
    apache: `# Heartbleed est une faille OpenSSL — mettre à jour le paquet\napt update && apt install --only-upgrade openssl\nsystemctl restart apache2\n# Régénérer le certificat et faire tourner les secrets exposés`,
    sources: [
      {
        name: 'Kali / sslscan+nmap',
        tool: 'sslscan / nmap',
        plugin: 'ssl-heartbleed',
        command: 'nmap -p 443 --script ssl-heartbleed',
        getValue: r => r.heartbleed ?? undefined,
        getEvidence: r => r.heartbleedEvidence,
      },
      {
        name: 'SSLyze',
        tool: 'SSLyze',
        plugin: 'HeartbleedPlugin',
        getValue: r => r.sslyzeHeartbleed ?? undefined,
        getVersion: r => r.sslyzeVersion,
      },
    ],
  },
  {
    id: 'sweet32',
    key: 'sweet32',
    name: 'SWEET32',
    cve: 'CVE-2016-2183',
    published: '2016-08-24',
    theoreticalSeverity: 'high',
    icon: '32',
    summary: 'Attaque visant les chiffrements à blocs de 64 bits comme 3DES lors de sessions longues.',
    description:
      'SWEET32 exploite les collisions qui peuvent apparaître lorsque de grandes quantités de données sont chiffrées avec un algorithme possédant des blocs de seulement 64 bits, notamment 3DES ou Blowfish.',
    impact:
      'Récupération possible de fragments de données répétitives, comme certains cookies, pendant une très longue session chiffrée.',
    conditions: 'Utilisation de 3DES ou d’un autre chiffrement à blocs de 64 bits.',
    attackScenario:
      'Sur une session longue utilisant 3DES, un attaquant observe les collisions de blocs pour reconstruire des fragments.',
    remediation:
      'Désactiver 3DES, Blowfish et les autres chiffrements à blocs de 64 bits. Utiliser AES-GCM ou ChaCha20-Poly1305.',
    needsCertRotation: false,
    verifyCommand: 'nmap -p 443 --script ssl-enum-ciphers <hôte> | grep -i 3DES',
    restartRequired: true,
    securityGain: 'Supprime l’exposition SWEET32 liée aux blocs 64 bits.',
    docsUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2016-2183',
    nginx: `ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:!3DES:!DES';\nssl_prefer_server_ciphers on;`,
    apache: `SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:!3DES:!DES\nSSLHonorCipherOrder on`,
    sources: [{ name: 'Kali', tool: 'testssl.sh', getValue: r => r.sweet32 ?? undefined }],
  },
  {
    id: 'crime',
    key: 'crime',
    name: 'CRIME',
    cve: 'CVE-2012-4929',
    published: '2012-09-15',
    theoreticalSeverity: 'high',
    icon: 'compress',
    summary: 'Attaque utilisant la compression TLS pour deviner des secrets transmis dans une requête chiffrée.',
    description:
      'CRIME observe les variations de taille des données compressées lorsqu’un attaquant injecte du contenu contrôlé à proximité d’un secret, par exemple un cookie de session.',
    impact: 'Récupération progressive de cookies ou de jetons d’authentification.',
    conditions:
      'Compression TLS activée et attaquant capable d’injecter des données dans les requêtes de la victime.',
    attackScenario:
      'L’attaquant injecte des préfixes connus à côté du cookie et compare les tailles compressées pour en déduire le secret octet par octet.',
    remediation: 'Désactiver la compression TLS côté serveur.',
    needsCertRotation: false,
    verifyCommand: 'openssl s_client -connect <hôte>:443 -tlsextdebug 2>&1 | grep -i compression',
    restartRequired: true,
    securityGain: 'Empêche l’oracle de taille lié à la compression TLS.',
    docsUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2012-4929',
    nginx: `# nginx désactive la compression TLS par défaut depuis v1.1.6\n# Vérifier : nginx -V 2>&1 | grep -i compression`,
    apache: `SSLCompression off`,
    sources: [
      { name: 'Kali', tool: 'testssl.sh', getValue: r => r.crime ?? undefined },
      {
        name: 'SSLyze',
        tool: 'SSLyze',
        plugin: 'CompressionPlugin',
        getValue: r => r.sslyzeCompression ?? undefined,
        getVersion: r => r.sslyzeVersion,
      },
    ],
  },
  {
    id: 'has3des',
    key: 'has3des',
    name: 'Chiffrement 3DES',
    cve: null,
    theoreticalSeverity: 'medium',
    icon: 'key_off',
    summary: 'Ancien algorithme de chiffrement désormais considéré comme faible et exposé à SWEET32.',
    description:
      '3DES utilise des blocs de 64 bits et présente une sécurité et des performances insuffisantes pour les configurations TLS modernes.',
    impact: 'Exposition possible à SWEET32 et réduction du niveau global de sécurité.',
    conditions: 'Au moins une suite cryptographique TLS contenant 3DES est acceptée.',
    attackScenario:
      'Si 3DES est accepté, une session longue peut être exposée à des collisions de blocs (SWEET32).',
    remediation:
      'Supprimer toutes les suites 3DES ou DES-CBC3 et privilégier AES-GCM ou ChaCha20-Poly1305.',
    needsCertRotation: false,
    verifyCommand: 'nmap -p 443 --script ssl-enum-ciphers <hôte> | grep -iE "3DES|DES-CBC3"',
    restartRequired: true,
    securityGain: 'Retire un chiffrement obsolète du profil TLS.',
    docsUrl: null,
    nginx: `ssl_ciphers 'HIGH:!3DES:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5';\nssl_prefer_server_ciphers on;`,
    apache: `SSLCipherSuite HIGH:!3DES:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5\nSSLHonorCipherOrder on`,
    sources: [{ name: 'Kali', tool: 'sslscan', getValue: r => r.has3des ?? undefined }],
  },
  {
    id: 'poodle',
    key: 'poodle',
    name: 'POODLE',
    cve: 'CVE-2014-3566',
    published: '2014-10-14',
    theoreticalSeverity: 'critical',
    icon: 'pets',
    summary: 'Attaque contre le remplissage CBC de SSL 3.0 permettant de récupérer du contenu chiffré.',
    description:
      'POODLE exploite la manière dont SSL 3.0 vérifie le remplissage des blocs CBC. Un attaquant placé sur le réseau peut provoquer plusieurs requêtes et récupérer progressivement certaines données.',
    impact: 'Récupération possible de cookies ou de jetons de session.',
    conditions: 'SSL 3.0 activé ou possibilité de forcer une rétrogradation vers SSL 3.0.',
    attackScenario:
      'Un MITM force une rétrogradation vers SSL 3.0 puis exploite le padding oracle CBC.',
    remediation: 'Désactiver entièrement SSL 3.0 et utiliser TLS 1.2 ou TLS 1.3.',
    needsCertRotation: false,
    verifyCommand: 'nmap -p 443 --script ssl-poodle <hôte>',
    restartRequired: true,
    securityGain: 'Supprime la surface d’attaque SSL 3.0 / POODLE.',
    docsUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2014-3566',
    nginx: `ssl_protocols TLSv1.2 TLSv1.3;`,
    apache: `SSLProtocol all -SSLv2 -SSLv3`,
    sources: [{ name: 'Kali', tool: 'sslscan / testssl.sh', getValue: r => r.poodle ?? undefined }],
  },
  {
    id: 'beast',
    key: 'beast',
    name: 'BEAST',
    cve: 'CVE-2011-3389',
    published: '2011-09-05',
    theoreticalSeverity: 'high',
    icon: 'security_key_off',
    summary: 'Ancienne attaque contre les suites CBC de TLS 1.0 dans certains navigateurs.',
    description:
      'BEAST exploite la génération des vecteurs d’initialisation de TLS 1.0 avec les chiffrements CBC. L’attaque nécessite généralement un navigateur ancien et la capacité d’injecter du trafic.',
    impact: 'Récupération possible de fragments de session HTTPS.',
    conditions: 'TLS 1.0 avec suites CBC et client vulnérable.',
    attackScenario:
      'Un attaquant réseau injecte du trafic et exploite les IV prévisibles de TLS 1.0/CBC.',
    remediation:
      'Désactiver TLS 1.0 lorsque possible et privilégier TLS 1.2 ou TLS 1.3 avec des suites AEAD.',
    needsCertRotation: false,
    verifyCommand: 'nmap -p 443 --script ssl-enum-ciphers <hôte> | grep -i "TLSv1.0"',
    restartRequired: true,
    securityGain: 'Réduit l’exposition aux attaques CBC historiques sur TLS 1.0.',
    docsUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2011-3389',
    nginx: `ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers on;`,
    apache: `SSLProtocol all -SSLv2 -SSLv3 -TLSv1\nSSLCipherSuite ECDHE+AESGCM:DHE+AESGCM:HIGH:!3DES:!MD5:!aNULL:!eNULL\nSSLHonorCipherOrder on`,
    sources: [{ name: 'Kali', tool: 'testssl.sh', getValue: r => r.beast ?? undefined }],
  },
  {
    id: 'robot',
    key: 'robot',
    name: 'ROBOT',
    cve: 'CVE-2017-13099',
    published: '2017-12-12',
    theoreticalSeverity: 'critical',
    icon: 'smart_toy',
    summary: 'Attaque par oracle contre l’échange de clés RSA PKCS#1 v1.5.',
    description:
      'ROBOT est une variante de l’attaque de Bleichenbacher. Des différences dans les réponses du serveur permettent à un attaquant d’obtenir des informations sur le traitement d’un message RSA mal formé.',
    impact:
      'Déchiffrement de sessions TLS ou création de signatures dans certaines implémentations vulnérables.',
    conditions:
      'Suites utilisant l’échange de clés RSA et comportement d’oracle présent dans l’implémentation TLS.',
    attackScenario:
      'L’attaquant envoie des messages RSA mal formés et observe les réponses pour reconstruire le plaintext.',
    remediation:
      'Mettre à jour la bibliothèque TLS et désactiver les suites utilisant l’échange de clés RSA statique. Utiliser ECDHE.',
    needsCertRotation: false,
    verifyCommand: 'testssl.sh --robot <hôte>',
    restartRequired: true,
    securityGain: 'Élimine l’oracle ROBOT sur l’échange RSA.',
    docsUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2017-13099',
    nginx: `ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';\nssl_prefer_server_ciphers on;`,
    apache: `SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\nSSLHonorCipherOrder on`,
    sources: [
      { name: 'Kali', tool: 'testssl.sh', getValue: r => r.robot ?? undefined },
      {
        name: 'SSLyze',
        tool: 'SSLyze',
        plugin: 'RobotPlugin',
        getValue: r => r.sslyzeRobot ?? undefined,
        getVersion: r => r.sslyzeVersion,
      },
    ],
  },
  {
    id: 'freak',
    key: 'freak',
    name: 'FREAK',
    cve: 'CVE-2015-0204',
    published: '2015-03-03',
    theoreticalSeverity: 'high',
    icon: 'vpn_key_off',
    summary: 'Attaque de rétrogradation vers d’anciennes clés RSA export de faible taille.',
    description:
      'FREAK exploite les anciennes restrictions cryptographiques dites export-grade. Un attaquant peut tenter de forcer une connexion à utiliser une clé RSA temporaire faible lorsque le serveur ou le client est vulnérable.',
    impact: 'Déchiffrement ou interception d’une session TLS.',
    conditions: 'Suites RSA_EXPORT acceptées et implémentation vulnérable à la rétrogradation.',
    attackScenario:
      'Un MITM force une suite EXPORT ; la clé RSA faible est ensuite factorisée pour déchiffrer la session.',
    remediation: 'Désactiver toutes les suites EXPORT et mettre à jour les bibliothèques TLS.',
    needsCertRotation: false,
    verifyCommand: 'nmap -p 443 --script ssl-enum-ciphers <hôte> | grep -i EXPORT',
    restartRequired: true,
    securityGain: 'Supprime les suites export-grade exploitables par FREAK.',
    docsUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2015-0204',
    nginx: `ssl_ciphers 'HIGH:!EXPORT:!aNULL:!eNULL:!DES:!MD5';\nssl_prefer_server_ciphers on;`,
    apache: `SSLCipherSuite HIGH:!EXPORT:!aNULL:!eNULL:!DES:!MD5\nSSLHonorCipherOrder on`,
    sources: [{ name: 'Kali', tool: 'testssl.sh', getValue: r => r.freak ?? undefined }],
  },
  {
    id: 'logjam',
    key: 'logjam',
    name: 'LOGJAM',
    cve: 'CVE-2015-4000',
    published: '2015-05-20',
    theoreticalSeverity: 'high',
    icon: 'lock_open',
    summary: 'Attaque contre les échanges Diffie-Hellman faibles ou réutilisant des groupes communs.',
    description:
      'LOGJAM peut provoquer une rétrogradation vers des paramètres Diffie-Hellman export ou exploiter des groupes DH faibles et largement réutilisés.',
    impact: 'Déchiffrement possible de sessions TLS utilisant des paramètres DH insuffisants.',
    conditions: 'Suites DHE_EXPORT, paramètres DH faibles ou groupes communs de taille insuffisante.',
    attackScenario:
      'Un MITM force DHE_EXPORT ou exploite un groupe DH faible pour casser l’échange de clés.',
    remediation:
      'Supprimer DHE_EXPORT, utiliser des paramètres DH d’au moins 2048 bits ou privilégier ECDHE.',
    needsCertRotation: false,
    verifyCommand: 'testssl.sh --logjam <hôte>',
    restartRequired: true,
    securityGain: 'Renforce les paramètres DH / ECDHE contre LOGJAM.',
    docsUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2015-4000',
    nginx: `openssl dhparam -out /etc/nginx/dhparam.pem 2048\nssl_dhparam /etc/nginx/dhparam.pem;\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers on;`,
    apache: `openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048\nSSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"\nSSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384`,
    sources: [{ name: 'Kali', tool: 'testssl.sh', getValue: r => r.logjam ?? undefined }],
  },
  {
    id: 'rc4',
    key: 'rc4',
    name: 'RC4',
    cve: 'CVE-2013-2566',
    published: '2013-03-15',
    theoreticalSeverity: 'high',
    icon: 'no_encryption',
    summary: 'Ancien chiffrement par flot présentant des biais statistiques connus.',
    description:
      'RC4 ne produit pas un flux suffisamment aléatoire. En observant un grand nombre de connexions, un attaquant peut exploiter ces biais pour récupérer certaines informations.',
    impact: 'Récupération progressive de données comme des cookies ou des mots de passe.',
    conditions: 'Au moins une suite cryptographique RC4 est acceptée.',
    attackScenario:
      'En accumulant de nombreuses connexions RC4, l’attaquant exploite les biais pour reconstruire le plaintext.',
    remediation: 'Désactiver toutes les suites RC4 et utiliser AES-GCM ou ChaCha20-Poly1305.',
    needsCertRotation: false,
    verifyCommand: 'nmap -p 443 --script ssl-enum-ciphers <hôte> | grep -i RC4',
    restartRequired: true,
    securityGain: 'Élimine les suites RC4 obsolètes.',
    docsUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2013-2566',
    nginx: `ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:!RC4';\nssl_prefer_server_ciphers on;`,
    apache: `SSLCipherSuite HIGH:!RC4:!aNULL:!eNULL:!MD5:!EXPORT\nSSLHonorCipherOrder on`,
    sources: [{ name: 'Kali', tool: 'sslscan', getValue: r => r.rc4 ?? undefined }],
  },
  {
    id: 'drown',
    key: 'drown',
    name: 'DROWN',
    cve: 'CVE-2016-0800',
    published: '2016-03-01',
    theoreticalSeverity: 'critical',
    icon: 'water_damage',
    summary:
      'Attaque inter-protocole exploitant SSL 2.0 lorsqu’une même clé RSA est réutilisée par plusieurs services.',
    description:
      'DROWN utilise un serveur acceptant SSL 2.0 comme oracle pour attaquer des connexions TLS modernes utilisant la même clé privée RSA. Le service SSL 2.0 peut se trouver sur un autre port ou sur un autre serveur.',
    impact: 'Déchiffrement possible de sessions TLS modernes.',
    conditions: 'SSL 2.0 actif sur un service réutilisant la même clé RSA.',
    attackScenario:
      'L’attaquant interroge un service SSL 2.0 partageant la clé pour obtenir un oracle contre TLS moderne.',
    remediation:
      'Désactiver SSL 2.0 sur tous les services et vérifier qu’aucun autre serveur ne réutilise la même clé privée.',
    needsCertRotation: false,
    verifyCommand: 'nmap -p 443 --script sslv2 <hôte>',
    restartRequired: true,
    securityGain: 'Supprime la surface SSL 2.0 exploitable par DROWN.',
    docsUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2016-0800',
    nginx: `ssl_protocols TLSv1.2 TLSv1.3;\n# Vérifier tous les server blocks utilisant le même certificat/clé`,
    apache: `SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\n# Vérifier aussi les autres ports (SMTP, IMAP) utilisant la même clé privée`,
    sources: [
      { name: 'Kali', tool: 'sslscan', getValue: r => r.drown ?? undefined },
      { name: 'SSL Labs', tool: 'Qualys SSL Labs API', getValue: r => r.ssllabsDrown ?? undefined },
    ],
  },
];

function sourceToStatus(v: SourceValue): VulnResultStatus {
  if (v === true) return 'detected';
  if (v === false) return 'not_detected';
  if (v === 'timeout' || v === 'error') return 'test_error';
  return 'not_tested';
}

function sourceMessage(v: SourceValue): string {
  if (v === true) return 'Le test indique que la vulnérabilité est présente.';
  if (v === false) return 'Le test n’a pas identifié cette vulnérabilité.';
  if (v === 'timeout') return 'Le test a expiré avant d’obtenir un résultat.';
  if (v === 'error') return 'Le test n’a pas pu être terminé correctement.';
  return 'Aucun résultat n’a été fourni par cet outil.';
}

function aggregateStatus(values: SourceValue[]): VulnResultStatus {
  const tested = values.filter(s => s === true || s === false);
  const positive = tested.filter(s => s === true);
  const failed = values.filter(s => s === 'timeout' || s === 'error');
  if (tested.length === 0 && failed.length > 0) return 'test_error';
  if (tested.length === 0) return 'not_tested';
  if (positive.length > 0) return 'detected';
  return 'not_detected';
}

function aggregateConfidence(values: SourceValue[]): VulnConfidence {
  const tested = values.filter(s => s === true || s === false) as boolean[];
  const failed = values.filter(s => s === 'timeout' || s === 'error');
  if (tested.length === 0) return 'unknown';
  if (tested.length >= 2) {
    const allSame = tested.every(s => s === tested[0]);
    if (allSame && failed.length === 0) return 'high';
    return 'medium';
  }
  return 'low';
}

function sourcesLabel(tested: number, concordant: number, available: number): string {
  if (tested === 0) return 'Aucune source disponible';
  if (tested === 1) return '1 source disponible';
  if (concordant === tested && tested >= 2) return `${tested} sources concordantes`;
  if (concordant > 0) return `${concordant} sur ${tested} sources concordantes`;
  return `${available} source${available > 1 ? 's' : ''} disponible${available > 1 ? 's' : ''}`;
}

export function detectPreferredServer(result: SslResultDto): { server: 'nginx' | 'apache'; detected: boolean } {
  const blob = [
    (result as any).serverBanner,
    (result as any).httpServer,
    (result as any).serverSoftware,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  if (blob.includes('apache')) return { server: 'apache', detected: true };
  if (blob.includes('nginx')) return { server: 'nginx', detected: true };
  // Défaut Nginx (ne pas imposer Apache) lorsque le serveur n’est pas identifiable
  return { server: 'nginx', detected: false };
}

export function buildVulnPresentations(result: SslResultDto): VulnPresentation[] {
  const endpoint =
    result.sslyzeIpAddress
      ? `${result.sslyzeIpAddress}:${result.sslyzePort || 443}`
      : result.ssllabsIpAddress
        ? `${result.ssllabsIpAddress}:443`
        : result.domain
          ? `${result.domain}:443`
          : null;

  return CATALOG.map(entry => {
    const values = entry.sources.map(s => s.getValue(result));
    const testedBools = values.filter(s => s === true || s === false) as boolean[];
    const testedSources = testedBools.length;
    const concordantSources =
      testedSources >= 2 && testedBools.every(s => s === testedBools[0]) ? testedSources : 0;
    const status = aggregateStatus(values);
    const confidence = aggregateConfidence(values);

    const results: VulnToolResult[] = entry.sources.map(s => {
      const raw = s.getValue(result);
      const st = sourceToStatus(raw);
      return {
        toolName: s.name,
        toolLabel: s.tool,
        version: s.getVersion?.(result) ?? null,
        testedAt: result.sslyzeScanStarted || null,
        endpoint,
        rawValue: raw,
        status: st,
        message: sourceMessage(raw),
        confidence: st === 'not_tested' || st === 'test_error' ? 'unknown' : (testedSources >= 2 ? confidence : 'low'),
        plugin: s.plugin || null,
        command: s.command || null,
        evidence: s.getEvidence?.(result) || null,
        error: raw === 'error' ? 'Erreur d’exécution' : raw === 'timeout' ? 'Timeout' : null,
      };
    });

    return {
      id: entry.id,
      name: entry.name,
      cve: entry.cve,
      published: entry.published || null,
      theoreticalSeverity: entry.theoreticalSeverity,
      status,
      confidence,
      summary: entry.summary,
      description: entry.description,
      impact: entry.impact,
      conditions: entry.conditions,
      attackScenario: entry.attackScenario,
      remediation: entry.remediation,
      needsCertRotation: entry.needsCertRotation,
      verifyCommand: entry.verifyCommand,
      restartRequired: entry.restartRequired,
      securityGain: entry.securityGain,
      docsUrl: entry.docsUrl,
      testedSources,
      concordantSources,
      availableSources: entry.sources.length,
      sourcesLabel: sourcesLabel(testedSources, concordantSources, entry.sources.length),
      needsSecondSource: testedSources === 1,
      results,
      serverConfigurations: { nginx: entry.nginx, apache: entry.apache },
      icon: entry.icon,
    };
  });
}

export function severityLabel(s: TheoreticalSeverity): string {
  switch (s) {
    case 'critical': return 'Critique';
    case 'high': return 'Élevée';
    case 'medium': return 'Moyenne';
    case 'low': return 'Faible';
  }
}

export function statusLabel(s: VulnResultStatus): string {
  switch (s) {
    case 'detected': return 'Détectée';
    case 'not_detected': return 'Non détectée';
    case 'inconclusive': return 'Résultat inconclusif';
    case 'not_tested': return 'Non testée';
    case 'test_error': return 'Erreur de test';
  }
}

export function confidenceLabel(c: VulnConfidence): string {
  switch (c) {
    case 'high': return 'Confiance élevée';
    case 'medium': return 'Confiance moyenne';
    case 'low': return 'Confiance faible';
    case 'unknown': return 'Confiance inconnue';
  }
}

export function buildSectionConclusion(items: VulnPresentation[]): string {
  const detected = items.filter(v => v.status === 'detected');
  const high = items.filter(v => v.confidence === 'high');
  const low = items.filter(v => v.confidence === 'low' || v.needsSecondSource);

  if (detected.length > 0) {
    const crit = detected.some(v => v.theoreticalSeverity === 'critical');
    return crit
      ? 'Une vulnérabilité critique a été détectée. La correction doit être prioritaire avant toute mise en production. Consultez les preuves techniques et les recommandations associées.'
      : `${detected.length} vulnérabilité${detected.length > 1 ? 's ont' : ' a'} été détectée${detected.length > 1 ? 's' : ''}. Consultez les détails et appliquez les corrections recommandées.`;
  }

  const highNames = high.map(v => v.name).slice(0, 4);
  const highPart = highNames.length
    ? ` Les résultats ${highNames.join(', ')} bénéficient d’une confiance élevée grâce à plusieurs sources concordantes.`
    : '';
  const lowPart = low.length
    ? ' Les autres résultats reposent sur une seule source et doivent être considérés comme des vérifications préliminaires.'
    : '';

  return `Les tests exécutés n’ont identifié aucune des vulnérabilités SSL/TLS recherchées.${highPart}${lowPart}`;
}

export function buildSummaryConclusion(items: VulnPresentation[]): string {
  const detected = items.filter(v => v.status === 'detected').length;
  const low = items.filter(v => v.confidence === 'low' || v.needsSecondSource).length;
  if (detected > 0) {
    return `${detected} vulnérabilité${detected > 1 ? 's ont' : ' a'} été détectée${detected > 1 ? 's' : ''}. Priorisez la correction et consultez les preuves.`;
  }
  if (low > 0) {
    return 'Aucune vulnérabilité connue n’a été détectée. Certains résultats reposent cependant sur une seule source et présentent un niveau de confiance limité.';
  }
  return 'Aucune vulnérabilité n’a été détectée par les tests exécutés.';
}
