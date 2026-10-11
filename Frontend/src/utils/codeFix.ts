import type { CveDto } from "../services/api";

/**
 * Remediation of a CODE finding (Semgrep rule): what the flaw is, how to fix it, and a before/after example in the
 * language of the flagged file. Matches on the CWE id or on the rule name. Pure function (unit-tested).
 */

export type Lang = "js" | "py" | "java" | "php" | "other";

export interface CodeFix {
  id: string;
  title: string;
  why: string;
  steps: string[];
  bad?: string;
  good?: string;
  ref: { label: string; url: string };
}

export function languageOf(path?: string | null): Lang {
  const ext = (path ?? "").toLowerCase().split(".").pop() ?? "";
  if (["js", "jsx", "ts", "tsx", "mjs", "cjs", "vue"].includes(ext)) return "js";
  if (ext === "py") return "py";
  if (["java", "kt", "scala", "groovy"].includes(ext)) return "java";
  if (ext === "php") return "php";
  return "other";
}

type Example = Partial<Record<Lang, [string, string]>>;

interface Rule {
  id: string;
  cwe: string[];
  words: string[];
  title: string;
  why: string;
  steps: string[];
  examples?: Example;
  ref: [string, string];
}

const OWASP = (slug: string): [string, string] => [
  `OWASP — ${slug.replace(/_/g, " ")}`,
  `https://cheatsheetseries.owasp.org/cheatsheets/${slug}_Cheat_Sheet.html`,
];

const RULES: Rule[] = [
  {
    id: "sqli", cwe: ["CWE-89"], words: ["sql-injection", "sqli", "sql_injection", "tainted-sql"],
    title: "Injection SQL",
    why: "Une entrée utilisateur est concaténée dans une requête SQL : un attaquant peut lire ou modifier la base.",
    steps: [
      "Remplacez la concaténation par une requête paramétrée (les valeurs sont envoyées à part).",
      "Ne construisez jamais un nom de table ou de colonne à partir d'une entrée : utilisez une liste blanche.",
      "Donnez à l'application un compte de base de données aux droits minimaux.",
    ],
    examples: {
      js: ['db.query("SELECT * FROM users WHERE id = " + req.params.id)', 'db.query("SELECT * FROM users WHERE id = ?", [req.params.id])'],
      py: ['cur.execute("SELECT * FROM users WHERE id = " + user_id)', 'cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))'],
      java: ['stmt.executeQuery("SELECT * FROM users WHERE id = " + id);', 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setString(1, id);'],
      php: ['$db->query("SELECT * FROM users WHERE id = " . $_GET[\'id\']);', "$st = $db->prepare('SELECT * FROM users WHERE id = ?');\n$st->execute([$_GET['id']]);"],
    },
    ref: OWASP("SQL_Injection_Prevention"),
  },
  {
    id: "nosqli", cwe: ["CWE-943"], words: ["nosql", "mongo-injection"],
    title: "Injection NoSQL",
    why: "Un objet fourni par l'utilisateur est passé tel quel à la requête (opérateurs comme $ne, $gt).",
    steps: [
      "Validez le type attendu (chaîne, nombre) avant la requête.",
      "Refusez les objets contenant des clés commençant par `$`.",
      "Utilisez un schéma de validation (Joi, Zod, Mongoose).",
    ],
    examples: { js: ["db.users.find({ user: req.body.user, pass: req.body.pass })", "db.users.find({ user: String(req.body.user), pass: String(req.body.pass) })"] },
    ref: OWASP("Injection_Prevention"),
  },
  {
    id: "xss", cwe: ["CWE-79"], words: ["xss", "innerhtml", "dangerouslysetinnerhtml", "unescaped", "template-injection", "reflected"],
    title: "Cross-site scripting (XSS)",
    why: "Du texte fourni par l'utilisateur est affiché en HTML sans échappement : un script peut s'exécuter chez les autres utilisateurs.",
    steps: [
      "Affichez les données comme du texte (textContent), pas comme du HTML.",
      "Activez l'échappement automatique du moteur de templates et évitez les variantes « raw / safe ».",
      "Si le HTML est indispensable, nettoyez-le avec une bibliothèque (DOMPurify).",
      "Ajoutez une Content-Security-Policy stricte.",
    ],
    examples: {
      js: ["el.innerHTML = userInput;", "el.textContent = userInput;"],
      py: ['return Markup("<p>" + name + "</p>")', 'return render_template("p.html", name=name)   # {{ name }} est échappé'],
      php: ["echo $_GET['q'];", "echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');"],
    },
    ref: OWASP("Cross_Site_Scripting_Prevention"),
  },
  {
    id: "cmdi", cwe: ["CWE-78", "CWE-77"], words: ["command-injection", "child_process", "os-command", "subprocess", "shell-injection", "exec"],
    title: "Injection de commande",
    why: "Une entrée utilisateur finit dans une commande système : l'attaquant exécute ses propres commandes sur le serveur.",
    steps: [
      "Évitez d'appeler un shell : utilisez l'API native de la bibliothèque.",
      "Sinon, passez les arguments en tableau (sans shell) et validez-les par liste blanche.",
      "N'utilisez jamais `shell=True` ou `exec()` avec une chaîne construite.",
    ],
    examples: {
      js: ['exec("ping " + host)', 'execFile("ping", ["-c", "1", host])   // + validation de host'],
      py: ['subprocess.run("ping " + host, shell=True)', 'subprocess.run(["ping", "-c", "1", host], check=True)   # + validation de host'],
      java: ['Runtime.getRuntime().exec("ping " + host);', 'new ProcessBuilder("ping", "-c", "1", host).start();   // + validation de host'],
    },
    ref: OWASP("OS_Command_Injection_Defense"),
  },
  {
    id: "codei", cwe: ["CWE-94", "CWE-95"], words: ["eval", "code-injection", "new-function", "dynamic-code"],
    title: "Exécution de code dynamique (eval)",
    why: "Du texte est exécuté comme du code : si une partie vient de l'utilisateur, il contrôle l'application.",
    steps: [
      "Supprimez `eval`, `Function` ou `exec` : utilisez un parseur (JSON.parse, ast.literal_eval) ou une table de fonctions.",
      "Si c'est inévitable, exécutez dans un bac à sable sans accès au reste de l'application.",
    ],
    examples: {
      js: ["const v = eval(req.query.expr);", "const v = JSON.parse(req.query.data);"],
      py: ["value = eval(user_text)", "import ast\nvalue = ast.literal_eval(user_text)"],
    },
    ref: OWASP("Injection_Prevention"),
  },
  {
    id: "path", cwe: ["CWE-22", "CWE-23", "CWE-73"], words: ["path-traversal", "directory-traversal", "path_traversal", "zip-slip"],
    title: "Traversée de répertoire",
    why: "Un nom de fichier fourni par l'utilisateur peut contenir `../` et sortir du dossier prévu.",
    steps: [
      "Construisez le chemin final, résolvez-le (chemin canonique) puis vérifiez qu'il reste sous le dossier autorisé.",
      "Utilisez un identifiant plutôt qu'un nom de fichier venant de l'utilisateur.",
      "Pour les archives, refusez les entrées dont le chemin sort du dossier cible (zip-slip).",
    ],
    examples: {
      js: ["res.sendFile(path.join(DIR, req.query.f))", "const p = path.resolve(DIR, req.query.f);\nif (!p.startsWith(path.resolve(DIR) + path.sep)) return res.sendStatus(400);\nres.sendFile(p);"],
      py: ["open(os.path.join(BASE, name))", "p = os.path.realpath(os.path.join(BASE, name))\nif not p.startswith(os.path.realpath(BASE) + os.sep):\n    abort(400)"],
      java: ["new File(BASE, name)", "File f = new File(BASE, name).getCanonicalFile();\nif (!f.toPath().startsWith(Path.of(BASE).toRealPath())) throw new SecurityException();"],
    },
    ref: OWASP("Input_Validation"),
  },
  {
    id: "secret", cwe: ["CWE-798", "CWE-259", "CWE-321"], words: ["hardcoded", "hard-coded", "api-key", "apikey", "private-key"],
    title: "Secret codé en dur",
    why: "Un mot de passe ou une clé est écrit dans le code : toute personne qui lit le dépôt (ou son historique) l'obtient.",
    steps: [
      "Révoquez ou changez le secret maintenant : il est déjà exposé.",
      "Lisez-le depuis une variable d'environnement ou un gestionnaire de secrets (Vault, AWS Secrets Manager).",
      "Retirez-le de l'historique git si le dépôt est partagé.",
      "Ajoutez un contrôle gitleaks en pré-commit.",
    ],
    examples: {
      js: ['const KEY = "sk_live_51H...";', "const KEY = process.env.STRIPE_KEY;"],
      py: ['PASSWORD = "s3cret"', 'PASSWORD = os.environ["DB_PASSWORD"]'],
      java: ['String pwd = "s3cret";', 'String pwd = System.getenv("DB_PASSWORD");'],
    },
    ref: OWASP("Secrets_Management"),
  },
  {
    id: "random", cwe: ["CWE-330", "CWE-338", "CWE-331"], words: ["weak-random", "math-random", "insecure-random", "random()"],
    title: "Générateur aléatoire non sûr",
    why: "Un générateur prévisible sert à créer un jeton, un mot de passe ou un identifiant de session : il peut être deviné.",
    steps: ["Utilisez le générateur cryptographique du langage pour tout ce qui touche à la sécurité."],
    examples: {
      js: ["const token = Math.random().toString(36);", 'const token = crypto.randomBytes(32).toString("hex");'],
      py: ["token = str(random.random())", "token = secrets.token_urlsafe(32)"],
      java: ["new Random().nextInt()", "new SecureRandom().nextInt()"],
    },
    ref: OWASP("Cryptographic_Storage"),
  },
  {
    id: "hash", cwe: ["CWE-327", "CWE-328", "CWE-916", "CWE-326"], words: ["weak-crypto", "md5", "sha1", "ecb", "cipher", "weak-hash", "createhash"],
    title: "Algorithme cryptographique faible",
    why: "MD5, SHA-1, DES ou le mode ECB sont cassés ou trop rapides à attaquer.",
    steps: [
      "Mots de passe : bcrypt, scrypt ou Argon2 (jamais un simple hash).",
      "Intégrité : SHA-256 ou plus.",
      "Chiffrement : AES-256-GCM, avec un nonce aléatoire par message.",
    ],
    examples: {
      js: ['crypto.createHash("md5").update(password).digest("hex")', "await bcrypt.hash(password, 12)"],
      py: ["hashlib.md5(password.encode()).hexdigest()", "bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))"],
      java: ['MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-256")   // mots de passe : BCryptPasswordEncoder'],
    },
    ref: OWASP("Password_Storage"),
  },
  {
    id: "deser", cwe: ["CWE-502"], words: ["deserializ", "pickle", "yaml.load", "unserialize", "objectinputstream"],
    title: "Désérialisation non sûre",
    why: "Des données non fiables sont reconstruites en objets : cela peut exécuter du code.",
    steps: [
      "N'utilisez pas pickle, ObjectInputStream ou unserialize sur des données externes : préférez JSON.",
      "Pour YAML, utilisez le chargeur sûr.",
      "Si inévitable, filtrez strictement les classes autorisées et signez les données.",
    ],
    examples: {
      py: ["data = yaml.load(text)", "data = yaml.safe_load(text)"],
      java: ["new ObjectInputStream(in).readObject()", "objectMapper.readValue(in, Expected.class)   // JSON typé"],
      php: ["unserialize($_COOKIE['d'])", "json_decode($_COOKIE['d'], true)"],
    },
    ref: OWASP("Deserialization"),
  },
  {
    id: "xxe", cwe: ["CWE-611", "CWE-776"], words: ["xxe", "external-entit", "xml-parser", "documentbuilder"],
    title: "Entités XML externes (XXE)",
    why: "Le parseur XML suit des références externes : lecture de fichiers locaux ou requêtes internes.",
    steps: ["Désactivez les DTD et les entités externes sur le parseur."],
    examples: {
      java: ["DocumentBuilderFactory.newInstance()", 'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'],
      py: ["etree.parse(path)", "import defusedxml.ElementTree as ET\nET.parse(path)"],
    },
    ref: OWASP("XML_External_Entity_Prevention"),
  },
  {
    id: "ssrf", cwe: ["CWE-918"], words: ["ssrf", "server-side-request"],
    title: "Requête côté serveur falsifiée (SSRF)",
    why: "Le serveur appelle une URL choisie par l'utilisateur : accès aux services internes, métadonnées cloud.",
    steps: [
      "N'autorisez qu'une liste blanche de domaines.",
      "Résolvez le nom et refusez les adresses privées (127.0.0.0/8, 10.0.0.0/8, 169.254.169.254…).",
      "Désactivez les redirections automatiques.",
    ],
    examples: {
      js: ["const r = await fetch(req.query.url);", 'const u = new URL(req.query.url);\nif (!ALLOWED_HOSTS.has(u.hostname)) return res.sendStatus(400);\nconst r = await fetch(u, { redirect: "error" });'],
      py: ['requests.get(request.args["url"])', "if urlparse(url).hostname not in ALLOWED_HOSTS:\n    abort(400)\nrequests.get(url, allow_redirects=False, timeout=5)"],
    },
    ref: OWASP("Server_Side_Request_Forgery_Prevention"),
  },
  {
    id: "csrf", cwe: ["CWE-352"], words: ["csrf"],
    title: "Falsification de requête (CSRF)",
    why: "Un site tiers peut faire envoyer au navigateur de la victime une action authentifiée.",
    steps: [
      "Ajoutez un jeton anti-CSRF à chaque requête qui modifie l'état.",
      "Cookies de session en `SameSite=Lax` ou `Strict`.",
      "Vérifiez l'en-tête Origin pour les API.",
    ],
    examples: { js: ["app.use(session({ secret: S }));   // aucune protection CSRF", 'app.use(csurf({ cookie: { sameSite: "lax", httpOnly: true } }));'] },
    ref: OWASP("Cross-Site_Request_Forgery_Prevention"),
  },
  {
    id: "redirect", cwe: ["CWE-601"], words: ["open-redirect", "unvalidated-redirect"],
    title: "Redirection ouverte",
    why: "L'adresse de redirection vient de l'utilisateur : le site sert à des campagnes d'hameçonnage.",
    steps: ["Redirigez vers des chemins internes ou une liste blanche d'adresses, jamais vers une URL libre."],
    examples: { js: ["res.redirect(req.query.next)", 'const ok = ["/home", "/profile"];\nres.redirect(ok.includes(req.query.next) ? req.query.next : "/home");'] },
    ref: OWASP("Unvalidated_Redirects_and_Forwards"),
  },
  {
    id: "cookie", cwe: ["CWE-614", "CWE-1004", "CWE-1275", "CWE-522"], words: ["cookie", "httponly", "secure-flag", "samesite"],
    title: "Cookie sans protection",
    why: "Sans `HttpOnly`, `Secure` et `SameSite`, le cookie de session peut être volé ou envoyé par un site tiers.",
    steps: ["Activez `HttpOnly`, `Secure` (HTTPS) et `SameSite` sur les cookies de session."],
    examples: { js: ['res.cookie("sid", id)', 'res.cookie("sid", id, { httpOnly: true, secure: true, sameSite: "lax" })'] },
    ref: OWASP("Session_Management"),
  },
  {
    id: "tls", cwe: ["CWE-295", "CWE-297"], words: ["verify=false", "rejectunauthorized", "insecure-tls", "tls-verify", "ssl-verify", "trustallcerts"],
    title: "Vérification TLS désactivée",
    why: "Le certificat du serveur n'est plus vérifié : une attaque de l'homme du milieu est possible.",
    steps: ["Supprimez l'option qui désactive la vérification ; ajoutez l'autorité de certification au besoin."],
    examples: {
      py: ["requests.get(url, verify=False)", 'requests.get(url, verify="/etc/ssl/ca.pem")   # ou verify=True'],
      js: ["https.request({ rejectUnauthorized: false })", 'https.request({ ca: fs.readFileSync("ca.pem") })'],
    },
    ref: OWASP("Transport_Layer_Security"),
  },
  {
    id: "http", cwe: ["CWE-319", "CWE-311"], words: ["plaintext-http", "insecure-transport", "using-http-server", "http-server"],
    title: "Communication en clair (HTTP)",
    why: "Les données circulent sans chiffrement : elles peuvent être lues ou modifiées sur le réseau.",
    steps: [
      "Utilisez https:// pour tous les liens, appels d'API et ressources.",
      "Terminez le TLS (certificat valide) sur le serveur ou sur le reverse proxy, et redirigez HTTP vers HTTPS.",
      "Ajoutez l'en-tête Strict-Transport-Security (HSTS).",
    ],
    examples: { js: ['const api = "http://api.example.com";', 'const api = "https://api.example.com";'] },
    ref: OWASP("Transport_Layer_Security"),
  },
  {
    id: "ci-pin", cwe: ["CWE-1357", "CWE-829"], words: ["mutable-action-tag", "github-actions"],
    title: "Action GitHub non épinglée",
    why: "`uses: org/action@v3` suit un tag modifiable : si l'auteur (ou un attaquant qui le compromet) republie ce tag, votre pipeline exécute son code.",
    steps: [
      "Épinglez l'action sur le hash complet du commit (40 caractères), avec le tag en commentaire.",
      "Activez Dependabot pour les actions afin de recevoir les mises à jour.",
    ],
    examples: { other: ["uses: actions/checkout@v4", "uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1"] },
    ref: ["GitHub — Sécuriser l'utilisation des actions", "https://docs.github.com/fr/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"],
  },
  {
    id: "container", cwe: ["CWE-732", "CWE-250"], words: ["no-new-privileges", "writable-filesystem", "privileged", "docker-compose"],
    title: "Conteneur trop permissif",
    why: "Le conteneur peut gagner des privilèges ou écrire sur son système de fichiers : une compromission de l'application s'étend plus facilement à l'hôte.",
    steps: [
      "Interdisez l'élévation de privilèges (`no-new-privileges`).",
      "Rendez le système de fichiers en lecture seule et montez uniquement les dossiers qui doivent être écrits.",
      "Ne lancez pas le conteneur en root ni en mode `privileged`.",
    ],
    examples: { other: ["services:\n  app:\n    image: myapp", "services:\n  app:\n    image: myapp\n    read_only: true\n    security_opt:\n      - no-new-privileges:true\n    user: \"1000:1000\""] },
    ref: OWASP("Docker_Security"),
  },
  {
    id: "authz", cwe: ["CWE-862", "CWE-863", "CWE-639", "CWE-284"], words: ["idor", "missing-authorization", "access-control", "broken-access"],
    title: "Contrôle d'accès insuffisant",
    why: "L'application ne vérifie pas que l'utilisateur a le droit d'accéder à cette ressource.",
    steps: [
      "Vérifiez les droits côté serveur à chaque accès (propriétaire de la ressource, rôle).",
      "Refusez par défaut : une route est interdite tant qu'elle n'est pas explicitement autorisée.",
    ],
    ref: OWASP("Authorization"),
  },
];

export function matchRule(c: Pick<CveDto, "cveId" | "cweId" | "packageName">): Rule | null {
  const cwe = `${c.cweId ?? ""} ${c.cveId ?? ""}`.toUpperCase();
  const rule = `${c.packageName ?? ""}`.toLowerCase();
  for (const r of RULES) {
    if (r.cwe.some((x) => new RegExp(`${x}(?!\\d)`).test(cwe))) return r;
  }
  for (const r of RULES) {
    if (r.words.some((w) => rule.includes(w))) return r;
  }
  return null;
}

export function codeFix(c: CveDto): CodeFix | null {
  const r = matchRule(c);
  if (!r) return null;
  const lang = languageOf(c.filePath);
  const ex = r.examples?.[lang];
  return {
    id: r.id,
    title: r.title,
    why: r.why,
    steps: r.steps,
    bad: ex?.[0],
    good: ex?.[1],
    ref: { label: r.ref[0], url: r.ref[1] },
  };
}
