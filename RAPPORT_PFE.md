# Documentation Technique — Projet PFE : Vulnix

> **Auteur :** [Ton prénom & nom]
> **Établissement :** [Ton école / université]
> **Année :** 2025–2026
> **Encadrant :** [Nom de l'encadrant]

---

## 1. Présentation générale du projet

**Vulnix** est une plateforme d'analyse de sécurité automatisée (DevSecOps) développée dans le cadre d'un Projet de Fin d'Études. Son objectif est de permettre à un développeur ou à un ingénieur sécurité de soumettre l'URL d'un dépôt Git public ou privé, de lancer une analyse de sécurité complète, et de consulter les résultats via une interface web moderne.

### Problème résolu

Aujourd'hui, l'analyse de sécurité d'une application nécessite d'installer et de maîtriser une dizaine d'outils différents (Grype, Trivy, Semgrep, Gitleaks, etc.), d'interpréter des fichiers JSON bruts, et de prioriser manuellement les vulnérabilités. Vulnix automatise l'intégralité de ce processus en une seule interface.

### Résultat obtenu

- Connexion via GitHub OAuth 2.0 → sessions sécurisées par JWT
- Soumission d'un dépôt Git, d'une image Docker, ou d'un domaine SSL → analyse complète en quelques minutes
- Détection de vulnérabilités de dépendances (CVE), de secrets exposés, de failles de code statique (SAST), de vulnérabilités dynamiques (DAST), et de configurations TLS défectueuses (SSL)
- Enrichissement automatique depuis NVD (descriptions, scores CVSS), Exploit-DB (exploits publics), CISA KEV (exploitations actives) et EPSS (probabilité d'exploitation)
- Résumé exécutif par IA Gemini et inventaire SBOM consultable depuis l'interface
- Analyse SSL multi-source agrégée (pipeline Kali + SSL Labs + Censys + SSLyze)
- Interface web claire avec priorisation composite (CVSS + EPSS + Exploit), badges visuels, export PDF, et correction automatique des dépendances via commit GitHub

---

## 2. Architecture globale

```
┌─────────────────────────────────────────────────────────────────┐
│                          UTILISATEUR                            │
│                    (navigateur web : React)                     │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTP / API REST / SSE (logs live)
                               │ Authorization: Bearer JWT
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     BACKEND (Spring Boot)                       │
│  - AuthController  : GitHub OAuth 2.0 → JWT + profil + repos   │
│  - ScanController  : scans, SSE, CVEs, SBOM, résumé IA         │
│  - SslController   : scan SSL/TLS agrégé + analyse IA          │
│  - AutoFixController: correction automatique des dépendances   │
│  - Services: NVD, EPSS, CISA KEV, Exploit-DB, SSL Labs,        │
│              Censys, Gemini Summary / SSL AI                   │
└───────────────┬──────────────────┬──────────────┬──────────────┘
                │                  │              │
                ▼                  ▼              ▼
┌─────────────────┐   ┌──────────────────────┐  ┌───────────────┐
│  PostgreSQL     │   │  Docker Scanner      │  │  GitHub API   │
│  - repositories │   │  (Kali Linux)        │  │  - OAuth      │
│  - scan_results │   │  - Grype / Trivy     │  │  - Advisories │
│  - cve_entries  │   │  - Semgrep / Gitleaks│  │  - Commits    │
│  - secret_      │   │  - OWASP ZAP (DAST)  │  └───────────────┘
│    findings     │   │  - sslyze / testssl  │
│  - nvd_cache    │   │    (SSL-only mode)   │
└─────────────────┘   └──────────────────────┘
```

**Technologies utilisées :**

| Couche            | Technologie                               | Version / précision                  |
| ----------------- | ----------------------------------------- | ------------------------------------ |
| Frontend          | React + TypeScript                        | React 18.2 / TypeScript 4.9.5        |
| Routing           | react-router-dom                          | 7.14                                 |
| CSS               | Tailwind CSS                              | 3.4                                  |
| Backend           | Spring Boot                               | 3.2.5                                |
| Langage Backend   | Java                                      | 17                                   |
| Base de données   | PostgreSQL                                | 15                                   |
| Conteneur scanner | Docker + Kali Linux                       | rolling                              |
| ORM               | Hibernate / JPA                           | inclus dans Spring Boot              |
| Auth              | GitHub OAuth 2.0 + JWT (JJWT)             | OAuth 2.0 + HS256                    |
| PDF               | jsPDF + jspdf-autotable                   | 4.2.1 / 5.0.7                        |
| IA                | Google Gemini Flash                       | 1.5                                  |

---

## 3. Composant 1 — Le Scanner Docker (Image Kali Linux)

### Rôle

Le scanner est une **image Docker basée sur Kali Linux** qui contient tous les outils de sécurité pré-installés. Lorsqu'un scan est lancé, le backend crée un conteneur à partir de cette image, lui passe l'URL du dépôt à analyser, et le conteneur produit des fichiers JSON de résultats dans un dossier partagé.

### Fonctionnement

1. **Le backend** exécute la commande Docker suivante :

   ```bash
   docker run --rm \
     -e REPO_URL=<url_du_depot> \
     -e SCAN_MODE=auto \
     -v /chemin/vers/resultats:/workspace/results \
     medianet-kali-scanner:auto
   ```

2. **Le script `scan.sh`** s'exécute à l'intérieur du conteneur :
   - Clone le dépôt Git dans `/workspace/repo`
   - Détecte automatiquement l'écosystème (Node.js, Java, Python, Go, PHP, Rust, Docker, etc.)
   - Lance les outils de scan correspondants
   - Écrit les résultats dans `/workspace/results/`

3. **Scripts de scan spécialisés** dans `scanner-image/scripts/` :

| Script                 | Outils utilisés               | Ce que ça détecte                                    |
| ---------------------- | ----------------------------- | ---------------------------------------------------- |
| `detect_ecosystems.sh` | Analyse les fichiers du dépôt | Identifie le langage / framework                     |
| `run_node_scans.sh`    | `npm audit`, Grype, Trivy     | CVEs des dépendances Node.js                         |
| `run_java_scans.sh`    | OWASP Dependency-Check, Grype | CVEs des dépendances Java/Maven                      |
| `run_python_scans.sh`  | `pip-audit`, OSV-Scanner      | CVEs des dépendances Python                          |
| `run_go_scans.sh`      | `govulncheck`, Grype          | CVEs des dépendances Go                              |
| `run_php_scans.sh`     | `local-php-security-checker`  | CVEs des dépendances PHP/Composer                    |
| `run_rust_scans.sh`    | `cargo audit`                 | CVEs des dépendances Rust                            |
| `run_docker_scans.sh`  | Trivy                         | CVEs dans les images Docker                          |
| `run_generic_scans.sh` | Semgrep, Gitleaks, Grype      | Code statique + secrets exposés                      |
| `run_ssl_scans.sh`     | sslscan, testssl.sh           | Failles SSL/TLS d'un domaine                         |
| `run_license_scan.sh`  | Trivy                         | Licences des dépendances                             |
| `run_iac_scans.sh`     | Trivy                         | Mauvaises configurations IaC (Terraform, Kubernetes) |
| `run_dast_scans.sh`    | OWASP ZAP                     | Tests dynamiques : SQLi, XSS, CSRF, headers (DAST)   |

4. **Fichiers de sortie** produits dans le dossier de résultats :

| Fichier                        | Contenu                                                        |
| ------------------------------ | -------------------------------------------------------------- |
| `result.json`                  | Métadonnées : durée, outils exécutés, écosystèmes détectés     |
| `grype.json`                   | CVEs détectées par Grype                                       |
| `trivy.json`                   | CVEs détectées par Trivy                                       |
| `osv-scanner.json`             | CVEs détectées par OSV-Scanner                                 |
| `semgrep.json`                 | Failles de code statique (OWASP)                               |
| `gitleaks.json`                | Secrets exposés dans le code (clés API, tokens, mots de passe) |
| `npm-audit.json`               | Audit Node.js                                                  |
| `dependency-check-report.json` | OWASP Dependency-Check                                         |
| `sbom.json`                    | Software Bill of Materials (liste des composants)              |
| `ssl-summary.json`             | Résumé SSL normalisé construit par le pipeline Kali            |
| `ssl-labs-result.json`         | Résultat externe SSL Labs                                      |
| `censys-result.json`           | Résultat externe Censys Platform                               |
| `sslyze.json`                  | Audit détaillé SSLyze                                          |
| `zap.json`                     | Alertes DAST OWASP ZAP (SQLi, XSS, CSRF, headers manquants)    |

---

## 4. Composant 2 — Le Backend (Spring Boot)

### Rôle

Le backend est le **cerveau de l'application**. Il reçoit les requêtes du frontend, orchestre les scans, parse les résultats, enrichit les données, et les expose via une API REST.

### Structure des fichiers

```
Backend/src/main/java/com/medianet/
├── MedianetApplication.java         ← Point d'entrée Spring Boot
├── config/
│   └── CorsConfig.java              ← Configuration CORS (autorise localhost:3000)
├── util/
│   └── JwtUtil.java                 ← Extraction du login GitHub depuis le JWT
├── entity/                          ← Modèles de données (tables BDD)
│   ├── Repository.java              ← Dépôt Git scanné (ownerLogin, targetDomain)
│   ├── ScanResult.java              ← Résultat d'un scan (PENDING/RUNNING/COMPLETED/FAILED)
│   ├── CveEntry.java                ← Une vulnérabilité CVE (voir détails colonnes ci-dessous)
│   └── SecretFinding.java           ← Un secret exposé (gitleaks)
├── dto/                             ← Objets de transfert (réponses API)
│   ├── CveDto.java
│   ├── ScanResultDto.java
│   ├── RepositoryDto.java
│   ├── SecretDto.java
│   ├── SastFindingDto.java          ← Résultats Semgrep (SAST)
│   ├── SslResultDto.java            ← Résultat SSL agrégé (Kali + SSL Labs + Censys + SSLyze)
│   ├── ScanRequest.java             ← repoUrl, branch, scanMode, targetDomain, dastTargetUrl, dockerImage, containerPort
│   └── ScanResponse.java
├── repository/                      ← Accès base de données (Spring Data JPA)
│   ├── CveEntryRepo.java
│   ├── ScanResultRepo.java
│   ├── RepositoryRepo.java
│   ├── SecretFindingRepo.java
│   └── NvdCacheRepo.java
├── service/                         ← Logique métier
│   ├── ScanService.java             ← Orchestre les scans Docker, SSE, arrêt
│   ├── ResultParserService.java     ← Parse grype/trivy/semgrep/gitleaks/zap/ssl JSON
│   ├── NvdEnrichmentService.java    ← Enrichissement NVD API + GitHub Advisory
│   ├── ExploitDbService.java        ← Exploitation CSV Exploit-DB (72 h refresh)
│   ├── CisaKevService.java          ← Catalogue CISA KEV (24 h refresh)
│   ├── EpssService.java             ← Scores EPSS batch FIRST.org (48 h refresh)
│   ├── AutoFixService.java          ← Correction programmatique + Gemini AI fallback
│   ├── GeminiSummaryService.java    ← Résumé exécutif IA d'un scan
│   ├── SslLabsService.java          ← Audit externe SSL Labs (@Async)
│   ├── CensysSslService.java        ← Audit externe Censys Platform (@Async)
│   ├── SslAiService.java            ← Interprétation IA du contexte SSL
│   └── TranslationService.java      ← Traduction EN→FR via MyMemory API
└── controller/
   ├── ScanController.java         ← API scans, repositories, résumé IA, SBOM
   ├── SslController.java          ← API SSL dédiée (/api/ssl/scan, /api/ssl/ai-analysis)
   ├── AuthController.java         ← GitHub OAuth 2.0 + /me + /github/repos
   ├── AutoFixController.java      ← Auto-fix (/api/autofix/preview, /apply)
   └── HelloController.java
```

### Base de données (tables PostgreSQL)

| Table               | Colonnes principales                                                                                                                                                                                                                                                                                               | Rôle                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------- |
| `repositories`      | `id`, `repo_url`, `owner_login`, `branch`, `scan_mode`, `target_domain`, `created_at`, `last_scanned_at`                                                                                                                                                                                                           | Dépôts Git soumis, scopés par user |
| `scan_results`      | `id`, `status` (PENDING/RUNNING/COMPLETED/FAILED), `started_at`, `finished_at`, `results_dir`, `ecosystems_detected`, `tools_executed`, `repository_id`                                                                                                                                                            | Chaque scan lancé                  |
| `cve_entries`       | `id`, `cve_id`, `package_name`, `package_version`, `severity`, `cvss_score`, `fixed_version`, `description`, `data_source`, `source`, `file_path`, `line_number`, `exploit_available`, `exploit_url`, `kev_listed`, `kev_date_added`, `kev_ransomware`, `epss_score`, `epss_percentile`, `confirmed_by`, `sources` | CVE ou alerte DAST/SAST            |
| `secret_findings`   | `id`, `rule_id`, `file`, `match`, `commit`, `scan_result_id`                                                                                                                                                                                                                                                       | Secret exposé (Gitleaks)           |
| `nvd_cache_entries` | `cve_id`, `description`, `cvss_score`, `cached_at`                                                                                                                                                                                                                                                                 | Cache NVD (30 jours)               |

### API REST exposée

**Scans & Résultats (`ScanController`) :**

| Méthode | Route                            | Auth JWT  | Description                                 |
| ------- | -------------------------------- | --------- | ------------------------------------------- |
| POST    | `/api/scans`                     | optionnel | Lancer un scan                              |
| GET     | `/api/scans`                     | optionnel | Liste des scans (scopés par user)           |
| GET     | `/api/scans/{id}/logs`           | non       | Stream SSE des logs en direct               |
| GET     | `/api/scans/{id}/cves`           | non       | CVEs d'un scan                              |
| GET     | `/api/scans/{id}/secrets`        | non       | Secrets d'un scan                           |
| GET     | `/api/scans/{id}/sast`           | non       | Findings SAST (Semgrep) d'un scan           |
| GET     | `/api/scans/{id}/ai-summary`     | non       | Résumé exécutif Gemini du scan              |
| GET     | `/api/scans/{id}/sbom`           | non       | Composants SBOM du scan                     |
| POST    | `/api/scans/{id}/stop`           | non       | Arrêter un scan en cours                    |
| DELETE  | `/api/scans/{id}`                | non       | Supprimer un scan                           |
| GET     | `/api/repositories`              | optionnel | Liste des dépôts scannés                    |
| GET     | `/api/repositories/{id}/scans`   | non       | Historique des scans d'un dépôt             |
| GET     | `/api/repositories/{id}/cves`    | non       | CVEs du dernier scan d'un dépôt             |
| POST    | `/api/admin/enrich-missing-cves` | non       | Re-enrichir les CVEs manquantes             |
| POST    | `/api/admin/enrich-exploits`     | non       | Re-enrichir Exploit-DB sur toutes les CVEs  |
| POST    | `/api/admin/enrich-kev`          | non       | Re-enrichir CISA KEV sur toutes les CVEs    |
| POST    | `/api/admin/enrich-epss`         | non       | Re-enrichir scores EPSS sur toutes les CVEs |

**SSL (`SslController`) :**

| Méthode | Route                       | Description                                                                 |
| ------- | --------------------------- | --------------------------------------------------------------------------- |
| POST    | `/api/ssl/scan`             | Lancer un scan SSL sur un domaine                                           |
| GET     | `/api/ssl/scan/{id}/logs`   | Stream SSE des logs SSL en direct                                           |
| GET     | `/api/ssl/scan/{id}/result` | Résumé SSL agrégé (Kali + SSL Labs + Censys + SSLyze, avec `combinedGrade`) |
| POST    | `/api/ssl/ai-analysis`      | Analyse contextuelle Gemini d'un résultat SSL                               |

**Authentification GitHub OAuth (`AuthController`) :**

| Méthode | Route                       | Description                                                                          |
| ------- | --------------------------- | ------------------------------------------------------------------------------------ |
| GET     | `/api/auth/github`          | Redirige vers GitHub OAuth                                                           |
| GET     | `/api/auth/github/callback` | Reçoit le code OAuth, échange contre un token, redirige vers le frontend avec un JWT |
| GET     | `/api/auth/me`              | Valide le JWT et retourne le profil GitHub courant                                   |
| GET     | `/api/auth/github/repos`    | Liste les dépôts GitHub accessibles à l'utilisateur connecté                         |

**Auto-Fix (`AutoFixController`) :**

| Méthode | Route                  | Description                                             |
| ------- | ---------------------- | ------------------------------------------------------- |
| POST    | `/api/autofix/preview` | Aperçu de la correction (diff original/corrigé + SHA)   |
| POST    | `/api/autofix/apply`   | Applique la correction (commit GitHub)                  |

### Comment fonctionne un scan (flux complet)

```
1. Utilisateur → POST /api/scans { repoUrl, branch, scanMode, dastTargetUrl? }
   (optionnel: header Authorization: Bearer <JWT GitHub>)
2. Backend trouve ou crée un Repository en BDD (scopé à l'ownerLogin du JWT)
3. Backend crée un ScanResult en BDD (status = PENDING → RUNNING)
4. Backend crée un dossier UUID dans scan-results/
5. Backend lance docker run ... en arrière-plan (ExecutorService.newCachedThreadPool)
   - Variables d'env : REPO_URL, SCAN_MODE, TARGET_DOMAIN, DAST_TARGET_URL
   - Selon le mode : DOCKER_IMAGE, CONTAINER_PORT
   - Volume : scan-results/{UUID}:/workspace/results
6. Les logs Docker sont streamés ligne par ligne via SSE (logBuffers + SseEmitter)
7. À la fin du Docker :
   a. ResultParserService parse les JSON → liste de CveEntry (grype, trivy, osv, semgrep, gitleaks, zap)
   b. NvdEnrichmentService enrichit avec NVD API (description, CVSS, sévérité)
   c. ExploitDbService enrichit depuis l'index CSV en mémoire (exploit_available, exploit_url)
   d. CisaKevService enrichit depuis l'index KEV en mémoire (kev_listed, kev_date_added, kev_ransomware)
   e. EpssService enrichit par batch depuis FIRST.org (epss_score, epss_percentile)
   f. TranslationService traduit les descriptions EN→FR via MyMemory API
   g. Le SBOM reste disponible tel quel via `GET /api/scans/{id}/sbom`
   h. Tout est sauvegardé en BDD
8. ScanResult status → COMPLETED (ou FAILED si erreur)
9. Frontend reçoit le signal %%SCAN_COMPLETE%% via SSE, ferme la connexion, charge les CVEs
10. L'interface peut ensuite appeler `GET /api/scans/{id}/ai-summary` pour obtenir le résumé exécutif IA
```

---

## 5. Composant 3 — Le Service d'Enrichissement NVD

### Rôle

La plupart des outils de scan retournent un CVE-ID (ex: `CVE-2021-44228`) sans description ni score CVSS détaillé. Le service NVD va chercher ces informations sur l'API officielle de la National Vulnerability Database (NIST).

### Fonctionnement

- **CVE-XXXX-XXXX** → appel à `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`
- **GHSA-XXXX-XXXX** → appel à l'API GitHub Advisory `https://api.github.com/advisories/...`
- **CWE-XX** → base locale statique (pas d'appel externe, descriptions en français)
- **Cache 30 jours** : si un CVE a déjà été enrichi récemment, il n'est pas rappelé
- **Traduction automatique** : les descriptions anglaises sont traduites en français via MyMemory API (gratuit, 100 000 caractères/jour)

### Clés de configuration

```properties
nvd.api.key=<clé_NVD>           # Clé API NVD (https://nvd.nist.gov/developers/request-an-api-key)
translation.enabled=true
translation.email=<email>        # Augmente la limite MyMemory à 100 000 chars/jour
```

---

## 6. Composant 4 — Le Service Exploit-DB

### Rôle

Exploit-DB est une base de données publique d'exploits réels. Pour chaque CVE trouvée, ce service vérifie si un code d'exploitation public existe. Cela permet de **distinguer les vulnérabilités théoriques des menaces réelles et actionnables**.

### Fonctionnement

1. **Au démarrage** : télécharge le fichier CSV officiel depuis GitLab d'Exploit-DB
   - URL : `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`
   - Sauvegardé localement dans `exploitdb-cache.csv`
2. **Si pas de connexion** : utilise le fichier local existant (mode offline)
3. **Toutes les 72 heures** : un `@Scheduled` relance le téléchargement pour rester à jour
4. **Indexation en mémoire** : `Map<CVE-ID → List<ID exploit>>` pour une recherche instantanée

### Impact sur les données

Les champs suivants sont ajoutés à chaque `CveEntry` et exposés dans l'API :

| Champ               | Type    | Valeur                                        |
| ------------------- | ------- | --------------------------------------------- |
| `exploit_available` | boolean | `true` si un exploit public existe            |
| `exploit_url`       | String  | URL directe vers l'exploit sur exploit-db.com |

### Valeur ajoutée

Sans Exploit-DB : deux CVEs CRITICAL ont le même poids.
Avec Exploit-DB : on sait lequel peut être attaqué **aujourd'hui** avec un outil téléchargeable.

---

## 7. Composant 5 — Le Frontend (React + TypeScript)

### Rôle

Interface web moderne qui permet de lancer des scans, visualiser les résultats, et naviguer dans les vulnérabilités.

### Pages de l'application

| Page                  | Route              | Fonctionnalité                                               |
| --------------------- | ------------------ | ------------------------------------------------------------ |
| `Login.tsx`           | `/login`           | Authentification GitHub OAuth (bouton de connexion)          |
| `AuthCallback.tsx`    | `/auth/callback`   | Réception du JWT après le retour OAuth GitHub                |
| `Dashboard.tsx`       | `/`                | Vue d'ensemble : compteurs, scans récents, graphiques        |
| `Scans.tsx`           | `/scans`           | Lancer un nouveau scan (repo Git, image Docker, SSL, DAST)   |
| `Vulnerabilities.tsx` | `/vulnerabilities` | CVEs, findings, SBOM, résumé IA, auto-fix, export PDF        |
| `Repositories.tsx`    | `/repositories`    | Liste des dépôts scannés avec historique                     |
| `Pipeline.tsx`        | `/pipeline`        | Vue pipeline CI/CD des scans                                 |
| `SSLAnalysis.tsx`     | `/ssl-analysis`    | Analyse SSL/TLS multi-source (grade agrégé, sources, IA)     |
| `ServerConfig.tsx`    | `/server-config`   | Configuration locale et options serveur                      |

Toutes les routes applicatives, sauf `/login` et `/auth/callback`, sont protégées par `ProtectedLayout`.

### Design System

- **Thème** : sombre (dark mode), inspiré Material You de Google
- **Couleurs** : primary=#a4e6ff (cyan), secondary=#d1bcff (violet), tertiary=#00fc92 (vert), error=#ffb4ab (rouge)
- **Typographies** : Space Grotesk (titres), Inter (corps de texte)
- **Icônes** : Google Material Symbols (chargées via CDN Google Fonts)
- **Effets** : Glass panels avec `backdrop-blur`, animations de scan (ring pulsant)

### Page Vulnerabilities — fonctionnalités clés

- Sélecteur de scan avec statut en temps réel (RUNNING / COMPLETED / FAILED)
- Logs en direct via **Server-Sent Events (SSE)** pendant le scan
- Tableau de CVEs avec colonnes : Vulnerability, Severity, CVSS, Package, Source
- Filtres par sévérité (CRITICAL / HIGH / MEDIUM / LOW / ALL)
- Barre de recherche sur CVE-ID, nom du package, description
- Badge rouge **"EXPLOIT"** cliquable si un exploit public existe (Exploit-DB)
- Badge vert **"CONFIRMÉ"** si la CVE est détectée par ≥ 2 outils indépendants (confirmation croisée)
- Badge de priorité automatique **🔴 URGENT / 🟠 ÉLEVÉ / 🟡 MOYEN / 🟢 FAIBLE** calculé par score composite
- Alertes DAST ZAP affichées avec le badge source `zaproxy` et l'URL affectée en `filePath`
- Résumé exécutif Gemini récupéré via `GET /api/scans/{id}/ai-summary`
- Onglet SBOM avec recherche, filtres et corrélation composants ↔ CVEs
- Fiche détail latérale avec : description, package, version corrigée, score de priorité, niveau de confirmation, référence NVD, lien Exploit-DB
- Recommandation d'action automatique selon le type de faille (CWE)

---

## 8. Composant 6 — Communication temps réel (SSE)

### Pourquoi SSE ?

Un scan Docker peut durer plusieurs minutes. Plutôt que de faire des appels HTTP répétés (polling), l'application utilise les **Server-Sent Events (SSE)** : le serveur pousse les logs au frontend au fur et à mesure, comme un terminal en direct.

### Comment ça fonctionne

```
Frontend                              Backend
   |                                     |
   |── GET /api/scans/{id}/logs ────────>|
   |                                     | (connexion SSE maintenue ouverte)
   |<── "data: [SCAN] Cloning repo..." ──|
   |<── "data: [INFO] Running grype..." ─|
   |<── "data: [NVD] Enriching CVEs..." ─|
   |<── "data: %%SCAN_COMPLETE%%" ───────|
   |                                     | (frontend ferme la connexion et charge les CVEs)
```

Le signal `%%SCAN_COMPLETE%%` est le signal de fin : le frontend le reçoit, ferme la connexion SSE, et appelle automatiquement `GET /api/scans/{id}/cves`.

---

## 9. Sécurité de l'application

### Mesures implémentées et limites connues

| Mesure                                   | Détail                                                                                                                                     |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Authentification GitHub OAuth 2.0        | Sessions utilisateur signées avec JWT (HS256), stockées côté navigateur et envoyées en Bearer sur les requêtes API                        |
| Isolation des données par utilisateur    | Scans et dépôts filtrés par `ownerLogin` extrait du JWT — un utilisateur ne voit pas les scans d'un autre                                  |
| Pas d'exécution de commandes utilisateur | Les commandes Docker sont construites avec des paramètres fixes, les variables d'environnement passées sont des chaînes, pas des commandes |
| Isolation des scans                      | Chaque scan s'exécute dans un conteneur Docker `--rm` (détruit après) avec accès limité                                                    |
| Cache NVD                                | Évite d'exposer trop fréquemment la clé API NVD                                                                                            |
| Gestion de configuration                 | En l'état du prototype, la configuration est centralisée dans `application.properties` ; avant production, les secrets doivent être externalisés |
| CORS                                     | Configuré pour n'accepter que les requêtes du frontend local (`localhost:3000`)                                                            |
| Gestion du token GitHub                  | Le claim `ghToken` est actuellement embarqué dans le JWT pour permettre l'auto-fix GitHub ; c'est pratique pour le PFE, mais à durcir avant production |

Le prototype est cohérent pour un usage local de démonstration, mais un déploiement réel devrait déplacer les secrets vers des variables d'environnement ou un coffre-fort, et sortir le token GitHub du JWT stocké en localStorage.

---

## 10. Configuration et démarrage

### Prérequis

- Java 17 (JBR 17.0.8.1)
- Maven 3.9+
- Node.js 18+
- PostgreSQL 15 (base `medianet_db`, user `postgres`)
- Docker Desktop avec l'image `medianet-kali-scanner:auto` construite

### Démarrage Backend

```powershell
cd Backend
$env:JAVA_HOME = "C:\Users\user\.jdks\jbr-17.0.8.1"
& "C:\Users\user\.maven\maven-3.9.14\bin\mvn.cmd" spring-boot:run
```

→ Démarre sur `http://localhost:8080`

### Démarrage Frontend

```powershell
cd Frontend
npm start
```

→ Démarre sur `http://localhost:3000` (proxy automatique vers 8080 via `setupProxy.js`)

### Fichier de configuration principal

`Backend/src/main/resources/application.properties` :

> Pour le rapport, il faut documenter une **version anonymisée** du fichier. Les clés et secrets vus dans l'environnement de développement ne doivent pas être recopiés tels quels.

```properties
spring.application.name=vulnix

# Base de données
spring.datasource.url=jdbc:postgresql://localhost:5432/medianet_db
spring.datasource.username=postgres
spring.datasource.password=<mot_de_passe>
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true

# Serveur
server.port=8080

# Dossier de résultats des scans
vulnix.results.base-dir=C:/Users/user/Desktop/medianet/scan-results

# Image Docker du scanner
vulnix.docker.image=medianet-kali-scanner:auto

# Clé API NVD (gratuite sur nvd.nist.gov)
nvd.api.key=<clé_api>

# Exploit-DB (cache CSV local, rechargé toutes les 72 h)
exploitdb.csv.local-path=C:/Users/user/Desktop/medianet/exploitdb-cache.csv

# CISA KEV (catalogue JSON local, rechargé toutes les 24 h)
cisa.kev.local-path=C:/Users/user/Desktop/medianet/cisa-kev-cache.json

# Traduction automatique EN→FR
translation.enabled=true
translation.email=<adresse_email>

# SSL Labs
ssllabs.enabled=true
ssllabs.email=<email_professionnel_enregistre_sur_ssllabs>
ssllabs.firstName=<prenom>
ssllabs.lastName=<nom>
ssllabs.organization=<organisation>

# Censys Platform
censys.api.key=<cle_censys>

# GitHub OAuth (Application GitHub → Settings → Developer settings)
github.client.id=<client_id>
github.client.secret=<client_secret>
github.oauth.redirect-uri=http://localhost:8080/api/auth/github/callback
github.oauth.frontend-url=http://localhost:3000

# JWT pour signer les sessions utilisateur
jwt.secret=<chaine_secrete_longue>

# Gemini AI (résumés de scan, analyse SSL, auto-fix fallback)
gemini.api.key=<clé_gemini>
gemini.api.url=https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent
```

---

## 11. Fonctionnalités ajoutées (journal des évolutions)

> Cette section est à mettre à jour à chaque nouvelle fonctionnalité ajoutée.

---

### [Démarrage du projet] — Architecture de base

**Ce qui a été fait :**

- Création du projet Spring Boot avec structure MVC (controller / service / repository / entity)
- Création du projet React avec TypeScript et Tailwind CSS
- Mise en place de la base de données PostgreSQL avec 4 tables
- Création de l'image Docker Kali Linux avec les outils de scan pré-installés
- Premier endpoint : `POST /api/scans` → déclenche le container Docker

---

### [Enrichissement NVD] — Descriptions et scores CVSS automatiques

**Problème résolu :** Les outils de scan (Grype, Trivy) retournent des CVE-IDs mais sans description lisible ni score CVSS précis.

**Solution :** `NvdEnrichmentService.java` appelle l'API NVD et GitHub Advisory pour chaque CVE détectée, stocke le résultat en cache 30 jours dans `nvd_cache_entries`.

**Valeur ajoutée :** Chaque CVE affichée dans l'interface a une description en français, un score CVSS, et une sévérité correcte.

---

### [Traduction FR] — Descriptions CVE en français

**Problème résolu :** Les descriptions NVD sont toutes en anglais.

**Solution :** `TranslationService.java` appelle l'API MyMemory (gratuit, 100 000 caractères/jour avec email) pour traduire chaque description automatiquement.

---

### [Logs en direct (SSE)] — Terminal live dans le frontend

**Problème résolu :** L'utilisateur ne savait pas ce qui se passait pendant les 3-5 minutes de scan.

**Solution :** Utilisation de Server-Sent Events. Le backend (`ScanService.createLogEmitter`) maintient une connexion ouverte et pousse chaque ligne de log Docker au frontend en temps réel.

**Résultat :** Le frontend affiche un "terminal" avec les logs colorisés et scrollables pendant toute la durée du scan.

---

### [Exploit-DB] — Détection des exploits publics

**Date d'ajout :** Avril 2026

**Problème résolu :** Toutes les CVEs ont un score CVSS, mais certaines ont un exploit public téléchargeable (risque immédiat) et d'autres non (risque théorique). Sans cette distinction, on ne peut pas bien prioriser.

**Solution :**

1. `ExploitDbService.java` télécharge le CSV officiel d'Exploit-DB (environ 10 MB) au démarrage depuis `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`
2. Le CSV est indexé en mémoire : `Map<CVE-ID → List<exploit_id>>`
3. Si pas de connexion internet, le fichier local est utilisé (mode offline)
4. Un scheduler `@Scheduled` relance le téléchargement toutes les 72 heures
5. Deux nouveaux champs en base de données : `exploit_available (boolean)` et `exploit_url (text)`
6. Dans le frontend : badge rouge **"EXPLOIT"** sur les CVEs concernées + lien direct vers exploit-db.com + panneau d'alerte dans la fiche détail

**Impact :** Permet de distinguer une CVE 9.8 avec exploit public (danger immédiat) d'une CVE 9.8 purement théorique.

---

### [Multi-confirmation] — Badge « CONFIRMÉ » par recoupement d'outils

**Date d'ajout :** Avril 2026

**Problème résolu :** Un outil de scan peut générer de faux positifs. Si une CVE n'est détectée que par un seul outil, sa fiabilité est incertaine. Inversement, si plusieurs outils indépendants détectent la même CVE sur le même package, c'est un signal fort de vulnérabilité réelle.

**Solution :**

1. Deux nouveaux champs ajoutés à l'entité `CveEntry` et à la table `cve_entries` :
   - `confirmed_by (integer)` : nombre d'outils ayant détecté cette CVE
   - `sources (text)` : liste des noms d'outils (ex: `grype, trivy, dependency-check`)
2. `ResultParserService.java` maintient une `sourcesMap` (`CVE-ID+package → Set<tool>`) et calcule le `confirmedBy` au moment de la déduplication
3. `ScanService.java` propage ces champs dans le `CveDto` retourné par l'API
4. Dans le frontend : badge vert **"CONFIRMÉ"** avec tooltip listant les outils sources
5. Dans la fiche détail : ligne « Confirmation — Détecté par N outils (grype, trivy...) »

**Valeur ajoutée :** Permet de trier les CVEs les plus fiables en priorité et de déprogrammer les faux positifs. Une CVE confirmée par 3 outils est quasi certaine.

---

### [Score de priorité automatique] — Calcul de risque composite

**Date d'ajout :** Avril 2026

**Problème résolu :** Le score CVSS seul ne suffit pas pour prioriser. Une CVE avec CVSS 9.8 mais sans exploit public et sans exploitation active dans le monde réel est moins urgente qu'une CVE CVSS 7.5 avec un exploit téléchargeable et un score EPSS de 90%.

**Solution — Formule de priorité composite :**

$$\text{Priorité} = \left(\frac{\text{CVSS}}{10} \times 0{,}2\right) + (\text{EPSS} \times 0{,}4) + (\text{Exploit} \times 0{,}4)$$

- **CVSS** (0–10) : score de sévérité officiel, poids 20 %
- **EPSS** (0–1) : probabilité d'exploitation dans les 30 prochains jours (FIRST.org), poids 40 %
- **Exploit** (0 ou 1) : présence d'un exploit public sur Exploit-DB, poids 40 %

**Niveaux de priorité :**

| Score  | Niveau    | Couleur |
| ------ | --------- | ------- |
| ≥ 0,70 | 🔴 URGENT | Rouge   |
| ≥ 0,40 | 🟠 ÉLEVÉ  | Orange  |
| ≥ 0,20 | 🟡 MOYEN  | Jaune   |
| < 0,20 | 🟢 FAIBLE | Gris    |

**Exemple concret :**

> CVE-2025-24813 — CVSS=9.8, EPSS=94.2%, Exploit=OUI
> Score = (0.98 × 0.2) + (0.942 × 0.4) + (1 × 0.4) = 0.196 + 0.377 + 0.400 = **0.973 → 🔴 URGENT**

**Implémentation :**

1. Fonction `calcPriority(cve: CveDto)` ajoutée dans `Vulnerabilities.tsx` — calcul 100 % côté frontend, aucune modification backend nécessaire
2. Badge priorité affiché dans chaque ligne du tableau (à côté du badge EXPLOIT et CONFIRMÉ)
3. Ligne « Priorité » ajoutée dans la fiche détail avec le score en pourcentage
4. Le système est **entièrement automatique** : dès que les données CVSS, EPSS et Exploit-DB sont enrichies par le backend, la priorité est calculée instantanément à l'affichage

---

### [Authentification GitHub OAuth] — Sessions utilisateur sécurisées

**Date d'ajout :** 2026

**Problème résolu :** Sans authentification, tous les utilisateurs voient tous les scans de tout le monde. L'application doit isoler les scans et les dépôts par utilisateur.

**Solution — GitHub OAuth 2.0 + JWT :**

```
1. Frontend → GET http://localhost:8080/api/auth/github
2. Backend → redirect GitHub (scopes: repo, user:email)
3. Utilisateur autorise l'application GitHub
4. GitHub → GET /api/auth/github/callback?code=<code_oauth>
5. Backend échange le code contre un token GitHub (POST github.com/login/oauth/access_token)
6. Backend appelle l'API GitHub (/user) pour obtenir le profil
7. Backend génère un JWT signé contenant : login, name, avatar, url, ghToken
8. Backend redirige → http://localhost:3000/auth/callback?token=<jwt>
9. Frontend (AuthCallback.tsx) stocke le JWT dans localStorage (clé: "vulnix_token")
10. Toutes les requêtes suivantes incluent : Authorization: Bearer <jwt>
11. Backend (JwtUtil.extractLogin) extrait le claim "login" du JWT
12. Scans et dépôts sont scopés à l'ownerLogin extrait du JWT
13. `GET /api/auth/me` permet de recharger le profil courant côté frontend
14. `GET /api/auth/github/repos` permet de lister les dépôts GitHub accessibles depuis l'interface
```

**Composants backend :**

- `AuthController.java` : endpoints `/api/auth/github`, `/api/auth/github/callback`, `/api/auth/me`, `/api/auth/github/repos`
- `JwtUtil.java` : méthode `extractLogin(authHeader)` — extrait le claim `login` depuis le JWT Bearer
- `application.properties` : `github.client.id`, `github.client.secret`, `jwt.secret`

**Composants frontend :**

- `Login.tsx` : page de connexion avec bouton GitHub, branding "Vulnix — Security Intelligence Platform" (tagline: "Quantum Observer v1.0")
- `AuthCallback.tsx` : route `/auth/callback` — récupère le `?token=` de l'URL, stocke dans localStorage, redirige vers `/`
- `AuthContext.tsx` : contexte React global — décode le JWT client-side pour extraire le profil `GitHubUser {id, login, name, avatar, url}`, expose `isAuthenticated`, `logout()`

**Note de sécurité :** le claim `ghToken` dans le JWT est un compromis de prototype pour permettre les appels GitHub côté backend sans persistance serveur de session. Pour une version production, ce token devrait être conservé côté serveur ou chiffré dans un stockage dédié.

**Isolation des données :**

- `Repository.ownerLogin` : login GitHub de l'utilisateur qui a créé le dépôt
- `GET /api/scans` : si JWT présent, filtre par `ownerLogin` (les utilisateurs ne voient que leurs scans)
- `GET /api/repositories` : même logique de filtrage

---

### [Scan d'images Docker] — Analyse de conteneurs

**Date d'ajout :** 2026

**Problème résolu :** Les équipes DevOps déploient des conteneurs Docker mais ne scannent pas systématiquement les images avant déploiement. Une image Docker peut contenir des dépendances vulnérables dans sa couche OS ou ses packages applicatifs.

**Solution — Mode `docker-image` :**

**Requête :**

```json
POST /api/scans
{
  "scanMode": "docker-image",
  "dockerImage": "nginx:1.21",
  "containerPort": 80
}
```

**Fonctionnement :**

1. `ScanService.java` détecte `scanMode=docker-image` → `isDockerImage=true`
2. Le `repoUrl` en BDD est stocké sous la forme `docker://nginx:1.21`
3. Le conteneur scanner reçoit les variables d'environnement :
   - `SCAN_MODE=docker-image`
   - `DOCKER_IMAGE=nginx:1.21`
   - `CONTAINER_PORT=80`
4. `scan.sh` branche sur le cas `docker-image` → appelle `run_docker_image_scans.sh`
5. Grype et Trivy scannent l'image Docker directement (pas un repo Git)
6. Les CVEs détectées sont parsées et enrichies identiquement aux scans de repo

**Interface frontend (`Repositories.tsx`) :**

- Sélecteur de mode : Git Repo / Docker Image / DAST / SSL
- En mode Docker Image : champ de saisie de la référence d'image (`docker.io/user/image:latest`)
- Badge violet "Docker Image" dans la liste des dépôts

---

### [Analyse SSL/TLS] — Scanner multi-source de configuration TLS

**Date d'ajout :** 2026

**Problème résolu :** La plupart des applications web exposent une interface HTTPS, mais la configuration TLS est souvent mal sécurisée : protocoles dépréciés (TLS 1.0/1.1), algorithmes faibles (3DES, RC4), vulnérabilités célèbres (Heartbleed, BEAST, POODLE). Ces failles ne sont pas visibles dans les dépendances logicielles — elles nécessitent un audit SSL spécifique.

**Solution — Pipeline SSL multi-source :**

```
Utilisateur saisit un domaine (ex: badssl.com)
     ↓
POST /api/ssl/scan { domain: "badssl.com" }
     ↓
SslController → ScanService (scanMode="ssl-only", repoUrl="ssl://badssl.com")
   ├── déclenche le scanner Kali (pipeline local)
   ├── lance `SslLabsService.analyzeAsync()` en parallèle
   └── lance `CensysSslService.analyzeAsync()` en parallèle
     ↓
Docker scanner (Kali Linux) — outils SSL :
  ├── sslyze      → versions TLS, certificat, vulnérabilités
  ├── sslscan     → ciphers supportés, BEAST, CRIME, POODLE
  ├── testssl.sh  → audit complet avec niveau de risque (LOW/MEDIUM/HIGH)
  ├── nmap        → --script ssl-enum-ciphers
  └── nikto       → en-têtes HTTP de sécurité
     ↓
Résultats fusionnés dans `SslResultDto`
     ↓
GET /api/ssl/scan/{id}/result → JSON structuré + `combinedGrade`
POST /api/ssl/ai-analysis → interprétation Gemini optionnelle
     ↓
SSLAnalysis.tsx → Dashboard visuel (grade local, sources externes, note agrégée, certificat, IA)
```

**Outils SSL du scanner (`scan.sh` mode ssl-only) :**

| Outil      | Rôle                                      | Sortie         |
| ---------- | ----------------------------------------- | -------------- |
| sslyze     | Audit TLS complet (Python)                | `sslyze.json`  |
| sslscan    | Ciphers, protocoles, vulnérabilités       | `sslscan.xml`  |
| testssl.sh | Audit expert avec niveaux LOW/MEDIUM/HIGH | `testssl.json` |
| nmap       | Enum ciphers, négociation TLS             | `nmap-ssl.txt` |
| nikto      | Headers HTTP de sécurité manquants        | `nikto.txt`    |

**Sources complémentaires hors conteneur :**

| Service      | Rôle                                                        | Sortie / canal                   |
| ------------ | ----------------------------------------------------------- | -------------------------------- |
| SSL Labs     | Note externe reconnue, certificat, forward secrecy, warnings | `ssl-labs-result.json`           |
| Censys       | Vue plateforme TLS / certificat / ports ouverts             | `censys-result.json`             |
| Gemini SSL AI | Synthèse et recommandations contextuelles                   | `POST /api/ssl/ai-analysis`      |

**Structure `SslResultDto` — données parsées :**

| Catégorie         | Champs principaux                                                                                                                                                                                                                         |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Données Kali      | `tls10`, `tls11`, `tls12`, `tls13`, `heartbleed`, `sweet32`, `crime`, `poodle`, `beast`, `robot`, `freak`, `logjam`, `rc4`, `drown`                                                   |
| Certificat local  | `certExpired`, `certDaysLeft`, `certIssuer`, `certSubject`, `chainComplete`, `certSignatureAlg`, `certKeySize`, `certNotBefore`, `certNotAfterStr`, `certSerialNumber`, `certEv`, `certWildcard`, `certTransparency`, `certSansCount` |
| Headers sécurité  | `hsts`, `ocspStapling`, `xFrameOptions`, `xContentTypeOptions`, `contentSecurityPolicy`, `referrerPolicy`, `permissionsPolicy`                                                           |
| Sources externes  | blocs `ssllabs*`, `censys*`, `sslyze*`                                                                                                                                                                                                   |
| Agrégation finale | `sourcesReady`, `sourcesTotal`, `combinedGrade`                                                                                                                                                                                          |

**Système de notation — `combinedGrade` calculé côté backend (`SslController`) :**

La note finale n'est plus calculée uniquement dans le frontend. Le backend fusionne les sources disponibles selon les pondérations suivantes :

- pipeline Kali : 30 %
- SSL Labs : 30 %
- Censys : 20 %
- SSLyze : 20 %

Si une des sources prêtes retourne une note `F`, la note agrégée finale est forcée à `F`.

| Score agrégé | Grade |
| ------------ | ----- |
| ≥ 97         | A+    |
| ≥ 85         | A     |
| ≥ 70         | B     |
| ≥ 55         | C     |
| ≥ 40         | D     |
| < 40         | F     |

**Jeux de test recommandés — sous-domaines `badssl.com` :**

Le domaine racine `badssl.com` ne doit pas être pris comme unique référence de démonstration. Pour valider précisément le pipeline, il est préférable d'utiliser les sous-domaines dédiés ci-dessous, chacun ciblant un scénario TLS particulier.

| Domaine de test         | Scénario attendu                          |
| ----------------------- | ----------------------------------------- |
| `expired.badssl.com`    | Certificat expiré                         |
| `self-signed.badssl.com`| Certificat auto-signé                     |
| `3des.badssl.com`       | Chiffrement faible / SWEET32              |
| `tls-v1-0.badssl.com`   | Protocole TLS 1.0 encore activé           |
| `hsts.badssl.com`       | Présence correcte de l'en-tête HSTS       |
| `no-hsts.badssl.com`    | Absence de HSTS                           |

Cette approche rend les démonstrations plus fiables et permet de justifier précisément quel sous-système Vulnix est en train d'être validé.

---

### [DAST — Tests dynamiques] — OWASP ZAP

**Date d'ajout :** Avril 2026

**Problème résolu :** Les tests statiques (SAST) ne peuvent pas détecter les vulnérabilités qui n'apparaissent qu'à l'exécution de l'application : injections SQL via des formulaires web, XSS reflété, CSRF, headers de sécurité manquants (HSTS, CSP, X-Frame-Options), redirections ouvertes, etc.

**Solution — Intégration de OWASP ZAP (Zed Attack Proxy) :**

1. **`Dockerfile`** : ZAP est installé depuis les releases GitHub officiales dans `/opt/zaproxy/`, avec le wrapper Python `zaproxy` pour `zap-baseline.py`
2. **`run_dast_scans.sh`** : nouveau script déclenché lorsque `SCAN_MODE=dast` ou que `DAST_TARGET_URL` est défini. Utilise `zap-baseline.py` (scan passif + actif basique, safe pour toute application) avec un timeout de 10 minutes. Produit `zap.json`
3. **`ScanRequest.java`** : nouveau champ `dastTargetUrl` — l'URL de l'application déployée à scanner
4. **`ScanService.java`** : transmet `DAST_TARGET_URL` au conteneur Docker via variable d'environnement
5. **`ResultParserService.java`** : nouveau parser `parseZap()` — lit `zap.json`, mappe chaque alerte ZAP vers un `CveEntry` avec :
   - `cveId = "ZAP-" + pluginId` (identifiant unique ZAP)
   - `packageName` = nom de l'alerte (ex: "SQL Injection", "Missing X-Frame-Options Header")
   - `severity` selon `riskdesc` (High→HIGH, Medium→MEDIUM, Low→LOW)
   - `filePath` = URL affectée (instance URL)
   - `source = "zaproxy"`
6. **`Repositories.tsx`** : mode **"DAST (ZAP)"** ajouté au sélecteur. Un champ URL orange apparaît automatiquement quand ce mode est sélectionné. Les modes SSL/TLS only et Secrets only ont été retirés
7. **`api.ts`** : interface `ScanRequest` mise à jour avec `dastTargetUrl?: string`

**Types de vulnérabilités détectées par ZAP :**

| Alerte ZAP                       | Catégorie                           |
| -------------------------------- | ----------------------------------- |
| SQL Injection                    | Injection (OWASP A03)               |
| Cross Site Scripting (Reflected) | XSS (OWASP A03)                     |
| Cross-Site Request Forgery       | CSRF (OWASP A01)                    |
| Missing HSTS Header              | Mauvaise configuration (OWASP A05)  |
| Missing Content Security Policy  | Mauvaise configuration (OWASP A05)  |
| X-Frame-Options Header Not Set   | Clickjacking (OWASP A05)            |
| Server Leaks Information         | Divulgation d'info (OWASP A09)      |
| Open Redirect                    | Redirection non validée (OWASP A01) |

**Comparaison SAST vs DAST :**

| Critère           | SAST (Semgrep, Grype...)    | DAST (OWASP ZAP)                             |
| ----------------- | --------------------------- | -------------------------------------------- |
| Quand ?           | Sans exécuter l'app         | Application déployée et en cours d'exécution |
| Ce qu'il voit     | Code source, dépendances    | Comportement réel de l'application           |
| Faux positifs     | Plus élevé                  | Plus fiable (testés en réel)                 |
| Failles détectées | CVEs de libs, secrets, code | XSS, SQLi, CSRF, headers, redirections       |

**Impact :** Vulnix couvre maintenant les deux axes de sécurité : analyse statique (SAST) et tests dynamiques (DAST), offrant une couverture complète de type DevSecOps.

---

### [Export PDF] — Rapport de sécurité exportable

**Date d'ajout :** Avril 2026

**Problème résolu :** Les résultats de scan étaient uniquement consultables dans l'interface web. Pour partager les vulnérabilités avec un client, une équipe ou un auditeur, il fallait faire des copies manuelles ou des captures d'écran.

**Solution — Génération PDF côté client avec jsPDF :**

1. **Bibliothèques** : `jspdf` + `jspdf-autotable` installées dans le frontend (aucune dépendance backend)
2. **Bouton « Export PDF »** ajouté dans la barre de filtres de la page Vulnerabilities — à droite des boutons de sévérité (CRITICAL / HIGH / MEDIUM / LOW). Il est désactivé si aucune vulnérabilité n'est visible
3. **La fonction `exportPdf()`** génère un PDF A4 paysage contenant :

**Structure du PDF généré :**

| Élément       | Contenu                                                                              |
| ------------- | ------------------------------------------------------------------------------------ |
| En-tête       | Nom du dépôt, numéro de scan, date et heure de génération                            |
| Résumé coloré | 5 pastilles : TOTAL / CRITICAL (rouge) / HIGH (orange) / MEDIUM (jaune) / LOW (gris) |
| Tableau       | CVE/ID + badges, Severity, CVSS, EPSS, Package, Priority, Source, Description        |
| Pied de page  | « Vulnix Security Scanner — repo — Page X / Y » centré                               |

**Badges dans le PDF :**

Les badges de sécurité sont dessinés directement sous le CVE ID dans la cellule (même principe que l'interface web) grâce au hook `didDrawCell` de jspdf-autotable :

| Badge           | Couleur | Condition                                                         |
| --------------- | ------- | ----------------------------------------------------------------- |
| 🟠 **CISA KEV** | Orange  | CVE répertoriée dans le catalogue CISA KEV (exploitée activement) |
| 🔴 **EXPLOIT**  | Rouge   | Exploit public disponible sur Exploit-DB                          |
| 🟢 **CONFIRMÉ** | Vert    | CVE détectée par ≥ 2 outils indépendants                          |

**Filtrage intelligent :** Le PDF exporte les vulnérabilités **telles que filtrées** dans l'interface. Si l'utilisateur filtre par CRITICAL avant d'exporter, seules les CVEs critiques apparaissent dans le PDF.

**Implémentation :**

- Import : `import jsPDF from 'jspdf'; import autoTable from 'jspdf-autotable';`
- Colonnes colorisées : severity et priority avec `didParseCell`
- Badges : dessinés manuellement avec `didDrawCell` (après le fond de cellule) en `roundedRect` + texte centré
- File name : `vulnix-report-{repo}-scan{id}.pdf`

**Valeur ajoutée :** Le rapport PDF peut être directement joint à un email, un ticket Jira, ou un rapport d'audit de sécurité. Il conserve toute l'information de priorisation (CVSS, EPSS, badges, niveau de priorité) de façon structurée et imprimable.

---

### [EPSS] — Probabilité d'exploitation en temps réel

**Date d'ajout :** Avril 2026

**Problème résolu :** Le score CVSS mesure la gravité théorique d'une vulnérabilité, mais ne dit rien sur la probabilité qu'elle soit réellement exploitée dans les 30 prochains jours. Deux CVEs avec CVSS 9.8 peuvent avoir un risque réel très différent.

**Solution :** Intégration du score **EPSS** (Exploit Prediction Scoring System), produit par **FIRST.org** (Forum of Incident Response and Security Teams).

- **Source :** API publique FIRST.org — `https://api.first.org/data/v1/epss` (route **v1**, non v1.0)
- **Format :** Score de 0 à 1 (ex: 0.942 = 94,2 % de probabilité d'exploitation dans les 30 prochains jours) + percentile (rang parmi toutes les CVEs connues)
- **Envoi par batch** : les CVEs sont envoyées en lots de 100 pour éviter les timeouts
- **Mise à jour :** refresh automatique toutes les **48 heures** (`@Scheduled`)
- **Champs BDD :** `epss_score (double)` **et** `epss_percentile (double)` ajoutés à `cve_entries`
- **Frontend :** Colonne EPSS affichée dans le tableau avec pourcentage colorisé (rouge si > 50 %)
- **Intégration dans le score composite** : poids de 40 % dans la formule de priorité automatique

**Valeur ajoutée :** Une CVE CVSS 7.5 avec EPSS 90% est plus urgente qu'une CVE CVSS 9.8 avec EPSS 0.1%. L'EPSS transforme la priorisation de théorique en probabiliste et factuelle.

---

### [CISA KEV] — Catalogue des vulnérabilités activement exploitées

**Date d'ajout :** Avril 2026

**Problème résolu :** Parmi les milliers de CVEs détectées, certaines sont **activement exploitées en ce moment par des acteurs malveillants** selon les agences gouvernementales américaines. Ces CVEs doivent être traitées en priorité absolue, indépendamment de leur score CVSS.

**Solution :** Intégration du **CISA KEV** (Known Exploited Vulnerabilities Catalog), maintenu par la Cybersecurity and Infrastructure Security Agency (CISA).

1. **Téléchargement automatique** : le backend charge le catalogue JSON officiel au démarrage depuis `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
2. **Refresh périodique** : `@Scheduled` toutes les 24 heures (le catalogue est mis à jour quotidiennement par CISA)
3. **Indexation en mémoire** : `Map<String, KevEntry>` des CVE-IDs répertoriés, où `KevEntry` est un `record(dateAdded, ransomware)` interne
4. **Champs BDD** : trois champs ajoutés à `cve_entries` :
   - `kev_listed (boolean)` : CVE dans le catalogue KEV
   - `kev_date_added (date)` : date d'entrée dans le catalogue KEV
   - `kev_ransomware (boolean)` : CVE liée à un ransomware (flag CISA)
5. **Frontend** : badge orange **"CISA KEV"** affiché sur les CVEs concernées, dans le tableau et dans le PDF exporté

**Impact :** Une CVE CISA KEV signifie que des pirates utilisent actuellement cette faille dans des attaques réelles documentées. C'est le signal d'alerte le plus élevé possible — au-dessus même d'un exploit Exploit-DB (qui peut être théorique).

---

### [Auto-Fix Programmatique] — Correction automatique des dépendances vulnérables

**Date d'ajout :** Avril 2026

**Problème résolu :** Une fois une CVE identifiée, le processus de correction reste manuel : chercher quelle version corriger, modifier le fichier de dépendances, commiter. Sur un projet avec des dizaines de CVEs, c'est répétitif, lent, et source d'erreurs humaines.

**Solution — moteur de correction programmatique sans IA :**

Le service `AutoFixService.java` implémente un moteur de correction entièrement **déterministe, basé sur l'analyse syntaxique du fichier de dépendances**. Aucune IA externe n'est utilisée — la correction est calculée et appliquée par l'application elle-même.

#### Flux de correction

```
1. Utilisateur clique "Corriger" sur une CVE dans l'interface
2. Frontend → POST /api/autofix/preview { repoFullName, packageName, currentVersion, fixedVersion, filePath }
3. Backend :
   a. discoverManifestPath() — localise le vrai fichier de dépendances dans le repo GitHub
   b. fetchFileFromGitHub() — télécharge le contenu (API GitHub)
   c. tryProgrammaticFix() — tente la correction par analyse syntaxique
   d. Si package.json → fixPackageLockJson() patche aussi package-lock.json
4. Backend → retourne { originalLines, fixedLines, filePath, sha, lockFilePath? }
5. Frontend affiche un diff côte-à-côte (ligne rouge = supprimée, ligne verte = ajoutée)
6. Utilisateur valide → POST /api/autofix/apply
7. Backend commit le fichier corrigé sur GitHub (API GitHub PUT /contents)
8. Si lock file → deuxième commit automatique pour package-lock.json
```

#### Fichiers de dépendances supportés

| Fichier                | Écosystème   | Méthode de correction                                                                                                |
| ---------------------- | ------------ | -------------------------------------------------------------------------------------------------------------------- |
| `pom.xml`              | Java / Maven | Localise le bloc `<dependency>` par `<artifactId>` et met à jour `<version>`                                         |
| `pom.xml` (transitive) | Java / Maven | Si la dep n'est pas déclarée explicitement → ajoute un bloc `<dependencyManagement>` pour forcer la version corrigée |
| `package.json`         | Node.js      | Met à jour la version dans `dependencies` ou `devDependencies` (compatible `^`, `~`, exact)                          |
| `requirements.txt`     | Python       | Met à jour la ligne `package==version` avec la version corrigée                                                      |

#### Détection automatique du fichier cible

La méthode `discoverManifestPath()` évite les erreurs en :

1. Analysant le `filePath` fourni par Grype/Trivy (ex: `Frontend/package-lock.json`)
2. Déduisant le répertoire préféré (`Frontend/`)
3. Cherchant le manifest correspondant via l'API GitHub Tree (`Frontend/package.json`)
4. Évitant de commiter dans le mauvais écosystème (ex: ne jamais mettre une dépendance npm dans `pom.xml`)

La méthode `inferManifestFilename()` détermine le type de fichier à partir du nom du package :

- Package avec `:` (ex: `org.springframework:spring-core`) → `pom.xml`
- Package connu Java (logback, spring, log4j, jackson...) → `pom.xml`
- Packages inconnus ou npm → `package.json`
- Packages Python (django, flask, requests...) → `requirements.txt`

#### Diff côte-à-côte (algorithme LCS)

Un algorithme **LCS (Longest Common Subsequence)** calcule les différences entre le fichier original et le fichier corrigé :

- **Lignes rouges** : supprimées (ancienne version vulnérable)
- **Lignes vertes** : ajoutées (nouvelle version corrigée)
- **Lignes blanches** : inchangées (contexte)

Cela permet à l'utilisateur de **vérifier exactement ce qui va être modifié** avant de valider le commit.

#### Sélection intelligente de la version de correction

Un algorithme de **sélection de version** (`pickBestFixVersion`) détermine automatiquement quelle version appliquer :

1. Parmi toutes les versions disponibles sur le registre (Maven Central / npm registry)
2. Filtre les versions de la **même série majeure** que la version actuelle (ex: si actuellement sur `1.x`, propose une `1.y` corrigée)
3. Sélectionne la version la plus récente de cette série sans montée de version majeure (évite les breaking changes)
4. Si aucune version mineure n'est disponible, remonte à une version majeure supérieure

**Valeur ajoutée :** La correction est instantanée, vérifiable ligne par ligne, et ne nécessite aucune intervention manuelle sur les fichiers. Le développeur garde le contrôle via le diff avant de valider.

---

### [Correctif groupé] — Un seul commit pour plusieurs CVEs

**Date d'ajout :** Avril 2026

**Problème résolu :** Un même package vulnérable peut générer plusieurs CVEs (ex: `axios 0.21.1` peut avoir CVE-2021-3749, CVE-2022-0155, CVE-2023-45857 simultanément). Sans groupement, l'utilisateur devrait corriger chaque CVE séparément, ce qui provoquerait des conflits de commit ou des mises à jour redondantes.

**Solution — Groupement automatique des CVEs par package :**

Le frontend `Vulnerabilities.tsx` calcule des **groupes de CVEs** via un `useMemo` :

```typescript
const fixGroups = React.useMemo(() => {
  const groups = new Map<string, CveDto[]>();
  cves.forEach((cve) => {
    const key = `${cve.packageName}|${cve.packageVersion}|${cve.filePath ?? ""}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(cve);
  });
  return groups;
}, [cves]);
```

**Comportement :**

- Lorsqu'un utilisateur clique sur une CVE appartenant à un groupe de N CVEs, le bouton affiche : **"Corriger N CVEs avec ce fix"**
- La version de correction appliquée est la **version la plus haute** parmi toutes les versions suggérées du groupe (logique "max fix")
- Le message de commit liste toutes les CVEs corrigées : `fix: auto-fix CVE-2021-3749, CVE-2022-0155, CVE-2023-45857 in axios (0.21.1 → 1.8.4)`
- Après le commit, **toutes les CVEs du groupe** sont marquées comme corrigées simultanément

**Bannière de groupe** dans l'interface :

Lorsqu'une CVE appartient à un groupe, une bannière teal s'affiche dans la fiche de correction :

> _Correctif groupé — 3 CVEs résolus par cette mise à jour : CVE-2021-3749, CVE-2022-0155, CVE-2023-45857_

**Valeur ajoutée :** Un seul commit corrige plusieurs CVEs à la fois, évite les conflits Git, et réduit le nombre d'actions nécessaires pour assainir un projet.

---

### [Patch du lock file] — Cohérence package.json / package-lock.json

**Date d'ajout :** Avril 2026

**Problème résolu :** Mettre à jour `package.json` ne suffit pas pour corriger une CVE détectée par les scanners. Les outils (Grype, Trivy, npm audit) lisent `package-lock.json` qui contient les **versions exactes et pinnées** de chaque dépendance. Si `package-lock.json` n'est pas mis à jour, le scan suivant détecte encore la même CVE malgré la correction dans `package.json`.

**Solution — Patch automatique du lock file :**

Après avoir corrigé `package.json`, l'`AutoFixService` :

1. Télécharge automatiquement `package-lock.json` du même répertoire via l'API GitHub
2. Appelle `fixPackageLockJson()` — méthode qui supporte :
   - **Format npm v1** : cherche `"axios": {` puis met à jour `"version": "..."`
   - **Format npm v2/v3** : cherche `"node_modules/axios": {` puis met à jour `"version": "..."`
3. Si le patch réussit, retourne `lockFilePath`, `lockFileSha`, `lockFileContent` dans la réponse preview
4. Le frontend affiche une bannière teal dans la fenêtre de diff : _"Lock file automatiquement patché : Frontend/package-lock.json sera aussi mis à jour"_
5. Lors de `applyFix`, deux commits sont effectués :
   - **Commit 1** : `package.json` avec la mise à jour de version
   - **Commit 2** : `package-lock.json` avec `chore: update package-lock.json after dependency fix`

**Valeur ajoutée :** Le scan suivant ne détecte plus la CVE corrigée car `package-lock.json` — qui est la source de vérité pour les scanners — a été mis à jour en même temps que `package.json`.

---

### [Badge "CORRIGÉ" et état "Déjà corrigé"] — Suivi des corrections appliquées

**Date d'ajout :** Avril 2026

**Problème résolu :** Après avoir appliqué un correctif, le bouton de correction restait affiché, donnant l'impression que rien n'avait été fait. L'utilisateur pouvait accidentellement re-commiter la même correction ou ne pas savoir quelles CVEs avaient déjà été traitées.

**Solution :**

1. **État `fixedCveIds`** — un `Set<number>` en mémoire côté React qui accumule les IDs de toutes les CVEs corrigées durant la session
2. **Badge "CORRIGÉ"** dans le tableau — badge teal apparu sur chaque ligne de CVE dont l'ID est dans `fixedCveIds`, visible sans avoir à ouvrir la fiche détail
3. **État "Déjà corrigé"** dans la fiche latérale — lorsqu'on clique sur une CVE déjà corrigée :
   - Le bouton "Corriger" est remplacé par un encadré teal "✓ X CVEs déjà corrigés dans cette session"
   - Un lien **"Voir le commit sur GitHub"** pointe directement vers le commit créé

**Comportement sur un groupe :** Quand un correctif groupé est appliqué (N CVEs), **tous les membres du groupe** sont ajoutés à `fixedCveIds` simultanément — le badge "CORRIGÉ" apparaît sur toutes les lignes du groupe.

**Valeur ajoutée :** L'utilisateur voit en un coup d'œil quelles CVEs ont déjà été traitées dans la session actuelle, évite les doubles corrections, et peut naviguer directement vers le commit GitHub correspondant.

---

## 12. Outils et APIs utilisés

| Outil / API            | Usage                                          | Lien                                                 |
| ---------------------- | ---------------------------------------------- | ---------------------------------------------------- |
| Grype                  | Scan CVE des dépendances                       | https://github.com/anchore/grype                     |
| Trivy                  | Scan CVE + IaC + licences                      | https://github.com/aquasecurity/trivy                |
| Semgrep                | Analyse statique de code (SAST)                | https://semgrep.dev                                  |
| Gitleaks               | Détection de secrets exposés                   | https://github.com/gitleaks/gitleaks                 |
| OSV-Scanner            | CVEs multi-langages (Google)                   | https://github.com/google/osv-scanner                |
| OWASP Dependency-Check | CVEs Java/Maven                                | https://owasp.org/www-project-dependency-check       |
| OWASP ZAP              | Tests dynamiques DAST                          | https://www.zaproxy.org                              |
| sslyze                 | Audit TLS (protocoles, certificat, ciphers)    | https://github.com/nabla-c0d3/sslyze                 |
| sslscan                | Scan SSL/TLS (ciphers, vulnérabilités)         | https://github.com/rbsec/sslscan                     |
| testssl.sh             | Audit TLS expert (niveaux LOW/MEDIUM/HIGH)     | https://testssl.sh                                   |
| NVD API                | Descriptions et scores CVE                     | https://nvd.nist.gov/developers                      |
| GitHub Advisory API    | CVEs des packages GitHub                       | https://api.github.com/advisories                    |
| FIRST.org EPSS API     | Scores EPSS (probabilité d'exploitation)       | https://api.first.org/data/v1/epss                   |
| CISA KEV               | Catalogue vulnérabilités activement exploitées | https://www.cisa.gov/known-exploited-vulnerabilities |
| Exploit-DB             | Base d'exploits publics                        | https://www.exploit-db.com                           |
| Google Gemini AI       | Auto-fix fallback (gemini-flash-latest)        | https://aistudio.google.com                          |
| GitHub OAuth API       | Authentification OAuth 2.0                     | https://docs.github.com/en/apps/oauth-apps           |
| GitHub Contents API    | Lecture/commit de fichiers (auto-fix)          | https://docs.github.com/en/rest/repos/contents       |
| MyMemory API           | Traduction EN→FR des descriptions CVE          | https://mymemory.translated.net                      |
| Spring Boot            | Framework backend Java                         | https://spring.io/projects/spring-boot               |
| React                  | Framework frontend                             | https://react.dev                                    |
| Tailwind CSS           | Framework CSS utilitaire                       | https://tailwindcss.com                              |
| PostgreSQL             | Base de données relationnelle                  | https://www.postgresql.org                           |
| Docker                 | Conteneurisation du scanner                    | https://www.docker.com                               |
| Kali Linux             | Distribution de sécurité (image scanner)       | https://www.kali.org                                 |
| jsPDF + autotable      | Export PDF côté client (React)                 | https://github.com/parallax/jsPDF                    |
