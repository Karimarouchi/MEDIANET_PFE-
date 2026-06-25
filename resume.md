# 📋 RÉSUMÉ COMPLET - APPLICATION VULNIX

## 📌 Vue d'ensemble générale

**Vulnix** est une plateforme d'analyse de sécurité automatisée (DevSecOps) qui permet aux développeurs et ingénieurs sécurité de:

- Soumettre des URL de dépôts Git (public/privé)
- Lancer des scans de sécurité complets
- Analyser des domaines SSL/TLS
- Configurer et exécuter des pipelines CI/CD
- Consulter les résultats via une interface web moderne
- Corriger automatiquement les vulnérabilités

**Stack Technologique:**

- **Frontend:** React 18.2 + TypeScript 4.9.5 + Tailwind CSS 3.4
- **Backend:** Spring Boot 3.2.5 + Java 17
- **Base de données:** PostgreSQL 15
- **Scanner:** Docker + Kali Linux
- **Authentification:** GitHub OAuth 2.0 + JWT
- **IA:** Google Gemini Flash 1.5

---

## 🔧 BACKEND ROUTES & APIS (Spring Boot)

### 1️⃣ AUTHENTIFICATION - `/api/auth`

#### Routes d'authentification GitHub:

- **GET** `/api/auth/github` → Redirection OAuth GitHub
- **GET** `/api/auth/github/callback` → Callback après login GitHub
- **GET** `/api/auth/github/link-url` → URL pour lier compte GitHub
- **POST** `/api/auth/login` → Login avec email/password

#### Routes d'authentification GitLab:

- **GET** `/api/auth/gitlab/link-url` → URL pour lier compte GitLab
- **GET** `/api/auth/gitlab/callback` → Callback après link GitLab

**Services associés:**

- `UserService` → Gestion des utilisateurs
- `GitLabService` → Intégration GitLab
- `TokenEncryptionService` → Chiffrement des tokens
- `AccessRoleService` → Gestion des rôles

---

### 2️⃣ SCANS DE SÉCURITÉ - `/api/scans`

#### Gestion des scans:

- **POST** `/api/scans` → Lancer un nouveau scan (repo Git, Docker, etc.)
- **GET** `/api/scans` → Lister tous les scans de l'utilisateur
- **GET** `/api/scans/{scanId}` → Détails d'un scan spécifique
- **POST** `/api/scans/{scanId}/stop` → Arrêter un scan en cours
- **DELETE** `/api/scans/{scanId}` → Supprimer un scan

#### Stream de logs (SSE - Server-Sent Events):

- **GET** `/api/scans/{scanId}/logs` (SSE) → Stream de logs en temps réel

#### Résultats des scans:

- **GET** `/api/scans/{scanId}/cves` → Liste des CVEs trouvés
- **GET** `/api/scans/{scanId}/secrets` → Liste des secrets exposés
- **GET** `/api/scans/{scanId}/sast` → Résultats SAST (analyse statique)
- **GET** `/api/scans/{scanId}/sbom` → Software Bill of Materials
- **GET** `/api/scans/{scanId}/ai-summary` → Résumé exécutif par Gemini AI

#### Dépôts:

- **GET** `/api/repositories` → Tous les dépôts scannés
- **GET** `/api/repositories/{repoId}` → Détails d'un dépôt
- **GET** `/api/repositories/{repoId}/scan-history` → Historique de scans

**Services associés:**

- `ScanService` → Orchestration des scans
- `NvdEnrichmentService` → Enrichissement depuis NVD (National Vulnerability Database)
- `ExploitDbService` → Données d'exploits publics
- `CisaKevService` → CISA Known Exploited Vulnerabilities
- `EpssService` → EPSS (Exploit Prediction Scoring System)
- `GeminiSummaryService` → Génération de résumés IA
- `ComplianceService` → Vérifications de conformité

---

### 3️⃣ ANALYSE SSL/TLS - `/api/ssl`

#### Scans SSL:

- **POST** `/api/ssl/scan` → Lancer un scan SSL/TLS pour un domaine
- **GET** `/api/ssl/scan/{scanId}/logs` (SSE) → Logs en temps réel
- **GET** `/api/ssl/scan/{scanId}/result` → Résultat du scan SSL (grade, certificat, vulnérabilités)

**Détails du résultat SSL:**

- Grade SSL (A+, A, B, C, F, etc.)
- État du certificat (expiration, chaîne complète, validité)
- Protocoles TLS supportés (TLS 1.0, 1.1, 1.2, 1.3)
- Vulnérabilités SSL (Heartbleed, SWEET32, CRIME, POODLE, BEAST, ROBOT, Logjam, FREAK, DROWN, etc.)
- Jours avant expiration du certificat
- Algorithme de signature
- Taille de clé
- Détails du certificat (issuer, subject, SANs)

**Services associés:**

- `SslLabsService` → Analyse SSL Labs API
- `CensysSslService` → Données Censys
- `SslAiService` → Analyse IA des résultats SSL

---

### 4️⃣ CORRECTION AUTOMATIQUE - `/api/autofix`

- **POST** `/api/autofix/scan/{scanId}` → Générer un commit GitHub pour corriger les dépendances vulnérables
- **GET** `/api/autofix/scan/{scanId}/status` → Statut de la correction automatique

**Services associés:**

- `AutoFixService` → Génération de corrections automatiques

---

### 5️⃣ PIPELINES CI/CD - `/api/pipelines`

#### Gestion des pipelines:

- **GET** `/api/pipelines` → Lister tous les pipelines
- **GET** `/api/pipelines/{id}` → Détails d'un pipeline
- **POST** `/api/pipelines` → Créer un nouveau pipeline
- **PUT** `/api/pipelines/{id}` → Modifier un pipeline
- **DELETE** `/api/pipelines/{id}` → Supprimer un pipeline

#### Exécution des pipelines:

- **POST** `/api/pipelines/{id}/run` → Exécuter un pipeline
- **GET** `/api/pipelines/{id}/runs` → Historique des exécutions
- **GET** `/api/pipelines/runs/{runId}` → Détails d'une exécution
- **GET** `/api/pipelines/runs/{runId}/logs` (SSE) → Logs en temps réel

#### Présets de pipelines:

- **GET** `/api/pipelines/presets/monolith-ecommerce` → Preset pour applications monolithiques
- **GET** `/api/pipelines/docker-hub-credential` → Récupérer les credentials Docker Hub
- **PUT** `/api/pipelines/docker-hub-credential` → Sauvegarder les credentials Docker Hub

**Services associés:**

- `PipelineService` → Gestion des pipelines
- `PipelineEventStreamService` → Stream d'événements des pipelines

---

### 6️⃣ CONFIGURATION DE SERVEURS - `/api/servers`

#### Gestion des serveurs:

- **GET** `/api/servers` → Lister tous les serveurs configurés
- **POST** `/api/servers` → Ajouter un nouveau serveur
- **GET** `/api/servers/{id}` → Détails d'un serveur
- **PUT** `/api/servers/{id}` → Modifier un serveur
- **DELETE** `/api/servers/{id}` → Supprimer un serveur

#### Scan de serveurs:

- **POST** `/api/servers/{id}/live` → Récupérer l'état en temps réel du serveur
- **POST** `/api/servers/{id}/scan` → Lancer un scan de hardening du serveur
- **GET** `/api/servers/{id}/findings` → Résultats de hardening trouvés

**Services associés:**

- `ServerConfigService` → Gestion des configurations de serveurs
- `SshServerScanner` → Scanner SSH pour serveurs
- `SshCommandExecutor` → Exécution de commandes SSH

---

### 7️⃣ GESTION DES UTILISATEURS - `/api/users`

- **GET** `/api/users/{id}` → Profil utilisateur
- **PUT** `/api/users/{id}` → Modifier profil
- **GET** `/api/users/me` → Profil de l'utilisateur courant

**Services associés:**

- `UserService` → Gestion des utilisateurs

---

### 8️⃣ GESTION DES CLIENTS - `/api/clients`

- **GET** `/api/clients` → Lister tous les clients (admin only)
- **POST** `/api/clients` → Créer un client
- **GET** `/api/clients/{id}` → Détails d'un client
- **PUT** `/api/clients/{id}` → Modifier un client
- **DELETE** `/api/clients/{id}` → Supprimer un client

**Services associés:**

- `ClientService` → Gestion des clients

---

### 9️⃣ GESTION DES RÔLES D'ACCÈS - `/api/access-roles`

- **GET** `/api/access-roles` → Lister tous les rôles (admin only)
- **POST** `/api/access-roles` → Créer un rôle
- **GET** `/api/access-roles/{id}` → Détails d'un rôle
- **PUT** `/api/access-roles/{id}` → Modifier un rôle
- **DELETE** `/api/access-roles/{id}` → Supprimer un rôle

**Services associés:**

- `AccessRoleService` → Gestion des permissions

---

## 🎨 FRONTEND PAGES & FONCTIONNALITÉS (React)

### Pages principales:

1. **Login.tsx** → Page de connexion GitHub/Email
2. **AuthCallback.tsx** → Callback après authentification OAuth
3. **Dashboard.tsx** → Tableau de bord principal avec résumé
4. **Profile.tsx** → Profil utilisateur + lien des comptes externes
5. **Repositories.tsx** → Liste des dépôts scannés
6. **Scans.tsx** → Liste et gestion des scans de sécurité
7. **Vulnerabilities.tsx** → Vue détaillée des CVEs par scan
8. **SSLAnalysis.tsx** → Analyse SSL/TLS des domaines
9. **ServerConfig.tsx** → Gestion des serveurs
10. **ServerConfigDetail.tsx** → Détails et scan d'un serveur
11. **Pipeline.tsx** → Vue générale des pipelines
12. **PipelineFormPage.tsx** → Formulaire de création/modification de pipeline
13. **PipelinePage.tsx** → Détails d'un pipeline
14. **PipelineRunInspectorPage.tsx** → Inspection détaillée d'une exécution
15. **AdminPanel.tsx** → Panneau d'administration (gestion des utilisateurs, rôles, clients)
16. **ClientDetail.tsx** → Détails d'un client

---

## 📊 DÉTAILS DES SCANS DE SÉCURITÉ

### Modes de scan:

1. **Mode auto (complet)** → Tous les outils (DAST, SAST, dépendances, secrets, SSL)
2. **Mode ssl-only** → Scan SSL/TLS uniquement

### Types de vulnérabilités détectées:

- **CVE (Common Vulnerabilities & Exposures)** → Vulnérabilités de dépendances
- **Secrets exposés** → Clés API, tokens, credentials (via Gitleaks)
- **SAST (Static Application Security Testing)** → Failles de code (via Semgrep)
- **Secrets exposure** → Credentials non protégés
- **SSL/TLS issues** → Certificats expirés, protocoles faibles, vulnérabilités cryptographiques

### Enrichissements de données:

- **NVD (National Vulnerability Database)** → Descriptions complètes, CVSS scores
- **Exploit-DB** → Exploits publics disponibles
- **CISA KEV** → Vulnérabilités en cours d'exploitation
- **EPSS** → Probabilité d'exploitation
- **Gemini AI** → Résumé exécutif automatisé
- **GitHub Advisory** → Avis de sécurité GitHub

---

## 🛠️ SERVICES BACKEND PRINCIPAUX

### Services de scanning:

- `ScanService` → Orchestration complète
- `ResultParserService` → Parsing des résultats

### Services d'enrichissement CVE:

- `NvdEnrichmentService` → Données NVD
- `EpssService` → Scores EPSS
- `CisaKevService` → CISA KEV data
- `ExploitDbService` → Exploit-DB data
- `GeminiSummaryService` → Résumés IA

### Services SSL:

- `SslLabsService` → Analyse SSL Labs
- `CensysSslService` → Données Censys
- `SslAiService` → Analyse IA SSL

### Services infrastructure:

- `ServerConfigService` → Configuration de serveurs
- `SshServerScanner` → Scan SSH
- `SshCommandExecutor` → Exécution SSH

### Services pipelines:

- `PipelineService` → Gestion des pipelines
- `PipelineEventStreamService` → Stream d'événements
- `PipelinePresetService` → Presets de pipelines

### Services sécurité:

- `AutoFixService` → Correction automatique
- `AccessRoleService` → Gestion des rôles

### Services utilitaires:

- `UserService` → Gestion utilisateurs
- `ClientService` → Gestion clients
- `TokenEncryptionService` → Chiffrement des tokens
- `GitLabService` → Intégration GitLab
- `TranslationService` → Traductions

---

## 📁 STRUCTURE DE BASE DE DONNÉES

### Entités principales (PostgreSQL):

1. **User** → Utilisateurs de la plateforme
2. **Repository** → Dépôts Git scannés
3. **ScanResult** → Résultats des scans
4. **CveEntry** → Entrées CVE enrichies
5. **SecretFinding** → Secrets trouvés
6. **SastFinding** → Résultats SAST
7. **SslResult** → Résultats SSL/TLS
8. **Pipeline** → Définitions de pipelines
9. **PipelineRun** → Exécutions de pipelines
10. **ServerNode** → Configurations de serveurs
11. **Client** → Clients/organisations
12. **AccessRole** → Rôles d'accès et permissions

---

## 🔐 SÉCURITÉ & AUTHENTIFICATION

- **OAuth 2.0** → GitHub et GitLab pour authentification
- **JWT (JJWT)** → Tokens sécurisés avec signature HS256
- **CORS** → Contrôle d'accès cross-origin
- **Authorization Header** → Validation sur chaque requête
- **Token Encryption** → Chiffrement des credentials externes
- **Role-Based Access Control** → Gestion granulaire des permissions

---

## 📈 AUTRES FONCTIONNALITÉS CLÉS

1. **Export PDF** → Export des résultats de scan en PDF
2. **SBOM (Software Bill of Materials)** → Inventaire complet des dépendances
3. **Compliance Checks** → Vérifications de conformité
4. **Real-time Logs (SSE)** → Stream de logs en temps réel
5. **Auto-Fix via GitHub Commits** → Correction automatique des dépendances
6. **Multi-source SSL Analysis** → Agrégation Kali + SSL Labs + Censys + SSLyze
7. **Docker Support** → Scan d'images Docker
8. **DAST (Dynamic Analysis)** → Tests de sécurité dynamiques
9. **CI/CD Integration** → Pipelines CI/CD customisables
10. **Server Hardening Checks** → Scan de configuration de serveurs

---

## 🎯 FLUX UTILISATEUR PRINCIPAL

```
1. Utilisateur se connecte via GitHub/Email
   ↓
2. Authentification → JWT token généré
   ↓
3. Accès au Dashboard
   ↓
4. Soumet URL de dépôt → Crée un ScanRequest
   ↓
5. Backend lance scan Docker (Kali Linux)
   ↓
6. Outils exécutés: Grype, Trivy, Semgrep, Gitleaks, OWASP ZAP, sslyze
   ↓
7. Résultats parsés et enrichis (NVD, EPSS, CISA KEV, Exploit-DB)
   ↓
8. Résumé IA généré par Gemini
   ↓
9. Utilisateur consulte les CVEs, secrets, SAST findings
   ↓
10. Option: Générer un commit GitHub pour auto-fix
```

---

## 🚀 MODE SSL-ONLY FLOW

```
1. Utilisateur entre un domaine
   ↓
2. Scan SSL lancé (scan-only mode)
   ↓
3. Trois sources en parallèle:
   - Kali Linux (sslyze)
   - SSL Labs API
   - Censys API
   ↓
4. Résultats agrégés
   ↓
5. IA analyse et génère recommendations
   ↓
6. Grade SSL affiché (A+, A, B, C, F, etc.)
```

---

## 📝 NOTES IMPORTANTES

- **Authentification requise** pour toutes les routes (sauf callback)
- **Authorization Header:** `Authorization: Bearer <JWT_TOKEN>`
- **SSE Logs:** Token peut être passé en query param pour les connexions sans header
- **Multi-tenant:** Chaque utilisateur voit ses propres données
- **Role-based access:** ADMIN, EMPLOYEE, CLIENT, etc.
- **Real-time updates:** WebSocket/SSE pour logs et événements pipelines

---

## 🔧 CONFIGURATION REQUISE

### Variables d'environnement backend:

- `github.client.id` → ID client GitHub OAuth
- `github.client.secret` → Secret client GitHub OAuth
- `github.oauth.redirect-uri` → URI de redirection
- `github.oauth.frontend-url` → URL du frontend
- `DATABASE_URL` → URL PostgreSQL
- `GEMINI_API_KEY` → Clé API Google Gemini
- `DOCKER_*` → Credentials Docker
- `SSH_*` → Credentials SSH pour serveurs

### Frontend:

- `REACT_APP_API_BASE_URL` → URL du backend API
- `REACT_APP_GITHUB_*` → Paramètres GitHub OAuth

---

## ✨ RÉSUMÉ EN UNE PHRASE

**Vulnix est une plateforme DevSecOps automatisée qui analyse les dépôts Git, domaines SSL et serveurs pour détecter les vulnérabilités (CVE, secrets, SAST), les enrichit depuis multiples sources (NVD, EPSS, CISA KEV, Exploit-DB), génère des résumés IA, et propose des corrections automatiques via commits GitHub.**
