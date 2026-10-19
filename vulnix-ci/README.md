# Vulnix CI (Woodpecker)

Woodpecker exécute les pipelines, **Vulnix les pilote** : on active la CI d'un dépôt, on lance un pipeline, on suit
les étapes et les journaux dans l'onglet **CI/CD** d'un projet Vulnix. On n'ouvre Woodpecker qu'une fois, à
l'installation (étape 1.4).

Un seul dossier, identique en local et sur le serveur. Ce qui change entre les deux : le fichier `.env`.

```
vulnix-ci/
├── docker-compose.yml   serveur Woodpecker + agent (versions fixées)
├── .env.example         modèle de configuration
├── .env                 ta configuration (créée par setup, jamais partagée)
├── setup.ps1 / setup.sh crée .env avec des secrets aléatoires
├── vulnix-token.py      crée le jeton avec lequel Vulnix pilote Woodpecker
└── data/                base de Woodpecker (créée au démarrage, à sauvegarder)
```

## Comment ça marche

1. Dans Vulnix, **Activer la CI** sur un dépôt du projet : Vulnix active le dépôt dans Woodpecker, lui dit de
   demander ses pipelines à Vulnix, et range un jeton CI Vulnix (scan + verdict de ce dépôt seulement) dans les
   secrets Woodpecker du dépôt. Rien n'est ajouté au dépôt.
2. À chaque pipeline (bouton **Lancer la CI**, ou `git push` quand Woodpecker est sur le serveur), Woodpecker appelle
   `POST /api/woodpecker/config` sur Vulnix. La requête est signée (ed25519) ; Vulnix vérifie la signature, lit la
   liste des fichiers du commit sur GitHub et écrit le pipeline :
   - une étape par partie du dépôt : Maven (`mvn verify`), Gradle, npm (install, test, lint, build), Python, Composer ;
   - l'étape **Scan Vulnix** : scan du commit, puis échec si une vulnérabilité critique, élevée ou KEV n'a pas
     d'exception validée.
3. Vulnix lit l'avancement et les journaux par l'API Woodpecker et les affiche dans le projet.

## Étape 1 — Installer

### 1.1 Créer l'application OAuth GitHub

Sur GitHub : **Settings → Developer settings → OAuth Apps → New OAuth App**

| Champ | En local | Sur le serveur |
|---|---|---|
| Application name | `Vulnix CI local` | `Vulnix CI` |
| Homepage URL | `http://localhost:8000` | `https://ci.ton-domaine.com` |
| Authorization callback URL | `http://localhost:8000/authorize` | `https://ci.ton-domaine.com/authorize` |

Puis **Generate a new client secret**. Il faut une application pour le local et une pour le serveur (adresse de
retour différente). Le compte GitHub qui se connecte doit être **admin** des dépôts à activer (Woodpecker y crée un
webhook) ; pour un dépôt d'organisation, l'organisation doit autoriser l'application.

### 1.2 Configurer

Windows :
```powershell
cd C:\Users\user\Desktop\vulnix-ci
.\setup.ps1
notepad .env      # WOODPECKER_ADMIN, WOODPECKER_GITHUB_CLIENT, WOODPECKER_GITHUB_SECRET, WOODPECKER_WEBHOOK_HOST
```
Serveur (Linux) :
```sh
cd vulnix-ci && sh setup.sh && nano .env
```

`WOODPECKER_WEBHOOK_HOST` : adresse publique que GitHub appelle à chaque push. GitHub refuse `localhost`, donc on
met une adresse de ton domaine même en local (les push n'arrivent pas tant que Woodpecker n'y est pas installé ; on
lance alors la CI depuis Vulnix).

### 1.3 Démarrer

```sh
docker compose up -d
docker compose ps        # les deux services doivent être "healthy"
```

### 1.4 Se connecter une fois, puis donner le jeton à Vulnix

1. Ouvrir `WOODPECKER_HOST` (en local http://localhost:8000) et **Login with GitHub** avec le compte `WOODPECKER_ADMIN`.
   C'est la seule fois où l'on ouvre Woodpecker.
2. Créer le jeton de Vulnix :
   - local : `python vulnix-token.py`
   - serveur : `docker run --rm -v "$PWD/data:/data:ro" -v "$PWD/vulnix-token.py:/t.py:ro" python:3.12-alpine python -I /t.py /data/woodpecker.sqlite`
3. Dans la configuration de Vulnix (`Backend/config/secrets.local.properties`, jamais sur GitHub) :
   ```properties
   vulnix.ci.woodpecker.url=http://localhost:8000
   vulnix.ci.woodpecker.token=<le jeton affiché>
   # Adresse de Vulnix vue depuis Woodpecker et depuis les étapes des pipelines
   vulnix.ci.woodpecker.callback-url=http://host.docker.internal:8080
   ```
4. Redémarrer Vulnix. L'onglet **CI/CD** des projets est prêt.

Le jeton reste valable tant que l'utilisateur existe dans Woodpecker. Il ne s'affiche ni dans l'interface ni dans les journaux.

## Local et serveur : les différences

| | Local (PC) | Serveur |
|---|---|---|
| `WOODPECKER_HOST` | `http://localhost:8000` | `https://ci.ton-domaine.com` |
| `vulnix.ci.woodpecker.callback-url` | `http://host.docker.internal:8080` | l'adresse publique de Vulnix (`https://vulnix.ton-domaine.com`) |
| Déclenchement | bouton **Lancer la CI** dans Vulnix | le bouton, et chaque `git push` (webhook) |
| Accès web Woodpecker | 127.0.0.1 seulement | nginx + certificat devant le port 8000 |

nginx sur le serveur (à adapter) : l'interface sur `ci.ton-domaine.com`, et le chemin du webhook choisi dans
`WOODPECKER_WEBHOOK_HOST` (ici `/ci`) renvoyé vers Woodpecker.
```nginx
server {
    server_name ci.ton-domaine.com;
    location / { proxy_pass http://127.0.0.1:8000; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme; }
}
# Dans le server{} du domaine de WOODPECKER_WEBHOOK_HOST :
location /ci/ { proxy_pass http://127.0.0.1:8000/; proxy_set_header Host $host; }
```

## Sécurité

- Les pipelines ne touchent jamais la production : ils compilent, testent et demandent un scan à Vulnix.
- Les dépôts ne sont pas « de confiance » dans Woodpecker : pas de mode privilégié, de volumes ni de réseau hôte.
- Le jeton CI Vulnix est limité à un dépôt (scan + verdict), rangé comme secret Woodpecker, retiré des pull requests,
  et révoqué quand on désactive la CI dans Vulnix.
- Vulnix n'accepte que les demandes de pipeline signées par la clé de ce Woodpecker, de moins de 5 minutes.

## Déplacer sur le serveur

1. Copier le dossier **sans** `.env` ni `data/` (ou avec `data/` pour garder l'historique et l'utilisateur).
2. `sh setup.sh`, remplir `.env` avec l'application OAuth du serveur.
3. `docker compose up -d`, puis l'étape 1.4.

## Sauvegarde et mise à jour

- Sauvegarde : le dossier `data/` (la base SQLite de Woodpecker), Woodpecker arrêté.
- Ne jamais ouvrir `data/woodpecker.sqlite` pendant que Woodpecker tourne (`vulnix-token.py` en lit une copie).
- Mise à jour : changer la version dans `docker-compose.yml` (les deux images, même version), puis
  `docker compose pull && docker compose up -d`.

## Uptime Kuma (surveillance des sites)

Troisième service du même `docker-compose.yml` (image `louislam/uptime-kuma:1.23.16`, environ 150 Mo, ~100 Mo de mémoire).
Données dans `./uptime-kuma/` : à sauvegarder avec `./data/`.

- Interface : http://localhost:3001. Compte `admin`, mot de passe dans `.env` (`UPTIME_ADMIN_PASSWORD`). À changer dans Paramètres > Sécurité.
- **Nommer chaque moniteur avec le domaine** du projet (ex. `courtlinker.com`) et l'ajouter à la page de statut **`vulnix`** :
  Vulnix lit cette page publique pour l'indicateur « Disponibilité » de la vue d'ensemble.
- Alertes : Paramètres > Notifications (e-mail SMTP, Telegram…), puis cocher la notification sur chaque moniteur.
- À ne pas installer sur le serveur de production : s'il tombe avec lui, il ne peut pas prévenir.

Côté Vulnix (`Backend/config/secrets.local.properties`) : `vulnix.uptime.url=http://127.0.0.1:3001` (127.0.0.1, pas localhost)
et `vulnix.uptime.status-page=vulnix`.
