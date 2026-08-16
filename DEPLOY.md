# Déploiement Vulnix / Medianet (préprod → prod)

## Prérequis serveur

- Docker + Docker Compose v2
- Image scanner Kali déjà construite : `medianet-kali-scanner:v3`
- (Recommandé) reverse proxy HTTPS (Caddy / nginx) devant le port 80
- 4 Go RAM minimum, 20 Go disque

## 1. Préparer les secrets

```bash
cp .env.example .env
nano .env   # remplir POSTGRES_PASSWORD, JWT_SECRET, OAuth, clés API
```

Générer un JWT secret (≥ 32 caractères) :

```bash
openssl rand -base64 64
```

Auth session (déjà configuré dans l’exemple) :

- Access JWT court (`JWT_ACCESS_TOKEN_MINUTES=15`) en cookie HttpOnly `vulnix_at`
- Refresh token révocable (`JWT_REFRESH_TOKEN_DAYS=7`) en cookie HttpOnly `vulnix_rt`
- En HTTPS : `COOKIE_SECURE=true`
- Rate-limit login : `LOGIN_RATE_LIMIT_PER_MINUTE=10`

## 2. Configurer OAuth (si utilisé)

Dans GitHub → Settings → Developer settings → OAuth Apps :

- Homepage URL : `https://ton-domaine.com`
- Authorization callback URL : `https://ton-domaine.com/api/auth/github/callback`  
  (ou `https://api.ton-domaine.com/...` si API séparée)

Mettre les mêmes valeurs dans `.env` :

- `GITHUB_OAUTH_FRONTEND_URL`
- `GITHUB_OAUTH_REDIRECT_URI`
- `APP_CORS_ALLOWED_ORIGINS=https://ton-domaine.com`

## 3. Lancer

```bash
docker compose up -d --build
```

Vérifier :

```bash
docker compose ps
curl -s http://localhost/api/hello
```

Frontend : `http://IP-SERVEUR/` (ou ton domaine HTTPS).

## 4. HTTPS (recommandé)

Exemple Caddy devant le compose :

```
ton-domaine.com {
  reverse_proxy localhost:80
}
```

Puis mets à jour `.env` avec les URLs `https://...` et redémarre :

```bash
docker compose up -d
```

## 5. Premier admin

Par défaut le bootstrap admin est **désactivé** en prod.

Options :

1. Créer le premier compte via l’UI (si `APP_FIRST_USER_IS_ADMIN=true`, le 1er user devient admin), ou
2. Activer temporairement le bootstrap :

```env
APP_BOOTSTRAP_ADMIN_ENABLED=true
APP_BOOTSTRAP_ADMIN_EMAIL=admin@ton-domaine.com
APP_BOOTSTRAP_ADMIN_LOGIN=admin@ton-domaine.com
APP_BOOTSTRAP_ADMIN_PASSWORD=MotDePasseFort!
```

Puis redémarrer, se connecter, et **remettre `false`**.

## 6. Scans Kali

Le service Compose `kali-scanner` construit et **garde** l’image `medianet-kali-scanner:v3`
(un `sleep infinity` la marque « in use » : `docker image prune` ne la supprime plus).

Premier build (long, 20–40 min) :

```bash
docker compose up -d --build kali-scanner
docker images | grep medianet-kali-scanner
```

Ne pas lancer `docker system prune -a` / `docker image prune -a` : ça efface toute image
sans conteneur en cours, donc l’ancien scanner Kali s’il n’était pas dans Compose.

## Checklist avant ouverture publique

- [ ] `.env` non commité, mots de passe forts
- [ ] HTTPS actif
- [ ] CORS = domaine réel uniquement
- [ ] OAuth redirect HTTPS
- [ ] Bootstrap admin désactivé
- [ ] Sauvegarde Postgres planifiée (`pg_dump`)
- [ ] Firewall : seuls 80/443 ouverts

## Dev local (inchangé)

```bash
# Backend
cd Backend && mvn spring-boot:run

# Frontend
cd Frontend && npm start
```
