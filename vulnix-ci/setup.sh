#!/usr/bin/env sh
# Linux (serveur) : même rôle que setup.ps1. Ne remplace jamais un .env existant.
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then echo ".env existe déjà : rien changé."; exit 0; fi
secret=$(openssl rand -hex 32)
sed -e "s/^WOODPECKER_AGENT_SECRET=$/WOODPECKER_AGENT_SECRET=${secret}/" -e "s/^WOODPECKER_GRPC_SECRET=$/WOODPECKER_GRPC_SECRET=$(openssl rand -hex 32)/" .env.example > .env
chmod 600 .env
mkdir -p data agent-config
echo ".env créé. Remplis WOODPECKER_ADMIN, WOODPECKER_GITHUB_CLIENT et WOODPECKER_GITHUB_SECRET, puis : docker compose up -d"
