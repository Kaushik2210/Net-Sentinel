#!/usr/bin/env bash
# Deploy or update NetSentinel on a Docker host (run from the repository root).
#   ./scripts/deploy.sh            build and start, then seed demonstration data once
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env.prod}"
COMPOSE=(docker compose -p netsentinel -f infrastructure/docker/docker-compose.prod.yml --env-file "$ENV_FILE")

[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE (copy infrastructure/docker/prod.env.example and fill it in)"; exit 1; }
for v in DOMAIN POSTGRES_PASSWORD JWT_SECRET SEED_VIEWER_PASSWORD; do
  grep -Eq "^${v}=.+" "$ENV_FILE" || { echo "$v is empty in $ENV_FILE"; exit 1; }
done

"${COMPOSE[@]}" up -d --build

echo "waiting for the API..."
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T api python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3)" 2>/dev/null; then ready=1; break; fi
  sleep 2
done
[ "${ready:-0}" = 1 ] || { echo "API did not become healthy"; "${COMPOSE[@]}" logs --tail 40 api; exit 1; }

"${COMPOSE[@]}" exec -T api python -m app.tools.seed_demo
"${COMPOSE[@]}" ps
echo "deployed: https://$(grep -E '^DOMAIN=' "$ENV_FILE" | cut -d= -f2)"
