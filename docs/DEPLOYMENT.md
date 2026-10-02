# Deployment

NetSentinel is a research platform. These notes describe how to run it beyond a laptop and what is **not** provided.

## Local development

See the README quick start. SQLite file `netsentinel.db` is created in the working directory of the API process; migrations run at startup
(`alembic upgrade head`), then dev users and the simulated network are seeded if the database is empty.

## Docker Compose (PostgreSQL)

```bash
cp .env.example .env     # set POSTGRES_PASSWORD, JWT_SECRET and the SEED_*_PASSWORD values
docker compose -f infrastructure/docker/docker-compose.yml --env-file .env up --build
```

Services: `db` (PostgreSQL 16, health-checked), `api` (port 8000, non-root user), `web` (port 3000). Compose refuses to start without `POSTGRES_PASSWORD` and `JWT_SECRET`.

> **Status: validated once, locally.** Built and run on Docker Desktop (Engine 29, Compose v5) with PostgreSQL 16: images build, the `db` health check passes, migrations apply on
> PostgreSQL, and the stack was exercised end to end (login, attack simulation, correlation, analyst, response recommendations, PCAP replay, MITRE, research run, UI under the production CSP).
> This was a single manual run, not CI. Running it on PostgreSQL also exposed the ML warm-up bug described in `docs/ML-METHODOLOGY.md`.

`NEXT_PUBLIC_API_URL` is baked into the web image at build time (build arg), so rebuild the image if the API's public address changes.

## Public deployment on a VPS (read-only demo)

`infrastructure/docker/docker-compose.prod.yml` runs PostgreSQL, the API, the web app and **Caddy**, which terminates TLS (automatic Let's Encrypt certificates for a real
hostname) and routes `/api/*`, `/health` and `/docs` to the API and everything else to the web app on one origin. Only Caddy publishes ports (80, 443); the database and
application containers are reachable only on the internal Docker network.

```bash
# on a Linux server with Docker and Compose, with an A/AAAA record for your domain pointing at it
git clone https://github.com/Kaushik2210/Net-Sentinel.git && cd Net-Sentinel
cp infrastructure/docker/prod.env.example .env.prod      # set DOMAIN and generate the three secrets
./scripts/deploy.sh                                      # build, start, wait for health, seed demonstration data once
```

Open ports 80 and 443 in the server firewall. To update: `git pull && ./scripts/deploy.sh` (seeding is idempotent).

**Access model.** Only the `VIEWER` account is created, so visitors can browse every page (dashboard, network twin, the demonstration incident, MITRE matrix, the sample replay,
research) but cannot run simulations, upload captures or change anything. `scripts/deploy.sh` seeds one reconstructed incident and one replay with `python -m app.tools.seed_demo`,
because a viewer cannot create them. Setting `SEED_ANALYST_PASSWORD` enables the attack demo and uploads for that account, which exposes PCAP parsing to the internet; do that deliberately.

**What was validated.** The full production stack (Caddy, HTTPS redirect, HSTS and CSP headers, viewer read access, 403 on write attempts, absent analyst/admin accounts, WebSocket over
`wss://`, forwarded-header handling) was run locally with `DOMAIN=localhost`. It has **not** been run on a real server with a real domain and Let's Encrypt certificate.

**Behind a proxy.** The API runs with `--proxy-headers` so rate limits and the audit log use the visitor's address rather than the proxy's. This is only safe because the API is not
published; do not expose port 8000 directly.

## Production checklist

- `ENVIRONMENT=production` (the API then refuses to start without `JWT_SECRET`); generate it with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- Terminate TLS in a reverse proxy; serve the web app and API over HTTPS and set `CORS_ORIGINS` to the exact web origin.
- Seed only the accounts you intend to expose (the production compose file seeds the viewer only); there is no user-management UI yet.
- Set `TELEMETRY_MODE=idle` unless you want synthetic traffic; with `idle` the attack-simulation endpoint is disabled.
- Run a single API worker, or replace the in-process pieces first: the event bus, rate limiter and login throttle are per-process.
- Back up PostgreSQL; `network_events` is pruned to `EVENT_RETENTION` rows, so treat it as a rolling window.
- Treat PCAP upload as handling hostile input: run the API in an isolated container or host.
- Keep `.env` out of version control (it is gitignored).

## Configuration reference

| Variable | Purpose | Default |
|---|---|---|
| `ENVIRONMENT` | `development`, `test` or `production` | `development` |
| `DATABASE_URL` | SQLAlchemy URL (`sqlite:///...` or `postgresql+psycopg://...`) | SQLite file |
| `JWT_SECRET` | token signing key (required in production) | ephemeral in dev |
| `ACCESS_TOKEN_MINUTES` | token lifetime | 60 |
| `SEED_ADMIN_PASSWORD` / `SEED_ANALYST_PASSWORD` / `SEED_VIEWER_PASSWORD` | dev seed accounts (empty skips the user) | empty |
| `CORS_ORIGINS` | comma-separated allowed web origins (also checked on WebSocket upgrade) | `http://localhost:3000` |
| `TELEMETRY_MODE` | `simulation` or `idle` | `simulation` |
| `SIMULATION_SEED`, `SIMULATION_EVENTS_PER_SECOND` | simulator determinism and rate | 1337, 4 |
| `EVENT_RETENTION` | maximum stored events | 20000 |
| `RATE_LIMIT_LOGIN`, `RATE_LIMIT_DEFAULT` | per-IP limits | `10/minute`, `240/minute` |
| `NEXT_PUBLIC_API_URL` | API address used by the browser | `http://localhost:8000` |

## Observability

The API logs to stdout through separate loggers: `netsentinel.app`, `.ingest`, `.detect`, `.audit` and `.seed`. Audit entries (logins, throttling, status changes, simulations,
uploads) are also stored in `audit_logs`. `GET /health` reports status, version, telemetry mode and live WebSocket subscribers.
