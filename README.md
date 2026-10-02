# NetSentinel

**An explainable network digital twin for threat detection, attack reconstruction and security investigation.**

NetSentinel is an MCA research project. It turns network telemetry into per-device behavioral
baselines, transparent risk scores, and (in later phases) correlated attack chains mapped to
MITRE ATT&CK. It is designed to consume telemetry from existing engines such as Zeek and
Suricata rather than replace them.

## Problem

Alert-centric tools tell analysts *that* something fired, but rarely *why*, what evidence
supports it, or how activity evolved. NetSentinel focuses on explainability: every score lists
its contributing factors, every conclusion cites events, and rule detections, behavioral
anomalies and ML anomalies are never conflated.

## Status

Phases 1–4 of 12 are complete. Honest feature matrix:

| Capability | State |
|---|---|
| Landing page, design system, command-center dashboard | Implemented |
| Auth (JWT), RBAC, audit log, rate limiting, secure headers | Implemented |
| Relational schema + Alembic migrations (all planned entities) | Implemented |
| Simulated enterprise network (47 devices) and live telemetry over WebSocket | Implemented |
| Behavioral baselines and transparent risk scoring | Implemented |
| React Flow network explorer, device intelligence panel | Implemented |
| Pluggable rule-based detection engine (8 detectors), alerts with evidence, labelled attack simulation | Implemented |
| Isolation Forest anomaly detection (labelled ML), behavioral alerts | Implemented |
| Correlation, attack chains, MITRE matrix | Phases 5–6 |
| PCAP replay, investigation workspace, evidence-bound assistant | Phases 7–8 |
| Threat intel, response simulation, research mode, demo mode | Phases 9–12 |

All telemetry is **synthetic** unless a real source is attached, and the UI says so.

## Quick start (local)

Requirements: Python 3.11+, Node 22+.

```bash
cp .env.example .env     # set JWT_SECRET and SEED_*_PASSWORD (see comments in the file)

# API  (http://localhost:8000, docs at /docs)
cd apps/api
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # Linux/macOS: .venv/bin/pip
.venv/Scripts/python -m uvicorn app.main:app --port 8000

# Web  (http://localhost:3000)
cd apps/web
npm install
npm run dev
```

Sign in with a seed account (`admin`, `analyst` or `viewer`) using the password you set in `.env`.

With Docker (PostgreSQL): `docker compose -f infrastructure/docker/docker-compose.yml --env-file .env up --build`
(compose file provided; not yet validated in CI).

## How risk scoring works

For each baseline metric (DNS/h, HTTP/h, SSH/h, upload MB/day, new destinations/day):
`points = min(cap, round(5 · log2(current / baseline_max)))` when the ratio exceeds 1.5×.
A criticality amplifier (+3 per level above 1) applies only if something already deviates.
Example, PC-07: SSH +20, upload +20, DNS +15, new destinations +9, criticality +3 = **67**.
The same breakdown is shown in the UI and pinned by a test. See `apps/api/app/services/behavior.py`.

## Tech stack

Next.js 16, TypeScript, Tailwind v4, Framer Motion, Recharts / React Flow (installed for upcoming
views), FastAPI, SQLAlchemy 2, Alembic, PostgreSQL / SQLite, scikit-learn (phase 4), pytest, Vitest.

## Testing

```bash
cd apps/api && python -m pytest && python -m ruff check .
cd apps/web && npm test && npm run typecheck && npm run lint && npm run build
```

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Threat detection](docs/THREAT-DETECTION.md) · [ML methodology](docs/ML-METHODOLOGY.md) · [Security](docs/SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Limitations

Synthetic data only; no real telemetry adapters yet; single-process event bus; session token in
`sessionStorage`; no independent security audit. See [SECURITY.md](docs/SECURITY.md).

## Author

Kaushik. MCA project.
