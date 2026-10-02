# Contributing

## Setup

```bash
cp .env.example .env            # then set JWT_SECRET and the SEED_*_PASSWORD values
cd apps/api && python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
cd ../web && npm install
```

## Checks (run before opening a PR)

```bash
cd apps/api && python -m pytest && python -m ruff check .
cd apps/web && npm test && npm run typecheck && npm run lint
```

## Conventions

- Conventional commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `perf:`, `security:`.
- One logical change per commit; keep messages short and specific.
- Schema changes need an Alembic migration (`alembic revision --autogenerate`).
- Anything shown to an analyst as a score must expose its contributing factors.
- Simulated data must be labelled as simulated wherever it is displayed.
- Detectors and telemetry adapters are added behind their interfaces without touching unrelated modules.
