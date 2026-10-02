# NetSentinel Architecture

NetSentinel is an experimental research platform for explainable network security
investigation. It is designed to sit on top of existing telemetry engines (Zeek,
Suricata, PCAP, NetFlow, syslog), not replace them.

## Data flow

```
Telemetry source ─▶ NetworkEvent ─▶ Behavior profile ─▶ Detectors ─▶ Alerts
 (adapter)          (normalized)     (baseline vs now)   (rule/behavioral/ML)
                                                              │
        Response ◀─ Risk engine ◀─ Attack chain ◀─ Correlation ◀┘
     (simulated)    (named factors)  (MITRE-mapped)  (entity + time)
```

Every arrow carries evidence IDs (`evt_…`, `alt_…`, `inc_…`) so any conclusion can be traced
back to raw telemetry. The planned analyst assistant only receives this evidence package.

## Repository layout

```
apps/api      FastAPI service (Python)
  app/core        settings, security (JWT, RBAC), middleware, rate limiting
  app/models      SQLAlchemy models, split by domain
  app/services    behavior scoring, simulation, ingestion loop, event bus, seed
  app/api/v1      versioned routers (+ WebSocket)
  alembic/        migrations
apps/web      Next.js console (TypeScript, Tailwind v4)
  src/components/cyber    design-system primitives
  src/components/{landing,dashboard,shell}
  src/lib         typed API client, auth, live-stream hook
infrastructure/docker     compose file
docs/                     this folder
```

Planned module boundaries (added by phase): `detection/`, `ml/`, `correlation/`, `replay/`
under `apps/api/app/`, each behind a small interface.

## Key decisions

| Decision | Rationale |
|---|---|
| Monorepo with `apps/` only (no shared `packages/` yet) | Types are small; a shared package would add build complexity before it pays off. Revisit when OpenAPI-generated types are introduced. |
| SQLite for local dev/tests, PostgreSQL for compose/production | Zero-setup demos and fast tests; migrations are written with `render_as_batch` so they run on both. |
| Prefixed string IDs (`evt_3fa9…`) | Evidence IDs are shown to analysts and quoted by the assistant; they must be readable and typed. |
| `TelemetrySource` protocol | The simulator and future Zeek/Suricata/PCAP adapters produce the same normalized event dict. |
| In-process `EventBus` | Enough for one worker. A Redis implementation can replace it behind the same two methods (`publish`, `subscribe`). Redis is deliberately not a dependency yet. |
| Roles stored as a column, not a table | Three fixed roles with a strict hierarchy; a table adds joins without flexibility we need. |
| WebSocket auth via first message | Keeps tokens out of URLs and access logs. |
| Transparent risk arithmetic | Every point of a score is a named factor (see `services/behavior.py`). No opaque "AI score". |

## Honesty rules (enforced in code and UI)

1. **Provenance is explicit.** Alerts carry `detection_class`: `RULE`, `BEHAVIORAL`, `ML`, `CORRELATED`. The UI never merges them.
2. **Simulation is labelled.** Mode is returned by `/api/v1/analytics/summary` and shown in the top bar and a dashboard banner. The simulator emits only `info` telemetry; it never fabricates detections.
3. **Planned features are inert.** Unbuilt modules appear in the sidebar tagged with their phase and are not links.

## Scaling notes

Event reads use keyset pagination on an indexed timestamp; the browser holds at most 60 events.
Ingestion is batched (1 s flush) with retention pruning. Next steps for volume: partitioned
event tables, Redis streams for fan-out, and pre-aggregated rollups for dashboard metrics.

## Extension points

- **New telemetry source:** implement `TelemetrySource` (`app/services/simulation.py`).
- **New detector (phase 3):** implement the detector interface and register it; no other module changes.
- **Future:** cloud flow logs, endpoint telemetry, SOAR hooks, and multi-tenancy are intended as adapters behind these same seams and are not implemented.
