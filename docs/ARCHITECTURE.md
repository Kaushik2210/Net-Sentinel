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
back to raw telemetry. The analyst only receives this evidence package.

## Repository layout

```
apps/api      FastAPI service (Python)
  app/core        settings, security (JWT, RBAC), middleware, rate limiting
  app/models      SQLAlchemy models, split by domain
  app/detection   detector interface, registry, built-in detectors, engine
  app/ml          features, AnomalyModel interface, Isolation Forest, training service
  app/correlation pure alert -> incident-chain logic
  app/ingest      PCAP parser and synthetic capture generator
  app/replay      incremental replay builder
  app/analyst     evidence packages, deterministic answers, citation validator, provider interface
  app/intel       threat-intel provider interface and local store
  app/response    recommendations and the simulation-only actuator
  app/research    evaluation harness
  app/services    behavior scoring, simulation, ingestion loop, event bus, risk, incidents, seed
  app/api/v1      versioned routers (+ WebSocket)
  alembic/        migrations
apps/web      Next.js console (TypeScript, Tailwind v4)
  src/components/{cyber,landing,shell,dashboard,network,replay,investigate}
  src/lib         typed API client, auth, live-stream hook
infrastructure/docker     compose file
docs/                     documentation
```

Modules are flat packages behind small interfaces (`Detector`, `AnomalyModel`, `TelemetrySource`, `ThreatIntelProvider`, `ResponseActuator`, `AnalystProvider`),
so adding a capability does not touch unrelated code.

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
3. **Claims match the code.** The README states limitations and what is simulated; the landing page tags capabilities; the analyst says "Insufficient evidence." rather than guessing; response actions are simulation-only.

## Measured performance

On a development machine (SQLite, 20,000 stored events, single worker), median API latency is 3-12 ms: `/health` 3.5 ms, `analytics/summary` 8.7 ms,
`events?limit=200` 11.9 ms, `network/topology` 10.8 ms, `incidents` 6.9 ms, `mitre` 8.4 ms. A training run of the anomaly model takes ~2 s at startup; the
research evaluation takes ~25 s; a replay of a 4,500-packet capture takes a few seconds. These are single-machine figures, not a load test.

## Scaling notes

Event reads use keyset pagination on an indexed timestamp; the browser holds at most 60 events.
Ingestion is batched (1 s flush) with retention pruning. Next steps for volume: partitioned
event tables, Redis streams for fan-out, and pre-aggregated rollups for dashboard metrics.

## Extension points

- **New telemetry source:** implement `TelemetrySource` (`app/services/simulation.py`).
- **New detector:** implement the detector interface and register it; no other module changes.
- **Future:** cloud flow logs, endpoint telemetry, SOAR hooks, and multi-tenancy are intended as adapters behind these same seams and are not implemented.
