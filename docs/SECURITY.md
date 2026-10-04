# Security

NetSentinel handles security data, so it is built as a security-sensitive application. It is a research project and **has not been
independently audited**; do not expose it to untrusted networks without further hardening.

## Implemented

**Authentication and authorization**
- JWT (HS256), 60-minute expiry, bcrypt password hashing. The token's role claim is informational only: authorization always uses the role in the database, and deactivated users are rejected immediately.
- `VIEWER < ANALYST < ADMIN` hierarchy enforced by dependency (`require_role`); write endpoints (notes, status, simulation, upload, indicators) need ANALYST, destructive ones (delete, reset, detector toggle) need ADMIN.
- Login hardening: per-IP rate limit, **per-username failed-attempt throttle** (8 failures / 15 min, keyed by the submitted name so it reveals nothing about which accounts exist, case-insensitive, returns `429` with `Retry-After`), identical error for unknown user and wrong password, and a dummy-hash comparison so timing does not reveal valid usernames.

**API surface**
- Pydantic models and bounded `Query` parameters on every endpoint; enumerated values (status, severity, kind) are validated by pattern or `Literal`.
- Headers: `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, strict CSP and `no-store` on API responses (relaxed only for `/docs`). CORS allows only configured origins, without credentials.
- Unhandled errors return a generic 500; details go only to logs.
- Parameterised queries throughout (SQLAlchemy); no raw SQL from user input.

**WebSocket**
- Authenticates on the first message with a 5-second timeout (tokens never appear in URLs or access logs), checks the `Origin` header against the allow-list, and is closed when the token expires. Slow consumers are dropped instead of back-pressuring ingestion.

**Frontend**
- Next.js sets `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, removes `X-Powered-By`, and in production sends a CSP (`default-src 'self'`, `connect-src` limited to the API origin, `frame-ancestors 'none'`, `object-src 'none'`). Verified by running the production build under the policy.
- React escapes all rendered values; no `dangerouslySetInnerHTML` is used.

**Untrusted input**
- PCAP upload: 25 MB cap (read at most limit+1 bytes), magic-byte check, packet and event caps, temp file always removed, filename stripped of path components, SHA-256 recorded, nothing executed.
- Custom detection rules are data matched by a small safe matcher; no expression is ever evaluated.
- Analyst answers are validated against a closed set of evidence IDs.

**Operations**
- Append-only audit log (logins, failures, throttling, status/assignment/notes, simulations, replays, intel changes) stored in `audit_logs` and mirrored to a dedicated logger.
- Secrets come from the environment; production refuses to start without `JWT_SECRET`; `.env` is gitignored; no credential is hard-coded.
- Response actions are recommendations; the only executor is a simulator that changes nothing and records `real: false`.

## Public (unauthenticated) surface

`/api/v1/public/playground` and, when `GUEST_ACCESS=true`, `/api/v1/auth/guest` are reachable without credentials. They are designed to be safe to expose:

- The playground accepts no files. Scenarios are built server-side from fixed recipes, results are computed in memory and never stored.
- Only an allow-list of detector parameters can be set, and each value is clamped to a fixed range, so a visitor cannot make a run expensive or inject arbitrary detector arguments. Unknown detectors, parameters or scenarios are rejected with 422.
- Both routes are rate limited per client address (12 runs and 20 guest sessions per minute).
- A guest session is always a VIEWER token for the existing `viewer` account (it cannot upload, simulate or write) and every issue is audit-logged. The route returns 404 unless enabled.

## Known limitations

- The web console keeps the bearer token in `sessionStorage`, which script can read if an XSS bug exists. A hardened deployment should use an httpOnly, SameSite cookie issued by the API.
- The production CSP allows `'unsafe-inline'` scripts because of Next.js bootstrap code; nonces are future work.
- No refresh tokens, MFA, password change or reset flow, or user-management UI.
- Rate limiting, login throttling and the event bus are in-memory and per process; use a shared store (Redis) before running more than one worker.
- Account throttling can be used to lock a *known* username for a few minutes. This was chosen over unlimited guessing.
- Scapy parses untrusted captures in-process; run replay on an isolated host for hostile files.
- SQLite is used for development and tests; the migrations have not been run against PostgreSQL.
- No TLS termination is provided; put a reverse proxy in front of any non-local deployment.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository rather than a public issue.
