# Security

NetSentinel handles security data, so it is built as a security-sensitive application. It is
a research project and **has not been independently audited**; do not expose it to untrusted
networks without further hardening.

## Implemented

- **Authentication:** JWT (HS256), 60-minute expiry, bcrypt password hashing.
- **Authorization:** `VIEWER < ANALYST < ADMIN` hierarchy enforced by `require_role`.
- **Login hardening:** per-IP rate limit, identical error for unknown user and wrong password, and a dummy-hash comparison so timing does not reveal valid usernames.
- **Input validation:** Pydantic models and bounded `Query` parameters on every endpoint.
- **Headers:** `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, strict CSP and `no-store` on API responses (relaxed only for `/docs`).
- **Audit log:** logins and failed logins are persisted (`audit_logs`) and mirrored to the `netsentinel.audit` logger.
- **Secrets:** read from the environment. Production refuses to start without `JWT_SECRET`. `.env` is gitignored.
- **Error handling:** unhandled errors return a generic 500; details go only to logs.
- **WebSocket:** authenticates on the first message, 5 s timeout, slow consumers are dropped rather than back-pressuring ingestion.

## Known limitations

- The web console stores the bearer token in `sessionStorage`, which is readable by script if an XSS bug exists. A hardened deployment should use an httpOnly, SameSite cookie issued by the API.
- No refresh tokens, account lockout, MFA, or password-reset flow.
- Rate limiting is in-memory per process; use a shared store when running multiple workers.
- Seed accounts are for development only; their passwords come from `.env`.
- No TLS termination is provided; put a reverse proxy in front for any non-local use.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository rather than a public issue.
