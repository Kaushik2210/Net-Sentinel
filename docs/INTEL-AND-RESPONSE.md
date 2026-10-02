# Threat Intelligence and Response Simulation

## Threat intelligence (`/threat-intel`)

Indicator kinds: IP, domain, hash (MD5/SHA-1/SHA-256), URL (http/https). Values are validated and normalised on entry
(IPs canonicalised, domains lower-cased without the trailing dot, hashes lower-cased), duplicates return 409, and writes need the
ANALYST role (delete needs ADMIN). Adds and deletes are audit-logged.

**No intelligence is shipped or fetched.** The only provider is the local store, containing whatever analysts add. Nothing is invented,
and no API key appears anywhere in the code. The UI states that a non-match never means "safe".

**Adapter interface.** `app/intel/providers.py` defines `ThreatIntelProvider.lookup(kind, value)`. A feed integration would implement it,
read credentials from environment variables, and be added to `providers()`. `/api/v1/threat-intel/check` already queries every registered provider.

**Matching.** `/api/v1/threat-intel/matches` reports IP and domain indicators that appear in the last 24 hours of alerts and events, with the
alert and event IDs involved.

## Response recommendations and simulation

Recommendations are derived from an incident's evidence, and each states which alerts motivated it:

| Action | Triggered by |
|---|---|
| Isolate device | incident risk ≥ 50, target is the chain's origin host |
| Block destination | an exfiltration step, target is the external address |
| Disable account | a successful login after a run of failures, target is that account |
| Review authentication logs | a credential-attack step, target is the attacked service |
| Review endpoint activity | a lateral-movement step, targets are the hosts that accepted logins |
| Capture additional traffic | a command-and-control step, target is the source |

**Safe simulation.** Everything is `RECOMMENDATION ONLY`. The one executor, `SimulatedActuator`, returns text such as
`DEVICE 10.0.20.22 WOULD BE ISOLATED. No real network modification occurs.`, marks the recommendation `simulated`, and writes an audit entry
with `real: false`. `ResponseActuator` is the interface a firewall, EDR or SOAR integration would implement; none exists, and any real actuator should be
opt-in via configuration and require explicit approval.

## Limitations

Recommendations are rule-derived from stage names and cannot judge business impact (isolating a domain controller is not free); the local indicator store
has no expiry, tags or feed sync; domain matching is suffix-based on recorded DNS/TLS names only.
