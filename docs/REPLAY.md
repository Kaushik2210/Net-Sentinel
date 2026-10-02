# PCAP Attack Replay

```
PCAP ─▶ parser (Scapy) ─▶ flows ─▶ events ─▶ incremental detection ─▶ correlation ─▶ replay JSON ─▶ player
```

## Parsing (`app/ingest/pcap.py`)

Packets are aggregated into flows and mapped onto the same event vocabulary as live telemetry
(`conn_attempt`, `dns_query`, `tls_session`, `auth_failure`, `auth_success`, ...).

**Inferred events.** SSH/RDP/SMB/WinRM payloads are encrypted, so authentication outcomes cannot be observed.
A short (< 3 s), low-payload (≤ 3 KB) flow is classified `auth_failure`; anything longer `auth_success`. These events carry
`attributes.inferred = true` and the UI states the heuristic. IPv4 only.

**Untrusted input.** 25 MB limit (read at most limit+1 bytes), magic-byte check (pcap, pcap-ns, pcapng), a capture must contain
IPv4 packets, 250k packet and 40k event caps, parsed from a temp file that is always removed, filename stripped of path components, SHA-256
stored, audit entry written. Nothing in the capture is executed. Scapy dissectors have had parser vulnerabilities: use an isolated host for
hostile captures.

## Replay (`app/replay/engine.py`)

The engine steps through the capture in 60 frames. At each frame it runs the detectors on only the events seen so far (10-minute window), so
an alert appears at the moment it first became detectable, not retroactively. Correlation and incident risk are recomputed per frame, which
produces the threat score and chain growth shown in the player. The ML detector is excluded (it is calibrated for live windows).

The result is one self-contained JSON document (hosts, edges, compact events, frames, alerts, incident). The browser derives everything from it,
so play, pause, step, rewind, fast-forward and scrubbing need no server calls.

## Synthetic sample

`POST /api/v1/replay/sample` generates a capture with Scapy (benign DNS/TLS plus a seven-minute attack), writes a real pcap and parses it through
the same path as an upload. A small file cannot carry 100 MB, so the sample lowers `DataExfiltrationDetector.min_bytes` to 3 MB; the override is
stored in the result and displayed. Without it the sample's ~4 MB upload is correctly *not* flagged (covered by a test).

## Limitations

Flow-level, IPv4-only analysis; encrypted-payload heuristics; synchronous processing (seconds for typical captures, longer near the caps);
the replay topology layout is a simple deterministic arc, not a force layout.
