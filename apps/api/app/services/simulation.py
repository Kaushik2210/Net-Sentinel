"""Telemetry source for SIMULATION mode.

``TelemetrySource`` is the seam where real adapters (Zeek, Suricata, PCAP, NetFlow, syslog)
plug in later: each yields normalized ``NetworkEvent`` dicts. The simulator below only
produces *telemetry*; it never fabricates detections. Detections come from the detection
engine (Phase 3) running over this telemetry.
"""

import random
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Protocol

from app.models.base import new_id


class TelemetrySource(Protocol):
    name: str

    def stream(self) -> Iterator[dict]: ...


# (event_type, protocol, port, weight)
_NORMAL = [
    ("dns_query", "dns", 53, 40),
    ("http_request", "http", 80, 16),
    ("tls_session", "tls", 443, 24),
    ("smb_session", "smb", 445, 6),
    ("kerberos_auth", "kerberos", 88, 5),
    ("ssh_session", "ssh", 22, 2),
    ("db_query", "postgres", 5432, 4),
    ("syslog", "syslog", 514, 3),
]

_DOMAINS = ["updates.example.org", "cdn.example.net", "mail.example.com", "intranet.corp.local",
            "api.example.io", "static.example.net", "time.example.org", "login.example.com"]


class SimulationSource:
    name = "simulation"

    def __init__(self, devices: list[dict], seed: int, now_fn=None):
        self._rng = random.Random(seed + 99)
        self._devices = [d for d in devices if d["device_type"] not in ("internet",)]
        self._servers = {d["device_type"]: [] for d in devices}
        for d in devices:
            self._servers[d["device_type"]].append(d)
        self._now = now_fn or (lambda: datetime.now(UTC))
        self._weights = [w for *_, w in _NORMAL]

    def _pick_dst(self, src: dict, etype: str) -> tuple[str, str | None]:
        r = self._rng
        if etype == "dns_query":
            dns = next((d for d in self._devices if d["hostname"] == "DNS-01"), None)
            return (dns["ip"] if dns else "10.0.10.14"), r.choice(_DOMAINS)
        if etype == "kerberos_auth":
            ad = next(d for d in self._devices if d["hostname"] == "AD-01")
            return ad["ip"], None
        if etype == "smb_session":
            fs = next(d for d in self._devices if d["hostname"] == "FILE-01")
            return fs["ip"], None
        if etype == "db_query":
            dbs = self._servers.get("database") or self._devices
            return r.choice(dbs)["ip"], None
        if etype == "syslog":
            return next(d for d in self._devices if d["hostname"] == "SIEM-LOG-01")["ip"], None
        if etype == "ssh_session":
            return r.choice(self._devices)["ip"], None
        # web / tls: external destination
        return f"198.51.100.{r.randint(2, 250)}", r.choice(_DOMAINS)

    def next_event(self) -> dict:
        r = self._rng
        src = r.choice(self._devices)
        etype, proto, port, _ = r.choices(_NORMAL, weights=self._weights)[0]
        dst_ip, domain = self._pick_dst(src, etype)
        attrs = {"domain": domain} if domain else {}
        return {
            "id": new_id("evt"),
            "ts": self._now(),
            "source": self.name,
            "src_ip": src["ip"],
            "dst_ip": dst_ip,
            "src_device_id": src["id"],
            "dst_port": port,
            "protocol": proto,
            "event_type": etype,
            "bytes_sent": r.randint(60, 4000),
            "bytes_received": r.randint(60, 60000),
            "duration_ms": r.randint(2, 900),
            "severity": "info",
            "attributes": attrs,
        }

    def stream(self) -> Iterator[dict]:
        while True:
            yield self.next_event()
