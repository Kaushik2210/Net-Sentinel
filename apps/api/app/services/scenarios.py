"""Labelled attack telemetry for SIMULATION mode (also the basis of the future demo mode).

Everything generated here has ``source == "sim-attack"`` so it can be identified, reset, and
never mistaken for real traffic. The generator only produces *telemetry*; whether anything is
detected is entirely up to the detection engine.

Scenario (staged over ~8 minutes ending "now"), attacker = PC-07:
  1 reconnaissance   host sweep across the DMZ/internal subnets
  2 port scan        vertical scan of DB-02
  3 credential       SSH brute force against JUMP-01
  4 compromise       successful SSH to JUMP-01, then lateral to APP-02 and DB-02
  5 c2 / dns         DNS tunnelling-style lookups
  6 exfiltration     ~1.2 GB outbound to an external host (documentation range)
"""

import random
import string
from datetime import datetime, timedelta

from app.models.base import new_id

SOURCE = "sim-attack"
EXTERNAL_C2 = "198.51.100.77"
ATTACKER = "PC-07"


def _ev(ts, src, dst, port, proto, etype, sent=0, recv=0, **attrs) -> dict:
    return {
        "id": new_id("evt"), "ts": ts, "source": SOURCE, "src_ip": src, "dst_ip": dst, "src_device_id": None,
        "dst_port": port, "protocol": proto, "event_type": etype, "bytes_sent": sent, "bytes_received": recv,
        "duration_ms": 0, "severity": "info", "attributes": {"scenario": "attack-chain", **attrs},
    }


def generate_attack(devices: list[dict], now: datetime, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    by = {d["hostname"]: d for d in devices}
    atk, jump, db2, app2 = by[ATTACKER], by["JUMP-01"], by["DB-02"], by["APP-02"]
    src = atk["ip"]
    base = now - timedelta(minutes=8)
    events: list[dict] = []

    def at(stage_minute: float, i: int, step: float) -> datetime:
        return base + timedelta(minutes=stage_minute, seconds=i * step)

    # 1 reconnaissance: sweep 24 hosts on 443
    targets = [d for d in devices if d["device_type"] not in ("internet",) and d["id"] != atk["id"]][:24]
    for i, t in enumerate(targets):
        events.append(_ev(at(0.0, i, 1.2), src, t["ip"], 443, "tcp", "conn_attempt", state="rejected"))
    # 2 port scan DB-02: 40 ports
    for i, port in enumerate(rng.sample(range(20, 9000), 40)):
        events.append(_ev(at(1.8, i, 0.4), src, db2["ip"], port, "tcp", "conn_attempt", state="rejected"))
    # 3 SSH brute force JUMP-01
    for i in range(60):
        events.append(_ev(at(3.2, i, 0.8), src, jump["ip"], 22, "ssh", "auth_failure", user=rng.choice(["root", "admin", "svc_backup", "deploy"])))
    # 4 compromise + lateral movement
    events.append(_ev(at(4.6, 0, 1), src, jump["ip"], 22, "ssh", "auth_success", user="svc_backup"))
    events.append(_ev(at(5.0, 0, 1), jump["ip"], app2["ip"], 22, "ssh", "auth_success", user="svc_backup"))
    events.append(_ev(at(5.2, 0, 1), src, db2["ip"], 22, "ssh", "auth_success", user="svc_backup"))
    events.append(_ev(at(5.3, 0, 1), src, app2["ip"], 22, "ssh", "auth_success", user="svc_backup"))
    # 5 DNS tunnelling-style lookups
    for i in range(45):
        label = "".join(rng.choices(string.ascii_lowercase + string.digits, k=28))
        events.append(_ev(at(5.8, i, 1.0), src, by["DNS-01"]["ip"], 53, "dns", "dns_query", sent=180, recv=90, domain=f"{label}.exfil-test.example"))
    # 6 exfiltration: 12 sessions x 100 MB
    for i in range(12):
        events.append(_ev(at(6.8, i, 6.0), src, EXTERNAL_C2, 443, "tls", "tls_session", sent=100_000_000, recv=4_000, domain="storage.exfil-test.example"))
    return sorted(events, key=lambda e: e["ts"])
