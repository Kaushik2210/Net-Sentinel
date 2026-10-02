"""One-off: populate a read-only instance with a demonstration incident and replay, with no login.

    docker compose ... exec api python -m app.tools.seed_demo

Runs the same labelled attack simulation and synthetic PCAP replay the UI uses, directly against the database, so a
deployment that only publishes a VIEWER account still has incidents, MITRE mappings and a replay to look at.
Idempotent: does nothing if incidents or replays already exist. Requires TELEMETRY_MODE=simulation.
"""

import sys
from datetime import UTC, datetime

from sqlalchemy import func, select

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.ingest.pcap import parse_pcap
from app.ingest.sample import SAMPLE_OVERRIDES, build_sample_pcap
from app.models import Device, Incident, NetworkEvent, ReplaySession
from app.replay.engine import build_replay
from app.services import audit
from app.services.alerts import run_detection_cycle
from app.services.scenarios import generate_attack


def main() -> int:
    if get_settings().telemetry_mode != "simulation":
        print("TELEMETRY_MODE must be 'simulation' to seed demonstration data", file=sys.stderr)
        return 1
    with SessionLocal() as db:
        if db.scalar(select(func.count()).select_from(Incident)) or db.scalar(select(func.count()).select_from(ReplaySession)):
            print("demo data already present; nothing to do")
            return 0
        devices = [{"id": d.id, "hostname": d.hostname, "ip": d.ip, "device_type": d.device_type} for d in db.scalars(select(Device))]
        if not devices:
            print("no devices yet: start the API once first so it can seed the simulated network", file=sys.stderr)
            return 1
        db.add_all(NetworkEvent(**e) for e in generate_attack(devices, datetime.now(UTC)))
        db.commit()
        alerts = run_detection_cycle(db, 900)
        data = build_sample_pcap()
        events, stats = parse_pcap(data)
        result = build_replay(events, SAMPLE_OVERRIDES)
        result["ingest"] = {"packets": stats.packets, "ipv4_packets": stats.ipv4, "flows": stats.flows, "events": len(events), "dns_queries": stats.dns_queries,
                            "skipped_non_ip": stats.skipped_non_ip, "skipped_other_l4": stats.skipped_other_l4, "truncated": stats.truncated, "notes": stats.notes,
                            "source_format": "pcap", "heuristics": "Authentication outcomes on SSH/RDP/SMB/WinRM are inferred from flow shape (payloads are encrypted)."}
        import hashlib

        db.add(ReplaySession(filename="synthetic-attack-sample.pcap", sha256=hashlib.sha256(data).hexdigest(), status="complete", packet_count=stats.packets, result=result))
        db.commit()
        audit.record(db, "system", "demo.seed", "", "", alerts=len(alerts))
        print(f"seeded demonstration data: {len(alerts)} alerts, 1 incident, 1 replay")
    return 0


if __name__ == "__main__":
    sys.exit(main())
