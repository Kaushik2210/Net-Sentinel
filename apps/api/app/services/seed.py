"""Idempotent bootstrap data: dev users, the simulated network, and its baselines."""

import json
import logging
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import Role, hash_password
from app.detection import registry
from app.models import BehaviorProfile, Connection, DetectionRule, Device, MITRETechnique, User
from app.services import topology
from app.services.behavior import score_device

log = logging.getLogger("netsentinel.seed")


def seed_users(db: Session) -> None:
    s = get_settings()
    wanted = [
        ("admin", "Administrator", Role.ADMIN, s.seed_admin_password),
        ("analyst", "SOC Analyst", Role.ANALYST, s.seed_analyst_password),
        ("viewer", "Read-only Viewer", Role.VIEWER, s.seed_viewer_password),
    ]
    for username, name, role, password in wanted:
        if not password:
            log.warning("no SEED_%s_PASSWORD set; skipping user '%s'", username.upper(), username)
            continue
        if db.scalar(select(User).where(User.username == username)):
            continue
        db.add(User(username=username, display_name=name, role=role.value, password_hash=hash_password(password)))
    db.commit()


def refresh_layout(db: Session) -> None:
    """Keep stored topology coordinates in sync with the layout algorithm (cheap, idempotent)."""
    specs = topology.build_devices(get_settings().simulation_seed)
    topology.layout(specs)
    pos = {sp.hostname: sp.position for sp in specs}
    changed = False
    for dev in db.scalars(select(Device)):
        if dev.hostname in pos and dev.position != pos[dev.hostname]:
            dev.position = pos[dev.hostname]
            changed = True
    if changed:
        db.commit()


def seed_network(db: Session) -> int:
    """Create the simulated network once. Returns the number of devices created."""
    if db.scalar(select(func.count()).select_from(Device)):
        refresh_layout(db)
        return 0
    seed = get_settings().simulation_seed
    specs = topology.build_devices(seed)
    topology.layout(specs)
    now = datetime.now(UTC)

    by_host: dict[str, Device] = {}
    for sp in specs:
        risk, factors = score_device(sp.baseline, sp.current, sp.criticality)
        dev = Device(
            hostname=sp.hostname, ip=sp.ip, mac=sp.mac, device_type=sp.device_type, role=sp.role,
            os=sp.os, zone=sp.zone, criticality=sp.criticality, open_ports=sp.ports,
            protocols=sp.protocols, risk_score=risk, risk_factors=factors, position=sp.position,
            last_seen=now - timedelta(seconds=zlib.crc32(sp.hostname.encode()) % 40),
            status="online",
        )
        dev.profile = BehaviorProfile(baseline=sp.baseline, current=sp.current, history=[])
        db.add(dev)
        by_host[sp.hostname] = dev
    db.flush()

    for e in topology.build_edges(specs, seed):
        db.add(Connection(
            src_device_id=by_host[e["src"]].id, dst_device_id=by_host[e["dst"]].id,
            protocol=e["protocol"], port=e["port"], bytes_per_hour=e["bytes_per_hour"],
            connections_per_hour=e["connections_per_hour"], suspicious=e["suspicious"],
        ))
    db.commit()
    log.info("seeded %d simulated devices", len(specs))
    return len(specs)


def seed_detection(db: Session) -> None:
    """One DetectionRule row per registered detector, plus the MITRE technique catalogue."""
    existing = {r.detector for r in db.scalars(select(DetectionRule))}
    for name, cls in registry().items():
        if name not in existing:
            db.add(DetectionRule(name=name, detector=name, enabled=True, parameters={}, description=(cls.__doc__ or "").strip()[:500]))
    known = {t.id for t in db.scalars(select(MITRETechnique))}
    for t in json.loads((Path(__file__).resolve().parent.parent / "data" / "mitre.json").read_text(encoding="utf-8")):
        if t["id"] not in known:
            db.add(MITRETechnique(**t))
    db.commit()
