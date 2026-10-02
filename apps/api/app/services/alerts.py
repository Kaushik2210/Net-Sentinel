"""Glue between the pure detection engine and the database: windowing, dedupe, persistence."""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection import DetectionEngine, EventRecord, Finding, registry
from app.models import Alert, DetectionRule, Evidence, NetworkEvent
from app.services.bus import bus

log = logging.getLogger("netsentinel.detect")
DEDUPE_WINDOW = timedelta(minutes=15)
MAX_WINDOW_EVENTS = 20000


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def to_record(e: NetworkEvent) -> EventRecord:
    return EventRecord(
        id=e.id, ts=_aware(e.ts), src_ip=e.src_ip, dst_ip=e.dst_ip, dst_port=e.dst_port, protocol=e.protocol,
        event_type=e.event_type, bytes_sent=e.bytes_sent, bytes_received=e.bytes_received, attributes=e.attributes or {},
    )


def build_engine(db: Session) -> DetectionEngine:
    """Detectors honour the ``detection_rules`` table (enabled flag and parameter overrides)."""
    rules = {r.detector: r for r in db.scalars(select(DetectionRule))}
    detectors = []
    for name, cls in registry().items():
        rule = rules.get(name)
        if rule is not None and not rule.enabled:
            continue
        detectors.append(cls(**(rule.parameters if rule else {})))
    return DetectionEngine(detectors)


def _persist(db: Session, f: Finding) -> Alert:
    alert = Alert(
        ts=f.timestamp, source=f.source, destination=f.destination, event_type=f.event_type, detection_class=f.detection_class,
        severity=f.severity, confidence=f.confidence, detector=f.detector, mitre_techniques=f.mitre_techniques,
        explanation=f.explanation[:512],
    )
    db.add(alert)
    db.flush()
    db.add(Evidence(alert_id=alert.id, kind="facts", summary=f.explanation[:512], data=f.facts))
    for eid in f.evidence_ids[:20]:
        db.add(Evidence(alert_id=alert.id, event_id=eid, kind="event", summary=f"supporting event {eid}"))
    return alert


def alert_payload(a: Alert) -> dict:
    return {
        "id": a.id, "ts": _aware(a.ts).isoformat(), "source": a.source, "destination": a.destination,
        "event_type": a.event_type, "detection_class": a.detection_class, "severity": a.severity,
        "confidence": a.confidence, "detector": a.detector, "mitre_techniques": a.mitre_techniques,
        "explanation": a.explanation, "status": a.status, "incident_id": a.incident_id,
    }


def run_detection_cycle(db: Session, window_seconds: int = 600) -> list[Alert]:
    """Detect over the recent window; persist only findings not already alerted recently."""
    since = datetime.now(UTC) - timedelta(seconds=window_seconds)
    rows = db.scalars(
        select(NetworkEvent).where(NetworkEvent.ts >= since).order_by(NetworkEvent.ts.desc()).limit(MAX_WINDOW_EVENTS)
    ).all()
    findings = build_engine(db).run([to_record(r) for r in rows])
    if not findings:
        return []

    recent = db.scalars(select(Alert).where(Alert.created_at >= datetime.now(UTC) - DEDUPE_WINDOW)).all()
    seen = {(a.detector, a.source, a.event_type) for a in recent}
    created: list[Alert] = []
    for f in findings:
        key = (f.detector, f.source, f.event_type)
        if key in seen:
            continue
        seen.add(key)
        created.append(_persist(db, f))
    db.commit()
    for a in created:
        bus.publish({"type": "alert", "data": alert_payload(a)})
        log.info("alert %s %s %s -> %s (conf %.2f)", a.id, a.severity, a.source, a.destination, a.confidence)
    return created
