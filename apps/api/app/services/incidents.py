"""Persist correlation output. Incident IDs stay stable as new alerts arrive (so analyst notes
and links are not orphaned): an existing incident is reused and updated; incidents that end up
sharing alerts are merged into the oldest one."""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.correlation import AlertLite, IncidentDraft, correlate
from app.models import Alert, Device, Incident, IncidentEvent, InvestigationNote
from app.services.bus import bus
from app.services.risk import incident_risk, incident_severity

log = logging.getLogger("netsentinel.detect")
LOOKBACK = timedelta(hours=24)


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def to_lite(a: Alert) -> AlertLite:
    return AlertLite(
        id=a.id, ts=_aware(a.ts), source=a.source, destination=a.destination, event_type=a.event_type,
        detection_class=a.detection_class, severity=a.severity, confidence=a.confidence, detector=a.detector,
        mitre=tuple(a.mitre_techniques or ()),
    )


def _title(draft: IncidentDraft, hosts: dict[str, Device]) -> str:
    src = draft.steps[0].alert.source
    name = hosts[src].hostname if src in hosts else src
    first, last = draft.steps[0].stage, draft.steps[-1].stage
    return f"{first} to {last} from {name}"[:160]


def _summary(draft: IncidentDraft) -> str:
    stages = list(dict.fromkeys(s.stage for s in draft.steps))
    return (
        f"{len(draft.steps)} correlated alerts across {len(stages)} stages ({' > '.join(stages)})."
        + (f" {len(draft.supporting)} supporting behavioral/ML signal(s)." if draft.supporting else "")
    )[:1024]


def _apply(db: Session, draft: IncidentDraft, hosts: dict[str, Device]) -> tuple[Incident, bool]:
    ids = draft.alert_ids
    existing = db.scalars(
        select(Incident).join(Alert, Alert.incident_id == Incident.id).where(Alert.id.in_(ids)).order_by(Incident.created_at)
    ).unique().all()
    created = not existing
    inc = existing[0] if existing else Incident(title="", severity="low")
    for other in existing[1:]:  # merge: keep notes, move alerts, drop the duplicate
        db.execute(update(Alert).where(Alert.incident_id == other.id).values(incident_id=inc.id))
        db.execute(update(InvestigationNote).where(InvestigationNote.incident_id == other.id).values(incident_id=inc.id))
        db.delete(other)
    if created:
        db.add(inc)
        db.flush()

    internal = [hosts[ip] for ip in draft.entities if ip in hosts]
    risk, factors = incident_risk(draft, max((d.criticality for d in internal), default=1))
    inc.title = _title(draft, hosts)
    inc.summary = _summary(draft)
    inc.risk_score, inc.risk_factors, inc.severity = risk, factors, incident_severity(risk)
    inc.first_seen = min(s.alert.ts for s in draft.steps)
    inc.last_seen = max(s.alert.ts for s in draft.steps)

    db.execute(delete(IncidentEvent).where(IncidentEvent.incident_id == inc.id))
    db.flush()
    for s in draft.steps:
        db.add(IncidentEvent(incident_id=inc.id, alert_id=s.alert.id, position=s.position, stage=s.stage,
                             link_reason=s.link_reason, link_confidence=s.link_confidence))
    db.execute(update(Alert).where(Alert.id.in_(ids)).values(incident_id=inc.id))
    return inc, created


def run_correlation(db: Session) -> list[Incident]:
    since = datetime.now(UTC) - LOOKBACK
    alerts = db.scalars(select(Alert).where(Alert.ts >= since)).all()
    drafts = correlate([to_lite(a) for a in alerts])
    if not drafts:
        return []
    hosts = {d.ip: d for d in db.scalars(select(Device))}
    out: list[Incident] = []
    for draft in drafts:
        inc, created = _apply(db, draft, hosts)
        out.append(inc)
        db.flush()
        if created:
            log.info("incident %s created: %s (risk %d)", inc.id, inc.title, inc.risk_score)
    db.commit()
    for inc in out:
        bus.publish({"type": "incident", "data": {"id": inc.id, "title": inc.title, "severity": inc.severity, "risk_score": inc.risk_score}})
    return out
