"""Evidence packages: the only thing the analyst is ever allowed to talk about.

Everything is read from stored records. ``ids`` is the closed set of identifiers an answer may cite;
the validator in ``answers.py`` rejects any citation outside it, so a model (or template) cannot
reference telemetry that does not exist.
"""

from dataclasses import dataclass, field

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import Alert, Device, Evidence, Incident, IncidentEvent, MITRETechnique


@dataclass
class StepEv:
    position: int
    stage: str
    alert_id: str
    ts: str
    source: str
    destination: str
    detector: str
    detection_class: str
    severity: str
    confidence: float
    explanation: str
    mitre: list[str]
    facts: dict
    event_ids: list[str]
    link_reason: str


@dataclass
class IncidentPackage:
    incident_id: str
    title: str
    status: str
    severity: str
    risk_score: int
    risk_factors: list[dict]
    summary: str
    first_seen: str
    last_seen: str
    steps: list[StepEv]
    supporting: list[dict]
    techniques: list[dict]
    ids: set[str] = field(default_factory=set)


@dataclass
class DevicePackage:
    device_id: str
    hostname: str
    ip: str
    role: str
    criticality: int
    risk_score: int
    risk_factors: list[dict]
    deviated_metrics: list[dict]
    alerts: list[dict]
    ids: set[str] = field(default_factory=set)


def build_incident_package(db: Session, incident_id: str) -> IncidentPackage | None:
    inc = db.get(Incident, incident_id)
    if inc is None:
        return None
    alerts = {a.id: a for a in db.scalars(select(Alert).where(Alert.incident_id == inc.id))}
    ev = db.scalars(select(Evidence).where(Evidence.alert_id.in_(list(alerts)))).all() if alerts else []
    events: dict[str, list[str]] = {}
    facts: dict[str, dict] = {}
    for e in ev:
        if e.kind == "facts":
            facts[e.alert_id] = e.data
        elif e.event_id:
            events.setdefault(e.alert_id, []).append(e.event_id)

    chain = db.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == inc.id).order_by(IncidentEvent.position)).all()
    steps, step_ids = [], set()
    for ie in chain:
        a = alerts.get(ie.alert_id or "")
        if a is None:
            continue
        step_ids.add(a.id)
        steps.append(StepEv(ie.position, ie.stage, a.id, a.ts.isoformat(), a.source, a.destination, a.detector, a.detection_class,
                            a.severity, a.confidence, a.explanation, list(a.mitre_techniques or []), facts.get(a.id, {}),
                            events.get(a.id, []), ie.link_reason))
    supporting = [{"id": a.id, "class": a.detection_class, "type": a.event_type, "severity": a.severity, "explanation": a.explanation, "source": a.source}
                  for a in alerts.values() if a.id not in step_ids]
    tech_ids = sorted({t for s in steps for t in s.mitre})
    techniques = [{"id": t.id, "name": t.name, "tactic": t.tactic}
                  for t in (db.scalars(select(MITRETechnique).where(MITRETechnique.id.in_(tech_ids))).all() if tech_ids else [])]

    pkg = IncidentPackage(inc.id, inc.title, inc.status, inc.severity, inc.risk_score, list(inc.risk_factors or []), inc.summary,
                          inc.first_seen.isoformat(), inc.last_seen.isoformat(), steps, supporting, techniques)
    pkg.ids = {inc.id, *alerts, *{e for v in events.values() for e in v}, *tech_ids}
    return pkg


def build_device_package(db: Session, device_id: str) -> DevicePackage | None:
    d = db.get(Device, device_id)
    if d is None:
        return None
    prof = d.profile
    deviated = []
    if prof:
        for k, base in prof.baseline.items():
            cur = prof.current.get(k)
            if cur is not None and cur > max(base["max"], 1) * 1.5:
                deviated.append({"metric": k, "current": cur, "baseline_max": base["max"]})
    related = db.scalars(select(Alert).where(or_(Alert.source == d.ip, Alert.destination.contains(d.ip))).order_by(Alert.ts)).all()
    alerts = [{"id": a.id, "type": a.event_type, "class": a.detection_class, "severity": a.severity, "role": "source" if a.source == d.ip else "target",
               "explanation": a.explanation, "incident_id": a.incident_id} for a in related]
    pkg = DevicePackage(d.id, d.hostname, d.ip, d.role, d.criticality, d.risk_score, list(d.risk_factors or []), deviated, alerts)
    pkg.ids = {d.id, *[a["id"] for a in alerts], *[a["incident_id"] for a in alerts if a["incident_id"]]}
    return pkg
