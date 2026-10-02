import asyncio
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func, select

from app.core.deps import Analyst, CurrentUser, DbSession, client_ip
from app.models import Alert, Evidence, Incident, IncidentEvent, MITRETechnique, User
from app.schemas.common import ORM, Factor, Page, UTCDatetime
from app.services import audit
from app.services.incidents import run_correlation

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentSummary(ORM):
    id: str
    title: str
    status: str
    severity: str
    risk_score: int
    first_seen: UTCDatetime
    last_seen: UTCDatetime
    summary: str
    classification: str = "CORRELATED"
    assignee: str | None = None


class StepOut(ORM):
    position: int
    stage: str
    alert_id: str | None
    timestamp: UTCDatetime
    source: str
    destination: str
    detector: str
    detection_class: str
    severity: str
    confidence: float
    explanation: str
    mitre: list[str]
    evidence_event_ids: list[str]
    facts: dict
    link_reason: str
    link_confidence: float


class SupportingOut(ORM):
    id: str
    detection_class: str
    event_type: str
    severity: str
    confidence: float
    explanation: str
    source: str


class TechniqueOut(ORM):
    id: str
    name: str
    tactic: str
    description: str


class IncidentDetail(IncidentSummary):
    risk_factors: list[Factor]
    steps: list[StepOut]
    supporting: list[SupportingOut]
    techniques: list[TechniqueOut]
    evidence_count: int


def _summaries(db, rows) -> list["IncidentSummary"]:
    names = {u.id: u.username for u in db.scalars(select(User).where(User.id.in_([r.assignee_id for r in rows if r.assignee_id])))} if rows else {}
    return [IncidentSummary.model_validate(r).model_copy(update={"assignee": names.get(r.assignee_id)}) for r in rows]


@router.get("", response_model=Page[IncidentSummary])
def list_incidents(
    _: CurrentUser,
    db: DbSession,
    status: Annotated[str | None, Query(pattern="^(open|investigating|resolved|false_positive|escalated)$")] = None,
    severity: Annotated[str | None, Query(pattern="^(info|low|medium|high|critical)$")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    stmt = select(Incident)
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Incident.risk_score.desc(), Incident.last_seen.desc()).limit(limit).offset(offset)).all()
    return Page(items=_summaries(db, rows), total=total, limit=limit, offset=offset)


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, _: CurrentUser, db: DbSession):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "Incident not found")
    chain = db.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == inc.id).order_by(IncidentEvent.position)).all()
    alerts = {a.id: a for a in db.scalars(select(Alert).where(Alert.incident_id == inc.id))}
    evidence = db.scalars(select(Evidence).where(Evidence.alert_id.in_(list(alerts)))).all() if alerts else []
    events_by_alert: dict[str, list[str]] = {}
    facts_by_alert: dict[str, dict] = {}
    for e in evidence:
        if e.kind == "facts":
            facts_by_alert[e.alert_id] = e.data
        elif e.event_id:
            events_by_alert.setdefault(e.alert_id, []).append(e.event_id)

    steps, step_alert_ids = [], set()
    for ie in chain:
        a = alerts.get(ie.alert_id or "")
        if a is None:
            continue
        step_alert_ids.add(a.id)
        steps.append(StepOut(
            position=ie.position, stage=ie.stage, alert_id=a.id, timestamp=a.ts, source=a.source, destination=a.destination,
            detector=a.detector, detection_class=a.detection_class, severity=a.severity, confidence=a.confidence,
            explanation=a.explanation, mitre=a.mitre_techniques, evidence_event_ids=events_by_alert.get(a.id, []),
            facts=facts_by_alert.get(a.id, {}), link_reason=ie.link_reason, link_confidence=ie.link_confidence,
        ))
    supporting = [SupportingOut.model_validate(a) for a in alerts.values() if a.id not in step_alert_ids]
    ids = sorted({t for s in steps for t in s.mitre})
    techniques = db.scalars(select(MITRETechnique).where(MITRETechnique.id.in_(ids))).all() if ids else []
    return IncidentDetail(
        **_summaries(db, [inc])[0].model_dump(), risk_factors=inc.risk_factors, steps=steps, supporting=supporting,
        techniques=[TechniqueOut.model_validate(t) for t in techniques],
        evidence_count=sum(len(v) for v in events_by_alert.values()),
    )


@router.post("/correlate", response_model=list[IncidentSummary])
async def correlate_now(request: Request, user: Analyst, db: DbSession):
    created = await asyncio.to_thread(run_correlation, db)
    audit.record(db, user.username, "incidents.correlate", "", client_ip(request), incidents=len(created))
    return _summaries(db, created)
