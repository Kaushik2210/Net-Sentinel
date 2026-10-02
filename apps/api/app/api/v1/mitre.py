from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from app.core.deps import CurrentUser, DbSession
from app.models import Alert, Evidence, IncidentEvent, MITRETechnique
from app.schemas.common import ORM, UTCDatetime

router = APIRouter(prefix="/mitre", tags=["mitre"])

# Matrix column order (ATT&CK Enterprise).
TACTIC_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]
LOOKBACK = timedelta(days=7)


class TechniqueCell(ORM):
    id: str
    name: str
    description: str
    observed: bool
    alert_count: int
    max_confidence: float | None
    mean_confidence: float | None
    first_seen: UTCDatetime | None


class Tactic(ORM):
    name: str
    techniques: list[TechniqueCell]


class Matrix(ORM):
    tactics: list[Tactic]
    observed_techniques: int
    total_techniques: int


class RelatedAlert(ORM):
    id: str
    ts: UTCDatetime
    detector: str
    detection_class: str
    severity: str
    confidence: float
    explanation: str
    source: str
    destination: str
    incident_id: str | None
    chain_position: int | None
    chain_length: int | None
    stage: str | None


class TechniqueDetail(TechniqueCell):
    tactic: str
    alerts: list[RelatedAlert]
    evidence_event_ids: list[str]


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def _observed(db) -> dict[str, list[Alert]]:
    """technique id -> alerts that reference it (alerts store their techniques as JSON)."""
    since = datetime.now(UTC) - LOOKBACK
    out: dict[str, list[Alert]] = {}
    for a in db.scalars(select(Alert).where(Alert.ts >= since)):
        for t in a.mitre_techniques or []:
            out.setdefault(t, []).append(a)
    return out


def _cell(t: MITRETechnique, alerts: list[Alert]) -> TechniqueCell:
    conf = [a.confidence for a in alerts]
    return TechniqueCell(
        id=t.id, name=t.name, description=t.description, observed=bool(alerts), alert_count=len(alerts),
        max_confidence=max(conf) if conf else None, mean_confidence=round(sum(conf) / len(conf), 2) if conf else None,
        first_seen=min(_aware(a.ts) for a in alerts) if alerts else None,
    )


@router.get("", response_model=Matrix)
def matrix(_: CurrentUser, db: DbSession):
    techniques = db.scalars(select(MITRETechnique).order_by(MITRETechnique.id)).all()
    observed = _observed(db)
    by_tactic: dict[str, list[TechniqueCell]] = {}
    for t in techniques:
        by_tactic.setdefault(t.tactic, []).append(_cell(t, observed.get(t.id, [])))
    tactics = [Tactic(name=n, techniques=by_tactic.get(n, [])) for n in TACTIC_ORDER if n in by_tactic]
    return Matrix(tactics=tactics, observed_techniques=sum(1 for t in techniques if t.id in observed), total_techniques=len(techniques))


@router.get("/{technique_id}", response_model=TechniqueDetail)
def technique(technique_id: str, _: CurrentUser, db: DbSession):
    t = db.get(MITRETechnique, technique_id)
    if t is None:
        raise HTTPException(404, "Technique not found")
    alerts = sorted(_observed(db).get(t.id, []), key=lambda a: a.ts)
    chain_len = {}
    pos = {}
    for iid in {a.incident_id for a in alerts if a.incident_id}:
        steps = db.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == iid)).all()
        chain_len[iid] = len(steps)
        for s in steps:
            pos[s.alert_id] = (s.position + 1, s.stage)
    event_ids = (
        [e for (e,) in db.execute(select(Evidence.event_id).where(Evidence.alert_id.in_([a.id for a in alerts]), Evidence.event_id.is_not(None)))]
        if alerts else []
    )
    related = [
        RelatedAlert(
            id=a.id, ts=a.ts, detector=a.detector, detection_class=a.detection_class, severity=a.severity, confidence=a.confidence,
            explanation=a.explanation, source=a.source, destination=a.destination, incident_id=a.incident_id,
            chain_position=pos.get(a.id, (None, None))[0], chain_length=chain_len.get(a.incident_id or ""),
            stage=pos.get(a.id, (None, None))[1],
        )
        for a in alerts
    ]
    return TechniqueDetail(**_cell(t, alerts).model_dump(), tactic=t.tactic, alerts=related, evidence_event_ids=event_ids[:200])

