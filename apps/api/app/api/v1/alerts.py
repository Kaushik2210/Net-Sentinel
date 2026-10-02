from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from app.core.deps import CurrentUser, DbSession
from app.models import Alert, Evidence
from app.schemas.common import ORM, Page, UTCDatetime

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertOut(ORM):
    id: str
    ts: UTCDatetime
    source: str
    destination: str
    event_type: str
    detection_class: str
    severity: str
    confidence: float
    detector: str
    mitre_techniques: list[str]
    explanation: str
    status: str
    incident_id: str | None


class EvidenceOut(ORM):
    id: str
    kind: str
    event_id: str | None
    summary: str
    data: dict


class AlertDetail(AlertOut):
    evidence: list[EvidenceOut]


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    _: CurrentUser,
    db: DbSession,
    severity: Annotated[str | None, Query(pattern="^(info|low|medium|high|critical)$")] = None,
    status: Annotated[str | None, Query(pattern="^(open|investigating|resolved|false_positive)$")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Alert.ts.desc()).limit(limit).offset(offset)).all()
    return Page(items=[AlertOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: str, _: CurrentUser, db: DbSession):
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, "Alert not found")
    evidence = db.scalars(select(Evidence).where(Evidence.alert_id == a.id)).all()
    return AlertDetail(**AlertOut.model_validate(a).model_dump(), evidence=[EvidenceOut.model_validate(e) for e in evidence])
