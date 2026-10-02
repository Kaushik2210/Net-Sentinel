from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.core.deps import Admin, Analyst, CurrentUser, DbSession, client_ip
from app.detection.base import is_internal
from app.intel.providers import IndicatorError, normalize, providers
from app.models import Alert, NetworkEvent, ThreatIndicator
from app.schemas.common import ORM, Page, UTCDatetime
from app.services import audit

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])
Kind = Literal["ip", "domain", "hash", "url"]
LOOKBACK = timedelta(hours=24)


class IndicatorIn(BaseModel):
    kind: Kind
    value: Annotated[str, Field(min_length=1, max_length=512)]
    source: Annotated[str, Field(max_length=48)] = "manual"
    confidence: Annotated[int, Field(ge=0, le=100)] = 50
    description: Annotated[str, Field(max_length=512)] = ""


class IndicatorOut(ORM):
    id: str
    kind: str
    value: str
    source: str
    confidence: int
    description: str
    created_at: UTCDatetime


class CheckIn(BaseModel):
    kind: Kind
    value: Annotated[str, Field(min_length=1, max_length=512)]


class HitOut(ORM):
    kind: str
    value: str
    source: str
    confidence: int
    description: str


class CheckOut(ORM):
    value: str
    matched: bool
    providers_checked: list[str]
    hits: list[HitOut]


class MatchOut(ORM):
    indicator_id: str
    kind: str
    value: str
    source: str
    confidence: int
    where: str
    alert_ids: list[str]
    event_ids: list[str]


@router.get("", response_model=Page[IndicatorOut])
def list_indicators(
    _: CurrentUser, db: DbSession, kind: Kind | None = None, q: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50, offset: Annotated[int, Query(ge=0)] = 0,
):
    stmt = select(ThreatIndicator)
    if kind:
        stmt = stmt.where(ThreatIndicator.kind == kind)
    if q:
        stmt = stmt.where(ThreatIndicator.value.contains(q.lower()))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(ThreatIndicator.created_at.desc()).limit(limit).offset(offset)).all()
    return Page(items=[IndicatorOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.post("", response_model=IndicatorOut, status_code=201)
def add_indicator(body: IndicatorIn, request: Request, user: Analyst, db: DbSession):
    try:
        value = normalize(body.kind, body.value)
    except IndicatorError as exc:
        raise HTTPException(422, str(exc)) from exc
    ind = ThreatIndicator(kind=body.kind, value=value, source=body.source or "manual", confidence=body.confidence, description=body.description)
    db.add(ind)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Indicator already exists") from None
    audit.record(db, user.username, "intel.add", ind.id, client_ip(request), kind=body.kind)
    return IndicatorOut.model_validate(ind)


@router.delete("/{indicator_id}", status_code=204)
def delete_indicator(indicator_id: str, request: Request, user: Admin, db: DbSession):
    ind = db.get(ThreatIndicator, indicator_id)
    if ind is None:
        raise HTTPException(404, "Indicator not found")
    db.delete(ind)
    db.commit()
    audit.record(db, user.username, "intel.delete", indicator_id, client_ip(request))


@router.post("/check", response_model=CheckOut)
def check(body: CheckIn, _: CurrentUser, db: DbSession):
    try:
        value = normalize(body.kind, body.value)
    except IndicatorError as exc:
        raise HTTPException(422, str(exc)) from exc
    ps = providers(db)
    hits = [h for p in ps for h in p.lookup(body.kind, value)]
    return CheckOut(value=value, matched=bool(hits), providers_checked=[p.name for p in ps], hits=[HitOut(**h.__dict__) for h in hits])


@router.get("/matches", response_model=list[MatchOut])
def matches(_: CurrentUser, db: DbSession):
    """Where known indicators appear in recent telemetry. Absence of a match says nothing about safety."""
    inds = db.scalars(select(ThreatIndicator).where(ThreatIndicator.kind.in_(["ip", "domain"]))).all()
    if not inds:
        return []
    since = datetime.now(UTC) - LOOKBACK
    alerts = db.scalars(select(Alert).where(Alert.ts >= since)).all()
    events = db.scalars(select(NetworkEvent).where(NetworkEvent.ts >= since).order_by(NetworkEvent.ts.desc()).limit(20000)).all()
    out = []
    for ind in inds:
        a_ids = [a.id for a in alerts if ind.kind == "ip" and (ind.value == a.source or ind.value in a.destination) or (ind.kind == "domain" and ind.value in a.explanation.lower())]
        if ind.kind == "ip":
            e_ids = [e.id for e in events if ind.value in (e.src_ip, e.dst_ip) and not (is_internal(ind.value))][:50]
        else:
            e_ids = [e.id for e in events if str((e.attributes or {}).get("domain", "")).lower().rstrip(".").endswith(ind.value)][:50]
        if a_ids or e_ids:
            out.append(MatchOut(indicator_id=ind.id, kind=ind.kind, value=ind.value, source=ind.source, confidence=ind.confidence,
                                where="alerts and events" if a_ids and e_ids else "alerts" if a_ids else "events", alert_ids=a_ids[:50], event_ids=e_ids))
    return out
