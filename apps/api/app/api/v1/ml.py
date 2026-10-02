import asyncio
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from app.core.deps import CurrentUser, DbSession
from app.ml.service import get_model, is_warm, score_events
from app.models import Device, NetworkEvent
from app.schemas.common import ORM
from app.services.alerts import MAX_WINDOW_EVENTS, to_record

router = APIRouter(prefix="/analytics/ml", tags=["ml"])


class ModelInfo(ORM):
    algorithm: str
    features: list[str]
    training_windows: int
    parameters: dict
    decision_threshold: float
    training_median: float
    trained_on: str


class ContributionOut(ORM):
    feature: str
    label: str
    value: float
    baseline_mean: float
    z: float


class ScoreOut(ORM):
    entity: str
    hostname: str | None
    score: float
    risk: int
    is_anomaly: bool
    contributions: list[ContributionOut]
    classification: str = "ML ANOMALY SCORE"
    note: str = "Statistical outlier vs a benign baseline. Not an attack classification."


@router.get("/model", response_model=ModelInfo)
async def model_info(_: CurrentUser):
    return (await asyncio.to_thread(get_model)).describe()


@router.get("/scores", response_model=list[ScoreOut])
async def scores(_: CurrentUser, db: DbSession, ip: str | None = None):
    if not is_warm():
        if ip is not None:
            raise HTTPException(404, "ML warm-up: not enough live history yet")
        return []
    since = datetime.now(UTC) - timedelta(minutes=10)
    rows = db.scalars(select(NetworkEvent).where(NetworkEvent.ts >= since).limit(MAX_WINDOW_EVENTS)).all()
    results = await asyncio.to_thread(score_events, [to_record(r) for r in rows])
    names = {d.ip: d.hostname for d in db.scalars(select(Device))}
    out = [
        ScoreOut(
            entity=r.entity, hostname=names.get(r.entity), score=r.score, risk=r.risk, is_anomaly=r.is_anomaly,
            contributions=[c.__dict__ for c in r.contributions],
        )
        for r in results
    ]
    if ip is not None:
        out = [o for o in out if o.entity == ip]
        if not out:
            raise HTTPException(404, "No score: insufficient recent events for this address")
    return sorted(out, key=lambda o: -o.risk)
