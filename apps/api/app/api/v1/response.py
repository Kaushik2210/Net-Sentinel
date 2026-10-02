from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from app.analyst.evidence import build_incident_package
from app.core.deps import Analyst, CurrentUser, DbSession, client_ip
from app.models import ResponseRecommendation
from app.response.engine import ACTIONS, SimulatedActuator, label_for, recommend
from app.schemas.common import ORM, UTCDatetime
from app.services import audit

router = APIRouter(prefix="/response", tags=["response"])
_actuator = SimulatedActuator()


class RecOut(ORM):
    id: str
    incident_id: str
    action: str
    label: str
    target: str
    rationale: str
    state: str
    created_at: UTCDatetime
    mode: str = "RECOMMENDATION ONLY"


class SimResult(ORM):
    recommendation: RecOut
    message: str
    real_changes_made: bool = False


def _out(r: ResponseRecommendation) -> RecOut:
    return RecOut(id=r.id, incident_id=r.incident_id, action=r.action, label=label_for(r.action), target=r.target, rationale=r.rationale, state=r.state, created_at=r.created_at)


@router.get("/incidents/{incident_id}", response_model=list[RecOut])
def for_incident(incident_id: str, _: CurrentUser, db: DbSession):
    """Recommendations for an incident (created on first view, then stable)."""
    pkg = build_incident_package(db, incident_id)
    if pkg is None:
        raise HTTPException(404, "Incident not found")
    existing = {(r.action, r.target): r for r in db.scalars(select(ResponseRecommendation).where(ResponseRecommendation.incident_id == incident_id))}
    for rec in recommend(pkg):
        if (rec.action, rec.target) not in existing:
            row = ResponseRecommendation(incident_id=incident_id, action=rec.action, target=rec.target[:128], rationale=rec.rationale[:512])
            db.add(row)
            existing[(rec.action, rec.target)] = row
    db.commit()
    return [_out(r) for r in sorted(existing.values(), key=lambda r: (list(ACTIONS).index(r.action), r.target))]


@router.post("/{rec_id}/simulate", response_model=SimResult)
def simulate(rec_id: str, request: Request, user: Analyst, db: DbSession):
    rec = db.get(ResponseRecommendation, rec_id)
    if rec is None:
        raise HTTPException(404, "Recommendation not found")
    message = _actuator.execute(rec.action, rec.target)
    rec.state = "simulated"
    db.commit()
    audit.record(db, user.username, "incident.response_simulated", rec.incident_id, client_ip(request), response_action=rec.action, response_target=rec.target, real=False)
    return SimResult(recommendation=_out(rec), message=message)
