import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import delete, select

from app.api.v1.alerts import AlertOut
from app.core.config import get_settings
from app.core.deps import Admin, Analyst, CurrentUser, DbSession, client_ip
from app.detection import registry
from app.models import Alert, DetectionRule, Device, Evidence, NetworkEvent
from app.schemas.common import ORM
from app.services import audit
from app.services.alerts import run_detection_cycle
from app.services.scenarios import SOURCE, generate_attack

router = APIRouter(prefix="/detections", tags=["detections"])


class DetectorOut(ORM):
    name: str
    detection_class: str
    mitre: list[str]
    enabled: bool
    parameters: dict


class SimulationResult(ORM):
    events_injected: int
    alerts_created: list[AlertOut]


class EnabledPatch(ORM):
    enabled: bool


@router.get("", response_model=list[DetectorOut])
def list_detectors(_: CurrentUser, db: DbSession):
    rules = {r.detector: r for r in db.scalars(select(DetectionRule))}
    out = []
    for name, cls in registry().items():
        r = rules.get(name)
        params = {**cls.defaults(), **(r.parameters if r else {})}
        out.append(DetectorOut(name=name, detection_class=cls.detection_class, mitre=list(cls.mitre),
                               enabled=r.enabled if r else True, parameters={k: v for k, v in params.items() if k != "rules"}))
    return out


@router.patch("/{name}", response_model=DetectorOut)
def set_enabled(name: str, body: EnabledPatch, request: Request, user: Admin, db: DbSession):
    if name not in registry():
        raise HTTPException(404, "Unknown detector")
    rule = db.scalar(select(DetectionRule).where(DetectionRule.detector == name))
    if rule is None:
        raise HTTPException(404, "Detector rule not seeded")
    rule.enabled = body.enabled
    db.commit()
    audit.record(db, user.username, "detector.toggle", name, client_ip(request), enabled=body.enabled)
    cls = registry()[name]
    return DetectorOut(name=name, detection_class=cls.detection_class, mitre=list(cls.mitre), enabled=rule.enabled, parameters=cls.defaults())


@router.post("/simulate-attack", response_model=SimulationResult)
async def simulate_attack(request: Request, user: Analyst, db: DbSession):
    """Inject a clearly labelled synthetic attack (source=sim-attack) and run detection on it."""
    if get_settings().telemetry_mode != "simulation":
        raise HTTPException(409, "Attack simulation is only available in simulation mode")
    devices = [{"id": d.id, "hostname": d.hostname, "ip": d.ip, "device_type": d.device_type} for d in db.scalars(select(Device))]
    events = generate_attack(devices, datetime.now(UTC))
    db.add_all(NetworkEvent(**e) for e in events)
    db.commit()
    created = await asyncio.to_thread(run_detection_cycle, db, 900)
    audit.record(db, user.username, "simulation.attack", f"{len(events)} events", client_ip(request), alerts=len(created))
    return SimulationResult(events_injected=len(events), alerts_created=[AlertOut.model_validate(a) for a in created])


@router.post("/reset-simulation", status_code=204)
def reset_simulation(request: Request, user: Admin, db: DbSession):
    """Remove injected attack telemetry and every alert (so demos can be repeated)."""
    db.execute(delete(Evidence))
    db.execute(delete(Alert))
    db.execute(delete(NetworkEvent).where(NetworkEvent.source == SOURCE))
    db.commit()
    audit.record(db, user.username, "simulation.reset", "", client_ip(request))
