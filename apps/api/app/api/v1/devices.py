from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, or_, select

from app.core.deps import CurrentUser, DbSession
from app.models import BehaviorProfile, Connection, Device, NetworkEvent
from app.schemas.common import ORM, DeviceSummary, EventOut, Factor, Page
from app.services.behavior import METRICS, deviation_score, severity_for_risk

router = APIRouter(prefix="/devices", tags=["devices"])


class MetricView(ORM):
    key: str
    label: str
    baseline_min: float
    baseline_max: float
    current: float
    deviated: bool


class Neighbor(ORM):
    id: str
    hostname: str
    ip: str
    direction: str
    protocol: str
    port: int | None
    bytes_per_hour: int
    suspicious: bool


class DeviceDetail(DeviceSummary):
    mac: str
    os: str
    open_ports: list[int]
    protocols: list[str]
    risk_severity: str
    risk_factors: list[Factor]
    deviation_score: int
    metrics: list[MetricView]
    connections: list[Neighbor]
    recent_events: list[EventOut]
    connection_count: int


@router.get("", response_model=Page[DeviceSummary])
def list_devices(
    _: CurrentUser,
    db: DbSession,
    q: Annotated[str | None, Query(max_length=64)] = None,
    device_type: Annotated[str | None, Query(max_length=24)] = None,
    min_risk: Annotated[int, Query(ge=0, le=100)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    stmt = select(Device).where(Device.risk_score >= min_risk)
    if device_type:
        stmt = stmt.where(Device.device_type == device_type)
    if q:
        stmt = stmt.where(or_(func.lower(Device.hostname).like(f"%{q.lower()}%"), Device.ip.like(f"%{q}%")))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Device.risk_score.desc(), Device.hostname).limit(limit).offset(offset)).all()
    return Page(items=[DeviceSummary.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{device_id}", response_model=DeviceDetail)
def get_device(device_id: str, _: CurrentUser, db: DbSession):
    dev = db.get(Device, device_id)
    if dev is None:
        raise HTTPException(404, "Device not found")
    prof: BehaviorProfile | None = dev.profile
    baseline = prof.baseline if prof else {}
    current = prof.current if prof else {}

    metrics = [
        MetricView(
            key=k,
            label=label,
            baseline_min=baseline[k].get("min", 0),
            baseline_max=baseline[k]["max"],
            current=current[k],
            deviated=current[k] > max(baseline[k]["max"], 1) * 1.5,
        )
        for k, (label, _cap) in METRICS.items()
        if k in baseline and k in current
    ]

    conns = db.scalars(
        select(Connection).where(or_(Connection.src_device_id == dev.id, Connection.dst_device_id == dev.id))
    ).all()
    other_ids = {c.dst_device_id if c.src_device_id == dev.id else c.src_device_id for c in conns}
    others = {d.id: d for d in db.scalars(select(Device).where(Device.id.in_(other_ids)))} if other_ids else {}
    neighbors = []
    for c in conns:
        outbound = c.src_device_id == dev.id
        o = others[c.dst_device_id if outbound else c.src_device_id]
        neighbors.append(
            Neighbor(
                id=o.id, hostname=o.hostname, ip=o.ip, direction="outbound" if outbound else "inbound",
                protocol=c.protocol, port=c.port, bytes_per_hour=c.bytes_per_hour, suspicious=c.suspicious,
            )
        )
    neighbors.sort(key=lambda n: (not n.suspicious, -n.bytes_per_hour))

    events = db.scalars(
        select(NetworkEvent)
        .where(or_(NetworkEvent.src_ip == dev.ip, NetworkEvent.dst_ip == dev.ip))
        .order_by(NetworkEvent.ts.desc())
        .limit(15)
    ).all()

    return DeviceDetail(
        **DeviceSummary.model_validate(dev).model_dump(),
        mac=dev.mac,
        os=dev.os,
        open_ports=dev.open_ports,
        protocols=dev.protocols,
        risk_severity=severity_for_risk(dev.risk_score),
        risk_factors=dev.risk_factors,
        deviation_score=deviation_score(baseline, current) if prof else 0,
        metrics=metrics,
        connections=neighbors,
        recent_events=[EventOut.model_validate(e) for e in events],
        connection_count=len(conns),
    )
