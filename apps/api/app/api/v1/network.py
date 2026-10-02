from fastapi import APIRouter
from sqlalchemy import select

from app.core.deps import CurrentUser, DbSession
from app.models import Connection, Device
from app.schemas.common import ORM, DeviceSummary

router = APIRouter(prefix="/network", tags=["network"])


class TopologyNode(DeviceSummary):
    position: dict
    connection_count: int


class TopologyEdge(ORM):
    id: str
    source: str
    target: str
    protocol: str
    port: int | None
    bytes_per_hour: int
    connections_per_hour: int
    suspicious: bool


class Topology(ORM):
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


@router.get("/topology", response_model=Topology)
def topology(_: CurrentUser, db: DbSession) -> Topology:
    devices = db.scalars(select(Device)).all()
    conns = db.scalars(select(Connection)).all()
    counts: dict[str, int] = {}
    for c in conns:
        counts[c.src_device_id] = counts.get(c.src_device_id, 0) + 1
        counts[c.dst_device_id] = counts.get(c.dst_device_id, 0) + 1
    nodes = [
        TopologyNode(
            **DeviceSummary.model_validate(d).model_dump(), position=d.position, connection_count=counts.get(d.id, 0)
        )
        for d in devices
    ]
    edges = [
        TopologyEdge(
            id=c.id, source=c.src_device_id, target=c.dst_device_id, protocol=c.protocol, port=c.port,
            bytes_per_hour=c.bytes_per_hour, connections_per_hour=c.connections_per_hour, suspicious=c.suspicious,
        )
        for c in conns
    ]
    return Topology(nodes=nodes, edges=edges)
