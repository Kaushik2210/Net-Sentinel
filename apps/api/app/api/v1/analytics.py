from datetime import UTC, datetime, timedelta

from fastapi import APIRouter
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.deps import CurrentUser, DbSession
from app.models import Alert, Connection, Device, NetworkEvent
from app.schemas.common import ORM

router = APIRouter(prefix="/analytics", tags=["analytics"])


class Summary(ORM):
    mode: str
    data_source: str
    active_devices: int
    active_connections: int
    events_per_min: int
    anomalous_devices: int
    high_risk_devices: int
    critical_alerts: int
    external_connections: int
    generated_at: datetime


def _count(db, stmt) -> int:
    return db.scalar(stmt) or 0


@router.get("/summary", response_model=Summary)
def summary(_: CurrentUser, db: DbSession) -> Summary:
    s = get_settings()
    now = datetime.now(UTC)
    internet_ids = select(Device.id).where(Device.device_type == "internet")
    simulated = s.telemetry_mode == "simulation"
    return Summary(
        mode="SIMULATION" if simulated else "IDLE",
        data_source="synthetic telemetry" if simulated else "none",
        active_devices=_count(
            db,
            select(func.count()).select_from(Device).where(Device.status == "online", Device.device_type != "internet"),
        ),
        active_connections=_count(db, select(func.count()).select_from(Connection)),
        events_per_min=_count(
            db, select(func.count()).select_from(NetworkEvent).where(NetworkEvent.ts >= now - timedelta(minutes=1))
        ),
        # "Anomalous" = scoring found at least one deviated metric (risk >= 25); see services/behavior.py.
        anomalous_devices=_count(db, select(func.count()).select_from(Device).where(Device.risk_score >= 25)),
        high_risk_devices=_count(db, select(func.count()).select_from(Device).where(Device.risk_score >= 50)),
        critical_alerts=_count(
            db, select(func.count()).select_from(Alert).where(Alert.severity == "critical", Alert.status == "open")
        ),
        external_connections=_count(
            db,
            select(func.count())
            .select_from(Connection)
            .where(Connection.src_device_id.in_(internet_ids) | Connection.dst_device_id.in_(internet_ids)),
        ),
        generated_at=now,
    )
