from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.core.deps import CurrentUser, DbSession
from app.models import NetworkEvent
from app.schemas.common import EventOut

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=list[EventOut])
def list_events(
    _: CurrentUser,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before: Annotated[datetime | None, Query(description="Keyset cursor: return events older than this")] = None,
    event_type: Annotated[str | None, Query(max_length=32)] = None,
    src_ip: Annotated[str | None, Query(max_length=45)] = None,
):
    # Keyset pagination on the indexed timestamp: stable under inserts, no OFFSET scans.
    stmt = select(NetworkEvent).order_by(NetworkEvent.ts.desc()).limit(limit)
    if before:
        stmt = stmt.where(NetworkEvent.ts < before)
    if event_type:
        stmt = stmt.where(NetworkEvent.event_type == event_type)
    if src_ip:
        stmt = stmt.where(NetworkEvent.src_ip == src_ip)
    return db.scalars(stmt).all()
