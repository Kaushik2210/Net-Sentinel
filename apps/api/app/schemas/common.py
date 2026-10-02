from datetime import UTC, datetime
from typing import Annotated, Generic, TypeVar

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

T = TypeVar("T")


def _as_utc(v: datetime) -> datetime:
    # SQLite returns naive datetimes; everything we store is UTC, and clients must see the offset.
    return v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)


UTCDatetime = Annotated[datetime, AfterValidator(_as_utc)]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=48)
    # bcrypt ignores bytes past 72; cap the input rather than silently truncating.
    password: str = Field(min_length=1, max_length=72)


class UserOut(ORM):
    id: str
    username: str
    display_name: str
    role: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    user: UserOut


class Factor(BaseModel):
    key: str
    label: str
    points: int
    detail: str


class DeviceSummary(ORM):
    id: str
    hostname: str
    ip: str
    device_type: str
    zone: str
    role: str
    criticality: int
    status: str
    risk_score: int
    last_seen: UTCDatetime


class EventOut(ORM):
    id: str
    ts: UTCDatetime
    source: str
    src_ip: str
    dst_ip: str
    dst_port: int | None
    protocol: str
    event_type: str
    bytes_sent: int
    bytes_received: int
    severity: str
    attributes: dict
