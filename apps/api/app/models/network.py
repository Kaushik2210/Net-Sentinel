from datetime import datetime

from sqlalchemy import JSON, BigInteger, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, new_id, utcnow


class Device(Base, TimestampMixin):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint("criticality BETWEEN 1 AND 5", name="ck_device_criticality"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_device_risk"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("dev"))
    hostname: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    mac: Mapped[str] = mapped_column(String(17))
    device_type: Mapped[str] = mapped_column(String(24), index=True)
    role: Mapped[str] = mapped_column(String(64))
    os: Mapped[str] = mapped_column(String(64), default="unknown")
    zone: Mapped[str] = mapped_column(String(16), default="internal")
    criticality: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[str] = mapped_column(String(16), default="online")
    open_ports: Mapped[list] = mapped_column(JSON, default=list)
    protocols: Mapped[list] = mapped_column(JSON, default=list)
    # Cached output of the transparent scoring function (services/behavior.py).
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)
    # Layout hint for the topology view (x, y); the layout itself is a frontend concern.
    position: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    profile: Mapped["BehaviorProfile | None"] = relationship(
        back_populates="device", uselist=False, cascade="all, delete-orphan"
    )


class BehaviorProfile(Base, TimestampMixin):
    """Per-device baseline ("normal") and the most recent observed ("current") values."""

    __tablename__ = "behavior_profiles"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("bhv"))
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), unique=True
    )
    # {"dns_per_hour": {"min": 40, "max": 90}, ...}
    baseline: Mapped[dict] = mapped_column(JSON, default=dict)
    # {"dns_per_hour": 1240, ...}
    current: Mapped[dict] = mapped_column(JSON, default=dict)
    history: Mapped[list] = mapped_column(JSON, default=list)

    device: Mapped[Device] = relationship(back_populates="profile")


class Connection(Base):
    """Aggregated communication relationship between two devices (a topology edge)."""

    __tablename__ = "connections"
    __table_args__ = (
        UniqueConstraint("src_device_id", "dst_device_id", "protocol", name="uq_connection_pair"),
        Index("ix_connection_dst", "dst_device_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("con"))
    src_device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    dst_device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    protocol: Mapped[str] = mapped_column(String(16))
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_per_hour: Mapped[int] = mapped_column(BigInteger, default=0)
    connections_per_hour: Mapped[int] = mapped_column(Integer, default=0)
    suspicious: Mapped[bool] = mapped_column(default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
