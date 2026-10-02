from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, new_id, utcnow


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("usr"))
    username: Mapped[str] = mapped_column(String(48), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(80))
    password_hash: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(10), default="VIEWER")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditLog(Base):
    """Append-only record of security-relevant actions (logins, status changes, simulations)."""

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_ts", "ts"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("aud"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(48))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(128), default="")
    ip: Mapped[str] = mapped_column(String(45), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class DetectionRule(Base, TimestampMixin):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("rul"))
    name: Mapped[str] = mapped_column(String(80), unique=True)
    detector: Mapped[str] = mapped_column(String(48))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    description: Mapped[str] = mapped_column(String(512), default="")


class MITRETechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # e.g. T1046
    name: Mapped[str] = mapped_column(String(120))
    tactic: Mapped[str] = mapped_column(String(48), index=True)
    description: Mapped[str] = mapped_column(String(1024), default="")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_indicator"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ioc"))
    kind: Mapped[str] = mapped_column(String(8))  # ip | domain | hash | url
    value: Mapped[str] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(48), default="manual")
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    description: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Dataset(Base):
    __tablename__ = "datasets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("dat"))
    name: Mapped[str] = mapped_column(String(80), unique=True)
    kind: Mapped[str] = mapped_column(String(24))  # cicids | unsw-nb15 | pcap | synthetic
    records: Mapped[int] = mapped_column(Integer, default=0)
    license: Mapped[str] = mapped_column(String(80), default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReplaySession(Base):
    __tablename__ = "replay_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("rpl"))
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    # Self-contained replay payload (hosts, edges, frames, alerts, incident); see app/replay/engine.py.
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
