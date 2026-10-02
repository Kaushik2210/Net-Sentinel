from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, new_id, utcnow


class NetworkEvent(Base):
    """A normalized telemetry record. Every telemetry adapter maps into this shape.

    High-volume table: keep it narrow and indexed on the access paths used by the
    dashboard (time, source, type).
    """

    __tablename__ = "network_events"
    __table_args__ = (
        Index("ix_event_ts", "ts"),
        Index("ix_event_src_ts", "src_ip", "ts"),
        Index("ix_event_type_ts", "event_type", "ts"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("evt"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Which adapter produced it: simulation | zeek | suricata | pcap | netflow | syslog
    source: Mapped[str] = mapped_column(String(16), default="simulation")
    src_ip: Mapped[str] = mapped_column(String(45))
    dst_ip: Mapped[str] = mapped_column(String(45))
    src_device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16))
    event_type: Mapped[str] = mapped_column(String(32))
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    bytes_received: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(10), default="info")
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)


class Alert(Base, TimestampMixin):
    """Output of a detector: the standardized detection event."""

    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alert_ts", "ts"), Index("ix_alert_incident", "incident_id"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("alt"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source: Mapped[str] = mapped_column(String(45))
    destination: Mapped[str] = mapped_column(String(45))
    event_type: Mapped[str] = mapped_column(String(48))
    # Distinguishes RULE | BEHAVIORAL | ML | CORRELATED so they are never conflated in the UI.
    detection_class: Mapped[str] = mapped_column(String(12), default="RULE")
    severity: Mapped[str] = mapped_column(String(10))
    confidence: Mapped[float] = mapped_column(Float)
    detector: Mapped[str] = mapped_column(String(48))
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    explanation: Mapped[str] = mapped_column(String(512), default="")
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), default="open")


class Evidence(Base):
    """Links an alert/incident to the raw events that justify it."""

    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_alert", "alert_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("evd"))
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"))
    event_id: Mapped[str | None] = mapped_column(
        ForeignKey("network_events.id", ondelete="SET NULL"), nullable=True
    )
    kind: Mapped[str] = mapped_column(String(24))
    summary: Mapped[str] = mapped_column(String(512))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
