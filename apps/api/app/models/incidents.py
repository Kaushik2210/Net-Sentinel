from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, new_id, utcnow


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"
    __table_args__ = (CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_incident_risk"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("inc"))
    title: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(10))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)
    assignee_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    summary: Mapped[str] = mapped_column(String(1024), default="")


class IncidentEvent(Base):
    """Ordered step in the reconstructed attack chain."""

    __tablename__ = "incident_events"
    __table_args__ = (UniqueConstraint("incident_id", "position", name="uq_incident_position"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ise"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    alert_id: Mapped[str | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    position: Mapped[int] = mapped_column(Integer)
    stage: Mapped[str] = mapped_column(String(32))
    link_reason: Mapped[str] = mapped_column(String(256), default="")
    link_confidence: Mapped[float] = mapped_column(Float, default=0.5)


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("note"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    body: Mapped[str] = mapped_column(String(4000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ResponseRecommendation(Base):
    __tablename__ = "response_recommendations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("rec"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(48))
    target: Mapped[str] = mapped_column(String(128))
    rationale: Mapped[str] = mapped_column(String(512))
    # Real actions are not wired up; "simulated" is the only executable state.
    state: Mapped[str] = mapped_column(String(16), default="proposed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
