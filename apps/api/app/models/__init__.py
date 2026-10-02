"""Import every model so ``Base.metadata`` is complete (used by Alembic and create_all)."""

from app.models.base import Base
from app.models.events import Alert, Evidence, NetworkEvent
from app.models.incidents import Incident, IncidentEvent, InvestigationNote, ResponseRecommendation
from app.models.network import BehaviorProfile, Connection, Device
from app.models.platform import (
    AuditLog,
    Dataset,
    DetectionRule,
    MITRETechnique,
    ReplaySession,
    ThreatIndicator,
    User,
)

__all__ = [
    "Alert", "AuditLog", "Base", "BehaviorProfile", "Connection", "Dataset", "DetectionRule",
    "Device", "Evidence", "Incident", "IncidentEvent", "InvestigationNote", "MITRETechnique",
    "NetworkEvent", "ReplaySession", "ResponseRecommendation", "ThreatIndicator", "User",
]
