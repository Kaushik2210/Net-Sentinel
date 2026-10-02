"""Detector contract, shared types and the plugin registry.

Adding a detector means: subclass ``Detector``, decorate with ``@register``, and import the
module from ``detection/__init__.py``. Nothing else in the codebase needs to change.
Detectors are pure functions of an event window, so they are testable without a database.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

DetectionClass = Literal["RULE", "BEHAVIORAL", "ML", "CORRELATED"]

INTERNAL_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")


def is_internal(ip: str) -> bool:
    return ip.startswith(INTERNAL_PREFIXES)


@dataclass(frozen=True)
class EventRecord:
    """Normalized telemetry as seen by detectors (decoupled from the ORM)."""

    id: str
    ts: datetime
    src_ip: str
    dst_ip: str
    dst_port: int | None
    protocol: str
    event_type: str
    bytes_sent: int = 0
    bytes_received: int = 0
    attributes: dict = field(default_factory=dict)


@dataclass
class Finding:
    """Standardized detection output (maps onto the ``alerts`` table)."""

    detector: str
    detection_class: DetectionClass
    event_type: str
    severity: str
    confidence: float
    source: str
    destination: str
    timestamp: datetime
    explanation: str
    evidence_ids: list[str]
    mitre_techniques: list[str]
    facts: dict = field(default_factory=dict)  # structured numbers shown as evidence


class Detector(ABC):
    name: str
    detection_class: DetectionClass = "RULE"
    mitre: tuple[str, ...] = ()

    def __init__(self, **params):
        self.params = {**self.defaults(), **params}

    @classmethod
    def defaults(cls) -> dict:
        return {}

    @abstractmethod
    def detect(self, events: list[EventRecord]) -> list[Finding]: ...


_REGISTRY: dict[str, type[Detector]] = {}


def register(cls: type[Detector]) -> type[Detector]:
    _REGISTRY[cls.name] = cls
    return cls


def registry() -> dict[str, type[Detector]]:
    return dict(_REGISTRY)


def severity_from(value: float, medium: float, high: float, critical: float) -> str:
    if value >= critical:
        return "critical"
    if value >= high:
        return "high"
    if value >= medium:
        return "medium"
    return "low"


def confidence_from(value: float, threshold: float, cap: float = 0.97) -> float:
    """Confidence grows with how far past the threshold the observation is (never 1.0)."""
    return round(min(cap, 0.55 + 0.4 * min(1.0, (value - threshold) / max(threshold, 1))), 2)
