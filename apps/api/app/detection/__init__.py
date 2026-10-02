"""Pluggable detection engine. Importing this package registers all built-in detectors."""

from app.detection import auth, custom, ml, recon, traffic  # noqa: F401
from app.detection.base import DetectionClass, Detector, EventRecord, Finding, register, registry
from app.detection.engine import DetectionEngine

__all__ = ["DetectionClass", "DetectionEngine", "Detector", "EventRecord", "Finding", "register", "registry"]
