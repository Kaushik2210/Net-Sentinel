import logging
from datetime import timedelta

from app.detection.base import Detector, EventRecord, Finding, registry

log = logging.getLogger("netsentinel.detect")

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class DetectionEngine:
    """Runs every enabled detector over an event window and returns standardized findings.

    A failing detector is logged and skipped so one bad plugin cannot blind the rest.
    """

    def __init__(self, detectors: list[Detector] | None = None, overrides: dict[str, dict] | None = None):
        overrides = overrides or {}
        self.detectors = (
            detectors if detectors is not None else [cls(**overrides.get(name, {})) for name, cls in registry().items()]
        )

    def run(self, events: list[EventRecord]) -> list[Finding]:
        findings: list[Finding] = []
        for d in self.detectors:
            try:
                found = d.detect(events)
            except Exception:
                log.exception("detector %s failed", d.name)
                continue
            if found:
                log.info("%s produced %d finding(s)", d.name, len(found))
            findings.extend(found)
        return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), -f.confidence))

    @staticmethod
    def window(events: list[EventRecord], seconds: int) -> list[EventRecord]:
        if not events:
            return []
        cutoff = max(e.ts for e in events) - timedelta(seconds=seconds)
        return [e for e in events if e.ts >= cutoff]
