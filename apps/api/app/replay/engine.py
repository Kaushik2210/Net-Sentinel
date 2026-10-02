"""Builds a self-contained replay result from time-ordered events.

The player in the browser needs no further server calls: this returns hosts, edges, a compact event
list, per-frame state (threat score, chain length, new alerts) and the final reconstructed incident.

Detection is run *incrementally*: at each frame boundary the engine sees only events up to that time
(within the standard 10-minute window), so an alert appears at the moment it first became detectable,
not retroactively. The ML detector is excluded (it is calibrated for live 10-minute windows) and
replay-specific threshold overrides are recorded in the result.
"""

import json
from bisect import bisect_right
from datetime import timedelta
from pathlib import Path

from app.correlation import AlertLite, correlate
from app.detection import DetectionEngine, EventRecord, Finding, registry
from app.detection.base import is_internal
from app.models.base import new_id
from app.services.risk import SEVERITY_POINTS, incident_risk

WINDOW = timedelta(minutes=10)
FRAMES = 60
MAX_RENDER_EVENTS = 20_000
EXCLUDED = {"MLAnomalyDetector"}
_CATALOGUE = {t["id"]: t for t in json.loads((Path(__file__).resolve().parent.parent / "data" / "mitre.json").read_text(encoding="utf-8"))}


def _lite(alert_id: str, f: Finding) -> AlertLite:
    return AlertLite(id=alert_id, ts=f.timestamp, source=f.source, destination=f.destination, event_type=f.event_type,
                     detection_class=f.detection_class, severity=f.severity, confidence=f.confidence, detector=f.detector,
                     mitre=tuple(f.mitre_techniques))


def build_replay(events: list[EventRecord], overrides: dict[str, dict] | None = None) -> dict:
    overrides = overrides or {}
    if not events:
        return {"empty": True, "settings": {"overrides": overrides}, "duration_s": 0, "hosts": [], "edges": [], "events": [], "frames": [], "alerts": [], "incident": None}

    events = sorted(events, key=lambda e: e.ts)
    t0, t1 = events[0].ts, events[-1].ts
    duration = max((t1 - t0).total_seconds(), 1.0)
    engine = DetectionEngine([cls(**overrides.get(n, {})) for n, cls in registry().items() if n not in EXCLUDED])
    times = [e.ts for e in events]

    seen: dict[tuple, dict] = {}
    findings: dict[str, Finding] = {}
    frames = []
    last_count = 0
    n_frames = FRAMES if duration > 1 else 1
    for k in range(1, n_frames + 1):
        tk = t0 + (t1 - t0) * (k / n_frames)
        hi = bisect_right(times, tk)
        new_ids: list[str] = []
        if hi != last_count:
            lo = bisect_right(times, tk - WINDOW)
            for f in engine.run(events[lo:hi]):
                key = (f.detector, f.source, f.event_type)
                if key in seen:
                    continue
                aid = new_id("alt")
                seen[key] = {"id": aid, "detected_offset_s": round((tk - t0).total_seconds(), 1)}
                findings[aid] = f
                new_ids.append(aid)
            last_count = hi
        lites = [_lite(a, f) for a, f in findings.items()]
        drafts = correlate(lites)
        best = max(drafts, key=lambda d: len(d.steps), default=None)
        if best:
            score, _ = incident_risk(best, 2)
        else:
            score = max((SEVERITY_POINTS[f.severity] for f in findings.values()), default=0)
        frames.append({"t": round((tk - t0).total_seconds(), 1), "events": hi, "alerts": len(findings), "chain": len(best.steps) if best else 0,
                       "threat": score, "new_alerts": new_ids})

    # Hosts and edges
    ips: dict[str, dict] = {}
    edges: dict[tuple[str, str], dict] = {}
    for e in events:
        off = (e.ts - t0).total_seconds()
        for ip in (e.src_ip, e.dst_ip):
            h = ips.setdefault(ip, {"ip": ip, "internal": is_internal(ip), "first_s": round(off, 1), "events": 0})
            h["events"] += 1
        ed = edges.setdefault((e.src_ip, e.dst_ip), {"src": e.src_ip, "dst": e.dst_ip, "first_s": round(off, 1), "count": 0, "bytes": 0})
        ed["count"] += 1
        ed["bytes"] += e.bytes_sent + e.bytes_received

    index = {ip: i for i, ip in enumerate(ips)}
    types = sorted({e.event_type for e in events})
    sample = events if len(events) <= MAX_RENDER_EVENTS else events[:MAX_RENDER_EVENTS]
    rows = [[round((e.ts - t0).total_seconds(), 2), index[e.src_ip], index[e.dst_ip], e.dst_port or 0, types.index(e.event_type), e.bytes_sent + e.bytes_received] for e in sample]

    alerts = []
    for aid, f in findings.items():
        meta = next(m for m in seen.values() if m["id"] == aid)
        alerts.append({
            "id": aid, "detected_offset_s": meta["detected_offset_s"], "first_event_offset_s": round((f.timestamp - t0).total_seconds(), 1),
            "source": f.source, "destination": f.destination, "event_type": f.event_type, "detection_class": f.detection_class,
            "severity": f.severity, "confidence": f.confidence, "detector": f.detector, "mitre": f.mitre_techniques,
            "explanation": f.explanation, "facts": f.facts, "evidence_event_ids": f.evidence_ids[:20],
        })
    alerts.sort(key=lambda a: a["detected_offset_s"])

    incident = None
    drafts = correlate([_lite(a, f) for a, f in findings.items()])
    if drafts:
        best = max(drafts, key=lambda d: len(d.steps))
        score, factors = incident_risk(best, 2)
        by_id = {a["id"]: a for a in alerts}
        incident = {
            "risk_score": score, "risk_factors": factors,
            "steps": [{"position": s.position, "stage": s.stage, "alert_id": s.alert.id, "link_reason": s.link_reason, "link_confidence": s.link_confidence,
                       "offset_s": by_id[s.alert.id]["first_event_offset_s"]} for s in best.steps],
            "techniques": [_CATALOGUE[t] for t in sorted({t for a in alerts if a["id"] in {s.alert.id for s in best.steps} for t in a["mitre"]}) if t in _CATALOGUE],
        }

    return {
        "empty": False, "settings": {"overrides": overrides, "excluded_detectors": sorted(EXCLUDED), "window_minutes": 10},
        "start": t0.isoformat(), "end": t1.isoformat(), "duration_s": round(duration, 1),
        "hosts": list(ips.values()), "edges": list(edges.values()), "event_types": types, "events": rows,
        "events_truncated": len(events) > MAX_RENDER_EVENTS, "frames": frames, "alerts": alerts, "incident": incident,
    }
