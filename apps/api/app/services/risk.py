"""Explainable incident risk. Every point is a named factor; the score is their (capped) sum.

    +severity              highest alert severity in the incident
    +confidence            mean detector confidence
    +related events        more corroborating alerts raise confidence the activity is real
    +attack-chain          distinct kill-chain stages observed (progression)
    +behavioral anomaly    a behavioral/ML signal on an involved entity, which is context, not proof
    +critical asset        most critical involved internal device
    +external communication  traffic to or from outside the network
"""

from app.correlation import IncidentDraft
from app.correlation.engine import STAGES
from app.detection.base import is_internal
from app.services.behavior import severity_for_risk

SEVERITY_POINTS = {"critical": 25, "high": 18, "medium": 10, "low": 4, "info": 0}


def incident_risk(draft: IncidentDraft, max_asset_criticality: int) -> tuple[int, list[dict]]:
    alerts = [s.alert for s in draft.steps]
    factors: list[dict] = []

    def add(key, label, points, detail):
        if points > 0:
            factors.append({"key": key, "label": label, "points": int(points), "detail": detail})

    top = max(alerts, key=lambda a: SEVERITY_POINTS[a.severity])
    add("severity", "Highest alert severity", SEVERITY_POINTS[top.severity], f"{top.severity} ({top.event_type.replace('_', ' ')})")
    mean_conf = sum(a.confidence for a in alerts) / len(alerts)
    add("confidence", "Detector confidence", round(mean_conf * 12), f"mean {mean_conf:.2f} across {len(alerts)} alerts")
    add("related_events", "Multiple related events", min(15, 3 * (len(alerts) - 1)), f"{len(alerts)} correlated alerts")
    stages = {STAGES[a.event_type][0] for a in alerts}
    add("chain", "Attack-chain progression", min(18, 3 * len(stages)), f"{len(stages)} stages: {', '.join(sorted(stages))}")
    if draft.supporting:
        kinds = sorted({a.detection_class for a in draft.supporting})
        add("anomaly", "Behavioral / ML anomaly on involved host", 12, "+".join(kinds) + " signal present (context only)")
    add("asset", "Critical asset involved", (max_asset_criticality - 1) * 3, f"criticality {max_asset_criticality}/5")
    external = [a for a in alerts if any(not is_internal(ip) for ip in a.target_ips)]
    add("external", "External communication", 10 if external else 0, f"{len(external)} step(s) reach external hosts")

    factors.sort(key=lambda f: f["points"], reverse=True)
    return min(100, sum(f["points"] for f in factors)), factors


def incident_severity(score: int) -> str:
    return severity_for_risk(score)
