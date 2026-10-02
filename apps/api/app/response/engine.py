"""Response recommendations and the (simulation-only) actuator.

Recommendations are derived from an incident's evidence; each one cites the alerts that motivated it.
Nothing here changes a network. ``SimulatedActuator`` is the only actuator and its result states plainly
that no real change occurred. A real integration (firewall, EDR, SOAR) would implement ``ResponseActuator``
and be added behind explicit configuration plus an approval step; none exists.
"""

import re
from dataclasses import dataclass
from typing import Protocol

from app.analyst.evidence import IncidentPackage
from app.detection.base import is_internal

ACTIONS = {
    "isolate_device": ("SIMULATE ISOLATION", "DEVICE {t} WOULD BE ISOLATED"),
    "block_destination": ("SIMULATE BLOCK", "{t} WOULD BE BLOCKED AT THE PERIMETER"),
    "disable_account": ("SIMULATE ACCOUNT DISABLE", "ACCOUNT {t} WOULD BE DISABLED"),
    "review_auth_logs": ("QUEUE LOG REVIEW", "AUTHENTICATION LOGS FOR {t} WOULD BE QUEUED FOR REVIEW"),
    "capture_traffic": ("SIMULATE CAPTURE", "ADDITIONAL TRAFFIC CAPTURE WOULD START FOR {t}"),
    "review_endpoint": ("QUEUE ENDPOINT REVIEW", "ENDPOINT PROCESS ACTIVITY ON {t} WOULD BE REVIEWED"),
}
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


@dataclass
class Recommendation:
    action: str
    target: str
    rationale: str


def label_for(action: str) -> str:
    return ACTIONS[action][0]


def recommend(p: IncidentPackage) -> list[Recommendation]:
    recs: dict[tuple[str, str], Recommendation] = {}

    def add(action: str, target: str, why: str, alert_ids: list[str]):
        recs.setdefault((action, target), Recommendation(action, target, f"{why} (evidence: {', '.join(alert_ids)})"))

    if not p.steps:
        return []
    src = p.steps[0].source
    if p.risk_score >= 50:
        add("isolate_device", src, f"{src} is the origin of a {len(p.steps)}-step chain with risk {p.risk_score}/100", [s.alert_id for s in p.steps][:3])
    for s in p.steps:
        if s.stage == "Possible Exfiltration":
            add("block_destination", s.destination, "outbound volume to this external host triggered the exfiltration indicator", [s.alert_id])
        if s.stage == "Credential Attack":
            add("review_auth_logs", s.destination, "repeated failed authentications were observed against this service", [s.alert_id])
        if s.stage == "Initial Access":
            acct = s.facts.get("account")
            if acct and acct != "?":
                add("disable_account", str(acct), "this account authenticated successfully after a run of failures", [s.alert_id])
        if s.stage == "Lateral Movement":
            for ip in _IP.findall(s.destination)[:3]:
                if is_internal(ip):
                    add("review_endpoint", ip, "this host accepted an admin-protocol login from the suspected source", [s.alert_id])
        if s.stage == "Command & Control":
            add("capture_traffic", s.source, "unusual DNS or external patterns warrant fuller packet capture", [s.alert_id])
    return list(recs.values())


class ResponseActuator(Protocol):
    name: str
    real: bool

    def execute(self, action: str, target: str) -> str: ...


class SimulatedActuator:
    name = "simulation"
    real = False

    def execute(self, action: str, target: str) -> str:
        return ACTIONS[action][1].format(t=target) + ". No real network modification occurs."
