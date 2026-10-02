"""Alert correlation: turn related alerts into ordered attack chains.

Pure functions (no I/O) so the logic is unit-testable and the persistence layer stays thin.

Relationship tests between two chain alerts, in the order the spec describes:
  similarity     both belong to the attack kill-chain vocabulary (stage map below)
  temporal       timestamps within ``MAX_GAP``
  entity         same source address, or one alert's source was a destination of the other (pivot)
  behavioral     the later alert's stage does not precede the earlier one's (progression)
Two alerts are linked when temporal AND entity hold; behavioral progression raises the link confidence.
Supporting alerts (ML / behavioral) that share an entity are attached to the incident but are not chain steps.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

MAX_GAP = timedelta(minutes=20)

# event_type -> (stage, order). Order encodes typical kill-chain progression.
STAGES: dict[str, tuple[str, int]] = {
    "horizontal_sweep": ("Reconnaissance", 0),
    "vertical_port_scan": ("Network Scanning", 1),
    "credential_attack": ("Credential Attack", 2),
    "possible_credential_compromise": ("Initial Access", 3),
    "dns_tunneling_suspected": ("Command & Control", 4),
    "dns_flood": ("Command & Control", 4),
    "lateral_movement": ("Lateral Movement", 5),
    "external_fanout": ("Command & Control", 4),
    "suspicious_protocol": ("Command & Control", 4),
    "possible_exfiltration": ("Possible Exfiltration", 6),
}
SUPPORTING_TYPES = {"ml_anomaly", "behavior_deviation"}

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


@dataclass(frozen=True)
class AlertLite:
    id: str
    ts: datetime
    source: str
    destination: str
    event_type: str
    detection_class: str
    severity: str
    confidence: float
    detector: str
    mitre: tuple[str, ...] = ()

    @property
    def stage(self) -> tuple[str, int] | None:
        return STAGES.get(self.event_type)

    @property
    def target_ips(self) -> set[str]:
        return set(_IP.findall(self.destination))


@dataclass
class Step:
    alert: AlertLite
    position: int
    stage: str
    link_reason: str
    link_confidence: float


@dataclass
class IncidentDraft:
    steps: list[Step]
    supporting: list[AlertLite] = field(default_factory=list)

    @property
    def alert_ids(self) -> list[str]:
        return [s.alert.id for s in self.steps] + [a.id for a in self.supporting]

    @property
    def entities(self) -> set[str]:
        out: set[str] = set()
        for s in self.steps:
            out.add(s.alert.source)
            out |= s.alert.target_ips
        return out


def _link(a: AlertLite, b: AlertLite) -> tuple[str, float] | None:
    """Reason and confidence if two chain alerts are related, else None."""
    if abs(a.ts - b.ts) > MAX_GAP:
        return None
    if a.source == b.source:
        reason, conf = f"same source {a.source}", 0.9
    elif b.source in a.target_ips or a.source in b.target_ips:
        reason, conf = "pivot: a prior target is now the source", 0.75
    else:
        return None
    early, late = sorted((a, b), key=lambda x: x.ts)
    if early.stage and late.stage and late.stage[1] >= early.stage[1]:
        conf = min(0.97, conf + 0.05)
        reason += ", stage progression"
    return reason, round(conf, 2)


def correlate(alerts: list[AlertLite], min_chain: int = 2) -> list[IncidentDraft]:
    chain = sorted((a for a in alerts if a.stage), key=lambda a: a.ts)
    parent = {a.id: a.id for a in chain}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    links: dict[tuple[str, str], tuple[str, float]] = {}
    for i, a in enumerate(chain):
        for b in chain[i + 1:]:
            res = _link(a, b)
            if res:
                links[(a.id, b.id)] = res
                parent[find(b.id)] = find(a.id)

    groups: dict[str, list[AlertLite]] = {}
    for a in chain:
        groups.setdefault(find(a.id), []).append(a)

    supporting_pool = [a for a in alerts if a.event_type in SUPPORTING_TYPES]
    drafts: list[IncidentDraft] = []
    for members in groups.values():
        if len(members) < min_chain:
            continue
        members.sort(key=lambda a: a.ts)
        steps = []
        for pos, a in enumerate(members):
            # Strongest link to any earlier member explains why this step belongs.
            earlier = [links[(p.id, a.id)] for p in members[:pos] if (p.id, a.id) in links]
            reason, conf = max(earlier, key=lambda x: x[1]) if earlier else ("chain origin", 1.0)
            steps.append(Step(a, pos, a.stage[0], reason, conf))  # type: ignore[index]
        draft = IncidentDraft(steps)
        ents = draft.entities
        draft.supporting = [s for s in supporting_pool if s.source in ents]
        drafts.append(draft)
    return sorted(drafts, key=lambda d: d.steps[0].alert.ts)
