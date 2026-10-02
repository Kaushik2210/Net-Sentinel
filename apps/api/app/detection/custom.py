from collections import defaultdict

from app.detection.base import Detector, EventRecord, Finding, confidence_from, register


@register
class CustomRuleDetector(Detector):
    """Evaluates analyst-defined rules stored as data (``detection_rules.parameters``).

    Rule shape: {"event_type": "...", "dst_port": [..], "protocol": "...", "min_count": N,
                 "severity": "...", "title": "...", "mitre": ["T..."]}
    Deliberately a small, safe matcher: no expressions are ever evaluated.
    """

    name = "CustomRuleDetector"

    @classmethod
    def defaults(cls):
        return {"rules": []}

    def detect(self, events: list[EventRecord]) -> list[Finding]:
        out = []
        for rule in self.params["rules"]:
            groups: dict[tuple[str, str], list[EventRecord]] = defaultdict(list)
            for e in events:
                if rule.get("event_type") and e.event_type != rule["event_type"]:
                    continue
                if rule.get("dst_port") and e.dst_port not in rule["dst_port"]:
                    continue
                if rule.get("protocol") and e.protocol != rule["protocol"]:
                    continue
                groups[(e.src_ip, e.dst_ip)].append(e)
            need = int(rule.get("min_count", 1))
            for (src, dst), evs in groups.items():
                if len(evs) >= need:
                    out.append(
                        Finding(
                            detector=self.name, detection_class="RULE", event_type="custom_rule",
                            severity=rule.get("severity", "medium"), confidence=confidence_from(len(evs), need, 0.8),
                            source=src, destination=dst, timestamp=evs[0].ts,
                            explanation=f"Rule '{rule.get('title', 'custom')}' matched {len(evs)} events from {src} to {dst}.",
                            evidence_ids=[e.id for e in evs][:50], mitre_techniques=list(rule.get("mitre", [])),
                            facts={"matches": len(evs)},
                        )
                    )
        return out
