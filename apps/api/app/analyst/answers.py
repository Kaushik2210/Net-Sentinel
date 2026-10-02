"""Deterministic, evidence-bound answers.

Every answer is a list of ``Claim`` objects, each carrying the identifiers it relies on. ``validate``
rejects any claim that cites an ID outside the evidence package. When the evidence cannot support an
answer the result is exactly "Insufficient evidence." with no embellishment.

No language model is used here. ``provider.py`` defines the adapter a model could implement later; its
output would pass through the same ``validate`` gate.
"""

from dataclasses import dataclass, field

from app.analyst.evidence import DevicePackage, IncidentPackage

INSUFFICIENT = "Insufficient evidence."

INCIDENT_QUESTIONS = ("explain", "what_changed", "timeline", "evidence", "next_steps", "related_events", "exfiltration", "report")
DEVICE_QUESTIONS = ("why_suspicious", "related_alerts")


@dataclass
class Claim:
    text: str
    cites: list[str] = field(default_factory=list)


@dataclass
class Answer:
    question: str
    claims: list[Claim]
    insufficient: bool = False
    mode: str = "deterministic"

    @property
    def citations(self) -> list[str]:
        return sorted({c for cl in self.claims for c in cl.cites})


class CitationError(ValueError):
    pass


def validate(answer: Answer, allowed_ids: set[str]) -> Answer:
    """Reject an answer that cites anything outside the evidence package."""
    bad = [c for cl in answer.claims for c in cl.cites if c not in allowed_ids]
    if bad:
        raise CitationError(f"answer cites identifiers not in the evidence package: {sorted(set(bad))[:5]}")
    return answer


def _none(question: str) -> Answer:
    return Answer(question, [Claim(INSUFFICIENT)], insufficient=True)


# Next-step guidance keyed by stage. These are standard analyst checks, not findings about this network.
_NEXT = {
    "Reconnaissance": "Identify what answered the sweep and confirm those hosts are expected to be reachable from {src}.",
    "Network Scanning": "Review firewall and host logs on {dst} for the scanned ports; confirm which services are exposed.",
    "Credential Attack": "Review authentication logs on the targeted host for the accounts attempted; consider forcing password resets for them.",
    "Initial Access": "Verify the account that succeeded after the failures; check for new sessions, keys or processes it started.",
    "Lateral Movement": "Inspect the hosts {src} authenticated to for new accounts, scheduled tasks and outbound connections.",
    "Command & Control": "Capture additional traffic from {src} and review DNS and proxy logs for the unusual destinations.",
    "Possible Exfiltration": "Determine what data the source could access, and block or monitor the external destination pending review.",
}


def answer_incident(question: str, p: IncidentPackage) -> Answer:
    if not p.steps:
        return _none(question)
    first, last = p.steps[0], p.steps[-1]

    if question == "explain":
        stages = " > ".join(dict.fromkeys(s.stage for s in p.steps))
        claims = [
            Claim(f"{p.incident_id} correlates {len(p.steps)} alerts from {first.source} into one chain: {stages}.", [p.incident_id, *[s.alert_id for s in p.steps]]),
            Claim(f"Risk is {p.risk_score}/100: " + "; ".join(f"+{f['points']} {f['label']}" for f in p.risk_factors[:4]) + ".", [p.incident_id]),
        ]
        if p.techniques:
            claims.append(Claim("Mapped techniques: " + ", ".join(f"{t['id']} {t['name']}" for t in p.techniques) + ".", [t["id"] for t in p.techniques]))
        return Answer(question, claims)

    if question == "what_changed":
        claims = [Claim(f"{s.stage}: {s.explanation}", [s.alert_id]) for s in p.steps]
        return Answer(question, [Claim(f"Activity progressed over {len(p.steps)} steps, from {first.ts[11:19]}Z to {last.ts[11:19]}Z:", [p.incident_id]), *claims])

    if question == "timeline":
        return Answer(question, [Claim(f"{s.ts[11:19]}Z  {s.stage}: {s.source} to {s.destination} ({s.detector}, {round(s.confidence * 100)}% confidence)", [s.alert_id]) for s in p.steps])

    if question == "evidence":
        claims = []
        for s in p.steps:
            n = len(s.event_ids)
            claims.append(Claim(f"{s.stage}: {n} supporting event(s)" + (f" ({', '.join(s.event_ids[:3])}{'...' if n > 3 else ''})" if n else " (derived signal, no raw events)") + ".", [s.alert_id, *s.event_ids[:3]]))
        return Answer(question, claims)

    if question == "related_events":
        claims = [Claim(f"{s.alert_id} ({s.stage}) is supported by {len(s.event_ids)} event(s): {', '.join(s.event_ids[:6]) or 'none'}.", [s.alert_id, *s.event_ids[:6]]) for s in p.steps if s.event_ids]
        return Answer(question, claims) if claims else _none(question)

    if question == "next_steps":
        seen, claims = set(), []
        for s in p.steps:
            tpl = _NEXT.get(s.stage)
            if tpl and s.stage not in seen:
                seen.add(s.stage)
                claims.append(Claim(tpl.format(src=s.source, dst=s.destination) + f" (because of {s.stage.lower()} evidence)", [s.alert_id]))
        return Answer(question, claims) if claims else _none(question)

    if question == "exfiltration":
        ex = [s for s in p.steps if s.stage == "Possible Exfiltration"]
        if not ex:
            return _none(question)
        return Answer(question, [Claim(f"{s.explanation} This is a volume-based indicator, not confirmation of what data left.", [s.alert_id, *s.event_ids[:3]]) for s in ex])

    if question == "report":
        lines = [Claim(f"Incident report: {p.title} ({p.incident_id})", [p.incident_id]),
                 Claim(f"Status {p.status}, severity {p.severity}, risk {p.risk_score}/100, {p.first_seen[:19]}Z to {p.last_seen[:19]}Z.", [p.incident_id])]
        lines += [Claim(f"{s.position + 1}. {s.stage} ({s.ts[11:19]}Z): {s.explanation} [{', '.join(s.mitre) or 'no technique'}]", [s.alert_id]) for s in p.steps]
        lines += [Claim(f"Risk factor +{f['points']}: {f['label']} ({f['detail']})", [p.incident_id]) for f in p.risk_factors]
        if p.supporting:
            lines.append(Claim("Supporting signals (context only): " + "; ".join(f"{x['class']} on {x['source']}" for x in p.supporting) + ".", [x["id"] for x in p.supporting]))
        return Answer(question, lines)

    raise ValueError(f"unknown incident question: {question}")


def answer_device(question: str, p: DevicePackage) -> Answer:
    if question == "why_suspicious":
        if not p.risk_factors and not p.alerts:
            return _none(question)
        claims = [Claim(f"{p.hostname} ({p.ip}) has risk {p.risk_score}/100.", [p.device_id])]
        claims += [Claim(f"+{f['points']} {f['label']}: {f['detail']}.", [p.device_id]) for f in p.risk_factors]
        claims += [Claim(f"Alert {a['id']} ({a['type'].replace('_', ' ')}, {a['class']}) lists it as {a['role']}.", [a["id"]]) for a in p.alerts[:5]]
        return Answer(question, claims)
    if question == "related_alerts":
        if not p.alerts:
            return _none(question)
        return Answer(question, [Claim(f"{a['id']}: {a['explanation']}", [a["id"]]) for a in p.alerts])
    raise ValueError(f"unknown device question: {question}")
