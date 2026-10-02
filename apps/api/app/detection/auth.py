from collections import defaultdict

from app.detection.base import Detector, EventRecord, Finding, confidence_from, is_internal, register, severity_from

ADMIN_PORTS = {22: "ssh", 445: "smb", 3389: "rdp", 5985: "winrm"}


@register
class BruteForceDetector(Detector):
    name = "BruteForceDetector"
    mitre = ("T1110",)

    @classmethod
    def defaults(cls):
        return {"min_failures": 10}

    def detect(self, events: list[EventRecord]) -> list[Finding]:
        groups: dict[tuple[str, str, int | None], list[EventRecord]] = defaultdict(list)
        for e in events:
            if e.event_type == "auth_failure":
                groups[(e.src_ip, e.dst_ip, e.dst_port)].append(e)
        out = []
        thr = self.params["min_failures"]
        for (src, dst, port), evs in groups.items():
            n = len(evs)
            if n < thr:
                continue
            users = {str(e.attributes.get("user", "?")) for e in evs}
            out.append(
                Finding(
                    detector=self.name, detection_class="RULE", event_type="credential_attack",
                    severity=severity_from(n, thr, thr * 3, thr * 8), confidence=confidence_from(n, thr),
                    source=src, destination=f"{dst}:{port}", timestamp=evs[0].ts,
                    explanation=f"{n} failed authentications from {src} to {dst}:{port} against {len(users)} account(s).",
                    evidence_ids=[e.id for e in evs][:50], mitre_techniques=list(self.mitre),
                    facts={"failures": n, "accounts_targeted": len(users), "port": port},
                )
            )
        return out


@register
class LateralMovementDetector(Detector):
    name = "LateralMovementDetector"
    mitre = ("T1021",)

    @classmethod
    def defaults(cls):
        return {"min_hosts": 3}

    def detect(self, events: list[EventRecord]) -> list[Finding]:
        by_src: dict[str, dict[str, list[EventRecord]]] = defaultdict(lambda: defaultdict(list))
        for e in events:
            if e.event_type == "auth_success" and e.dst_port in ADMIN_PORTS and is_internal(e.src_ip) and is_internal(e.dst_ip):
                by_src[e.src_ip][e.dst_ip].append(e)
        out = []
        thr = self.params["min_hosts"]
        for src, dsts in by_src.items():
            if len(dsts) < thr:
                continue
            evs = sorted((e for v in dsts.values() for e in v), key=lambda e: e.ts)
            out.append(
                Finding(
                    detector=self.name, detection_class="RULE", event_type="lateral_movement",
                    severity=severity_from(len(dsts), thr, thr + 2, thr + 5), confidence=confidence_from(len(dsts), thr, 0.9),
                    source=src, destination=", ".join(sorted(dsts))[:45], timestamp=evs[0].ts,
                    explanation=f"{src} authenticated to {len(dsts)} internal hosts over admin protocols.",
                    evidence_ids=[e.id for e in evs][:50], mitre_techniques=[*self.mitre, "T1078"],
                    facts={"hosts": len(dsts), "protocols": sorted({ADMIN_PORTS[e.dst_port] for e in evs if e.dst_port})},
                )
            )
        return out


@register
class CredentialCompromiseDetector(Detector):
    """A successful login to a service after a run of failures from the same source."""

    name = "CredentialCompromiseDetector"
    mitre = ("T1078", "T1110")

    @classmethod
    def defaults(cls):
        return {"min_failures": 5}

    def detect(self, events: list[EventRecord]) -> list[Finding]:
        fails: dict[tuple[str, str, int | None], list[EventRecord]] = defaultdict(list)
        wins: dict[tuple[str, str, int | None], list[EventRecord]] = defaultdict(list)
        for e in events:
            key = (e.src_ip, e.dst_ip, e.dst_port)
            if e.event_type == "auth_failure":
                fails[key].append(e)
            elif e.event_type == "auth_success":
                wins[key].append(e)
        out = []
        for key, ok in wins.items():
            prior = [f for f in fails.get(key, []) if f.ts < ok[0].ts]
            if len(prior) < self.params["min_failures"]:
                continue
            src, dst, port = key
            user = ok[0].attributes.get("user", "?")
            out.append(
                Finding(
                    detector=self.name, detection_class="RULE", event_type="possible_credential_compromise",
                    severity="high", confidence=confidence_from(len(prior), self.params["min_failures"], 0.92),
                    source=src, destination=f"{dst}:{port}", timestamp=ok[0].ts,
                    explanation=f"{src} authenticated to {dst}:{port} as '{user}' after {len(prior)} failed attempts.",
                    evidence_ids=[*[f.id for f in prior[-10:]], ok[0].id], mitre_techniques=list(self.mitre),
                    facts={"prior_failures": len(prior), "account": str(user)},
                )
            )
        return out
