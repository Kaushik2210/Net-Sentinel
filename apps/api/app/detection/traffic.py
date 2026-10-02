import math
from collections import Counter, defaultdict

from app.detection.base import Detector, EventRecord, Finding, confidence_from, is_internal, register, severity_from


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values()) if s else 0.0


@register
class DNSAnomalyDetector(Detector):
    name = "DNSAnomalyDetector"
    mitre = ("T1071.004",)

    @classmethod
    def defaults(cls):
        return {"min_queries": 200, "min_unique_ratio": 0.6, "min_entropy": 3.5, "min_long_labels": 15}

    def detect(self, events: list[EventRecord]) -> list[Finding]:
        by_src: dict[str, list[EventRecord]] = defaultdict(list)
        for e in events:
            if e.event_type == "dns_query":
                by_src[e.src_ip].append(e)
        out = []
        for src, evs in by_src.items():
            domains = [str(e.attributes.get("domain", "")) for e in evs]
            unique = len(set(domains))
            odd = [d for d in domains if len(d.split(".")[0]) >= 16 and entropy(d.split(".")[0]) >= self.params["min_entropy"]]
            volume = len(evs) >= self.params["min_queries"] and unique / len(evs) >= self.params["min_unique_ratio"]
            tunnel = len(odd) >= self.params["min_long_labels"]
            if not (volume or tunnel):
                continue
            n = max(len(evs) if volume else 0, len(odd) * 10)
            tail = f"; {len(odd)} had long, high-entropy labels typical of tunneling." if tunnel else "."
            out.append(
                Finding(
                    detector=self.name, detection_class="RULE",
                    event_type="dns_tunneling_suspected" if tunnel else "dns_flood",
                    severity=severity_from(n, 200, 600, 1500), confidence=confidence_from(n, 200, 0.9),
                    source=src, destination=evs[0].dst_ip, timestamp=evs[0].ts,
                    explanation=f"{src} issued {len(evs)} DNS queries to {unique} distinct names{tail}",
                    evidence_ids=[e.id for e in evs][:50], mitre_techniques=list(self.mitre),
                    facts={"queries": len(evs), "unique_domains": unique, "high_entropy_names": len(odd)},
                )
            )
        return out


@register
class ConnectionAnomalyDetector(Detector):
    name = "ConnectionAnomalyDetector"
    mitre = ("T1090",)

    @classmethod
    def defaults(cls):
        return {"min_external_dests": 40}

    def detect(self, events: list[EventRecord]) -> list[Finding]:
        by_src: dict[str, dict[str, list[EventRecord]]] = defaultdict(lambda: defaultdict(list))
        for e in events:
            if e.event_type in {"tls_session", "http_request"} and is_internal(e.src_ip) and not is_internal(e.dst_ip):
                by_src[e.src_ip][e.dst_ip].append(e)
        out = []
        thr = self.params["min_external_dests"]
        for src, dsts in by_src.items():
            if len(dsts) < thr:
                continue
            evs = [e for v in dsts.values() for e in v]
            out.append(
                Finding(
                    detector=self.name, detection_class="RULE", event_type="external_fanout",
                    severity=severity_from(len(dsts), thr, thr * 2, thr * 4), confidence=confidence_from(len(dsts), thr, 0.85),
                    source=src, destination=f"{len(dsts)} external hosts", timestamp=min(e.ts for e in evs),
                    explanation=f"{src} contacted {len(dsts)} distinct external hosts in the window.",
                    evidence_ids=[e.id for e in evs][:50], mitre_techniques=list(self.mitre),
                    facts={"distinct_external_hosts": len(dsts)},
                )
            )
        return out


@register
class DataExfiltrationDetector(Detector):
    name = "DataExfiltrationDetector"
    mitre = ("T1041", "T1048")

    @classmethod
    def defaults(cls):
        return {"min_bytes": 100_000_000}

    def detect(self, events: list[EventRecord]) -> list[Finding]:
        by_pair: dict[tuple[str, str], list[EventRecord]] = defaultdict(list)
        for e in events:
            if is_internal(e.src_ip) and not is_internal(e.dst_ip) and e.bytes_sent > 0:
                by_pair[(e.src_ip, e.dst_ip)].append(e)
        out = []
        thr = self.params["min_bytes"]
        for (src, dst), evs in by_pair.items():
            total = sum(e.bytes_sent for e in evs)
            if total < thr:
                continue
            out.append(
                Finding(
                    detector=self.name, detection_class="RULE", event_type="possible_exfiltration",
                    severity=severity_from(total, thr, thr * 5, thr * 10), confidence=confidence_from(total, thr, 0.9),
                    source=src, destination=dst, timestamp=evs[0].ts,
                    explanation=f"{src} sent {total / 1e6:.0f} MB to external host {dst} across {len(evs)} sessions.",
                    evidence_ids=[e.id for e in evs][:50], mitre_techniques=list(self.mitre),
                    facts={"bytes_sent": total, "sessions": len(evs)},
                )
            )
        return out
