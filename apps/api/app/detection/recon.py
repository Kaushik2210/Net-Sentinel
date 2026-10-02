from collections import defaultdict

from app.detection.base import Detector, EventRecord, Finding, confidence_from, is_internal, register, severity_from


@register
class PortScanDetector(Detector):
    name = "PortScanDetector"
    mitre = ("T1046", "T1595")

    @classmethod
    def defaults(cls):
        return {"min_ports": 15, "min_hosts": 10}

    def detect(self, events: list[EventRecord]) -> list[Finding]:
        by_src: dict[str, list[EventRecord]] = defaultdict(list)
        for e in events:
            if e.event_type == "conn_attempt":
                by_src[e.src_ip].append(e)
        out: list[Finding] = []
        for src, evs in by_src.items():
            ports_by_dst: dict[str, set[int]] = defaultdict(set)
            for e in evs:
                if e.dst_port:
                    ports_by_dst[e.dst_ip].add(e.dst_port)
            dst, ports = max(ports_by_dst.items(), key=lambda kv: len(kv[1]), default=("", set()))
            hosts = len(ports_by_dst)
            # Independent checks: a sweep (many hosts) and a port scan (many ports on one host) are
            # different behaviours and map to different stages, so one source can trigger both.
            checks = []
            if len(ports) >= self.params["min_ports"]:
                checks.append(("vertical_port_scan", len(ports), self.params["min_ports"], dst,
                               f"{src} probed {len(ports)} distinct ports on {dst}.", [e for e in evs if e.dst_ip == dst]))
            if hosts >= self.params["min_hosts"]:
                checks.append(("horizontal_sweep", hosts, self.params["min_hosts"], f"{hosts} hosts",
                               f"{src} probed {hosts} distinct hosts.", evs))
            for kind, count, thr, target, expl, used in checks:
                out.append(
                    Finding(
                        detector=self.name, detection_class="RULE", event_type=kind,
                        severity=severity_from(count, thr, thr * 3, thr * 10), confidence=confidence_from(count, thr),
                        source=src, destination=target, timestamp=min(e.ts for e in used), explanation=expl,
                        evidence_ids=[e.id for e in used][:50], mitre_techniques=list(self.mitre),
                        facts={"distinct_ports": len(ports), "distinct_hosts": hosts, "probes": len(used), "internal_source": is_internal(src)},
                    )
                )
        return out


@register
class SuspiciousProtocolDetector(Detector):
    name = "SuspiciousProtocolDetector"
    mitre = ("T1571",)

    @classmethod
    def defaults(cls):
        # Ports rarely legitimate in this environment: telnet, IRC, Tor relay, common backdoor default.
        return {"ports": {23: "telnet", 6667: "irc", 9001: "tor-relay", 4444: "common-backdoor"}, "min_events": 3}

    def detect(self, events: list[EventRecord]) -> list[Finding]:
        hits: dict[tuple[str, str, int], list[EventRecord]] = defaultdict(list)
        for e in events:
            if e.event_type != "conn_attempt" and e.dst_port in self.params["ports"]:
                hits[(e.src_ip, e.dst_ip, e.dst_port)].append(e)
        out = []
        for (src, dst, port), evs in hits.items():
            if len(evs) < self.params["min_events"]:
                continue
            label = self.params["ports"][port]
            out.append(
                Finding(
                    detector=self.name, detection_class="RULE", event_type="suspicious_protocol",
                    severity="medium" if len(evs) < 20 else "high",
                    confidence=confidence_from(len(evs), self.params["min_events"], 0.9),
                    source=src, destination=f"{dst}:{port}", timestamp=evs[0].ts,
                    explanation=f"{src} made {len(evs)} connections to port {port} ({label}), unexpected in this network.",
                    evidence_ids=[e.id for e in evs][:50], mitre_techniques=list(self.mitre),
                    facts={"port": port, "label": label, "count": len(evs)},
                )
            )
        return out
