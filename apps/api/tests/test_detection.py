from datetime import UTC, datetime, timedelta

from app.detection import DetectionEngine, Detector, EventRecord, register, registry
from app.detection.auth import BruteForceDetector, LateralMovementDetector
from app.detection.custom import CustomRuleDetector
from app.detection.recon import PortScanDetector, SuspiciousProtocolDetector
from app.detection.traffic import DataExfiltrationDetector, DNSAnomalyDetector
from app.services import scenarios, topology
from app.services.simulation import SimulationSource

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)


def ev(i, src="10.0.20.22", dst="10.0.30.12", port=22, etype="conn_attempt", **kw):
    return EventRecord(id=f"evt_{i}", ts=NOW + timedelta(seconds=i), src_ip=src, dst_ip=dst, dst_port=port,
                       protocol=kw.pop("protocol", "tcp"), event_type=etype, **kw)


def devices():
    specs = topology.build_devices(7)
    return [{"id": f"dev_{i}", "hostname": s.hostname, "ip": s.ip, "device_type": s.device_type} for i, s in enumerate(specs)]


def test_all_builtin_detectors_registered():
    assert {"PortScanDetector", "BruteForceDetector", "DNSAnomalyDetector", "ConnectionAnomalyDetector", "DataExfiltrationDetector",
            "LateralMovementDetector", "SuspiciousProtocolDetector", "CustomRuleDetector"} <= set(registry())


def test_port_scan_fires_with_evidence_and_mitre():
    events = [ev(i, port=1000 + i) for i in range(20)]
    (f,) = PortScanDetector().detect(events)
    assert f.event_type == "vertical_port_scan" and "T1046" in f.mitre_techniques
    assert f.facts["distinct_ports"] == 20 and len(f.evidence_ids) == 20
    assert 0.5 < f.confidence < 1.0 and f.detection_class == "RULE"


def test_port_scan_below_threshold_is_silent():
    assert PortScanDetector().detect([ev(i, port=1000 + i) for i in range(5)]) == []


def test_horizontal_sweep():
    events = [ev(i, dst=f"10.0.20.{i}", port=443) for i in range(12)]
    (f,) = PortScanDetector().detect(events)
    assert f.event_type == "horizontal_sweep"


def test_brute_force_counts_failures_not_successes():
    fails = [ev(i, etype="auth_failure", port=22, attributes={"user": "root"}) for i in range(12)]
    ok = [ev(99, etype="auth_success", port=22)]
    (f,) = BruteForceDetector().detect(fails + ok)
    assert f.facts["failures"] == 12 and f.severity in {"low", "medium", "high", "critical"}
    assert BruteForceDetector().detect(fails[:5]) == []


def test_lateral_movement_needs_multiple_internal_hosts():
    ok = [ev(i, dst=f"10.0.20.{30 + i}", port=22, etype="auth_success") for i in range(3)]
    (f,) = LateralMovementDetector().detect(ok)
    assert "T1021" in f.mitre_techniques and f.facts["hosts"] == 3
    assert LateralMovementDetector().detect(ok[:2]) == []


def test_exfiltration_ignores_internal_destinations():
    big_internal = [ev(i, dst="10.0.30.12", etype="tls_session", bytes_sent=50_000_000) for i in range(5)]
    big_external = [ev(i, dst="198.51.100.9", etype="tls_session", bytes_sent=50_000_000) for i in range(5)]
    assert DataExfiltrationDetector().detect(big_internal) == []
    (f,) = DataExfiltrationDetector().detect(big_external)
    assert f.facts["bytes_sent"] == 250_000_000


def test_dns_tunneling_by_entropy():
    odd = [ev(i, dst="10.0.10.14", port=53, etype="dns_query", attributes={"domain": "q9x8z7w6v5u4t3s2r1p0.evil.example"}) for i in range(20)]
    (f,) = DNSAnomalyDetector().detect(odd)
    assert f.event_type == "dns_tunneling_suspected"


def test_suspicious_protocol_ports():
    events = [ev(i, dst="198.51.100.5", port=4444, etype="tls_session") for i in range(4)]
    (f,) = SuspiciousProtocolDetector().detect(events)
    assert f.facts["label"] == "common-backdoor"


def test_custom_rule_is_data_driven_and_safe():
    rule = {"title": "RDP from workstation", "dst_port": [3389], "min_count": 2, "severity": "high", "mitre": ["T1021"]}
    events = [ev(i, port=3389, etype="auth_success") for i in range(3)]
    (f,) = CustomRuleDetector(rules=[rule]).detect(events)
    assert f.severity == "high" and "RDP from workstation" in f.explanation


def test_detector_plugin_without_touching_other_modules():
    @register
    class Marker(Detector):
        name = "MarkerDetector"

        def detect(self, events):
            return []

    assert "MarkerDetector" in registry() and Marker().detect([]) == []


def test_engine_isolates_failing_detector():
    class Boom(Detector):
        name = "Boom"

        def detect(self, events):
            raise RuntimeError("bad plugin")

    findings = DetectionEngine([Boom(), PortScanDetector()]).run([ev(i, port=1000 + i) for i in range(20)])
    assert len(findings) == 1  # the healthy detector still ran


def test_no_false_positives_on_an_hour_of_benign_traffic():
    src = SimulationSource(devices(), seed=7, now_fn=lambda: NOW)
    t = [NOW]
    raw = []
    for _ in range(4 * 600):  # 600 s at 4 ev/s, the default simulation rate
        e = src.next_event()
        e["ts"] = t[0]
        t[0] += timedelta(milliseconds=250)
        raw.append(EventRecord(id=e["id"], ts=e["ts"], src_ip=e["src_ip"], dst_ip=e["dst_ip"], dst_port=e["dst_port"], protocol=e["protocol"],
                               event_type=e["event_type"], bytes_sent=e["bytes_sent"], bytes_received=e["bytes_received"], attributes=e["attributes"]))
    assert DetectionEngine().run(raw) == []


def test_attack_scenario_is_detected_end_to_end():
    d = devices()
    raw = scenarios.generate_attack(d, NOW)
    assert {e["source"] for e in raw} == {"sim-attack"}
    records = [EventRecord(id=e["id"], ts=e["ts"], src_ip=e["src_ip"], dst_ip=e["dst_ip"], dst_port=e["dst_port"], protocol=e["protocol"],
                           event_type=e["event_type"], bytes_sent=e["bytes_sent"], bytes_received=e["bytes_received"], attributes=e["attributes"]) for e in raw]
    findings = DetectionEngine().run(records)
    kinds = {f.event_type for f in findings}
    assert {"vertical_port_scan", "horizontal_sweep", "credential_attack", "lateral_movement", "possible_exfiltration"} <= kinds
    assert all(f.source == "10.0.20.22" for f in findings)
    techniques = {t for f in findings for t in f.mitre_techniques}
    assert {"T1046", "T1110", "T1021", "T1041"} <= techniques
