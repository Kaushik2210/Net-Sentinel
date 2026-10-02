from datetime import UTC, datetime, timedelta

from app.correlation import AlertLite, correlate
from app.services.risk import incident_risk

T0 = datetime(2026, 10, 2, 9, 0, tzinfo=UTC)


def al(i, minute, etype, src="10.0.20.22", dst="10.0.30.12", sev="medium", conf=0.9, cls="RULE", mitre=()):
    return AlertLite(id=f"alt_{i}", ts=T0 + timedelta(minutes=minute), source=src, destination=dst, event_type=etype,
                     detection_class=cls, severity=sev, confidence=conf, detector="D", mitre=mitre)


def chain():
    return [
        al(1, 0, "horizontal_sweep", dst="24 hosts"),
        al(2, 2, "vertical_port_scan", dst="10.0.30.12"),
        al(3, 4, "credential_attack", dst="10.0.20.35:22", sev="high"),
        al(4, 6, "possible_credential_compromise", dst="10.0.20.35:22", sev="high"),
        al(5, 8, "lateral_movement", dst="10.0.20.12, 10.0.30.12"),
        al(6, 12, "possible_exfiltration", dst="198.51.100.77", sev="critical"),
    ]


def test_related_alerts_become_one_ordered_incident():
    (inc,) = correlate(chain())
    expected = ["Reconnaissance", "Network Scanning", "Credential Attack", "Initial Access", "Lateral Movement", "Possible Exfiltration"]
    assert [s.stage for s in inc.steps] == expected
    assert [s.position for s in inc.steps] == list(range(6))
    assert inc.steps[0].link_reason == "chain origin"
    assert all(s.link_confidence >= 0.9 for s in inc.steps[1:])  # same source + stage progression


def test_unrelated_sources_stay_separate():
    alerts = chain() + [al(9, 5, "vertical_port_scan", src="10.0.20.99", dst="10.0.30.50")]
    drafts = correlate(alerts)
    assert len(drafts) == 1 and "alt_9" not in drafts[0].alert_ids  # lone alert is not an incident


def test_temporal_gap_breaks_the_chain():
    far = [al(1, 0, "horizontal_sweep"), al(2, 90, "possible_exfiltration", dst="198.51.100.9")]
    assert correlate(far) == []


def test_pivot_links_a_new_source_to_an_earlier_target():
    alerts = [
        al(1, 0, "credential_attack", src="10.0.20.22", dst="10.0.20.35:22"),
        al(2, 5, "lateral_movement", src="10.0.20.35", dst="10.0.30.12"),
    ]
    (inc,) = correlate(alerts)
    assert "pivot" in inc.steps[1].link_reason and inc.steps[1].link_confidence < 0.9


def test_supporting_signals_attach_but_are_not_chain_steps():
    alerts = chain() + [al(7, 13, "ml_anomaly", cls="ML"), al(8, 13, "behavior_deviation", cls="BEHAVIORAL"),
                        al(10, 13, "ml_anomaly", src="10.0.20.150", cls="ML")]
    (inc,) = correlate(alerts)
    assert len(inc.steps) == 6
    assert {a.id for a in inc.supporting} == {"alt_7", "alt_8"}  # other host's ML alert is not attached


def test_risk_is_a_sum_of_named_factors_and_capped():
    (inc,) = correlate(chain() + [al(7, 13, "ml_anomaly", cls="ML")])
    score, factors = incident_risk(inc, max_asset_criticality=5)
    assert score == min(100, sum(f["points"] for f in factors))
    keys = {f["key"] for f in factors}
    assert {"severity", "chain", "related_events", "external", "asset", "anomaly"} <= keys
    assert factors == sorted(factors, key=lambda f: f["points"], reverse=True)
    assert 60 <= score <= 100


def test_single_low_alert_pair_scores_lower_than_full_chain():
    small = correlate([al(1, 0, "horizontal_sweep", sev="low"), al(2, 1, "vertical_port_scan", sev="low")])[0]
    full = correlate(chain())[0]
    assert incident_risk(small, 2)[0] < incident_risk(full, 2)[0]
