from datetime import UTC, datetime

import pytest

from app.detection import EventRecord
from app.detection.ml import MLAnomalyDetector
from app.ml.features import FEATURES, MIN_EVENTS, extract_features
from app.ml.model import AnomalyModel, IsolationForestModel
from app.ml.service import _benign_training_frame, get_model
from app.services import scenarios, topology

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)


def rec(i, src="10.0.20.5", dst="198.51.100.4", port=443, etype="tls_session", sent=500, recv=5000, proto="tls"):
    return EventRecord(id=f"e{i}", ts=NOW, src_ip=src, dst_ip=dst, dst_port=port, protocol=proto, event_type=etype,
                       bytes_sent=sent, bytes_received=recv, duration_ms=50)


def attack_records():
    specs = topology.build_devices(1337)
    devs = [{"id": f"d{i}", "hostname": s.hostname, "ip": s.ip, "device_type": s.device_type} for i, s in enumerate(specs)]
    return [
        EventRecord(id=e["id"], ts=e["ts"], src_ip=e["src_ip"], dst_ip=e["dst_ip"], dst_port=e["dst_port"], protocol=e["protocol"],
                    event_type=e["event_type"], bytes_sent=e["bytes_sent"], bytes_received=e["bytes_received"], attributes=e["attributes"])
        for e in scenarios.generate_attack(devs, NOW)
    ]


def test_features_shape_and_minimum_events():
    df = extract_features([rec(i) for i in range(MIN_EVENTS)] + [rec(99, src="10.0.20.6")])
    assert list(df.columns) == FEATURES
    assert list(df.index) == ["10.0.20.5"]  # the 1-event source is skipped, not scored on thin data
    assert df.loc["10.0.20.5", "unique_destinations"] == 1


def test_external_sources_are_not_profiled():
    assert extract_features([rec(i, src="198.51.100.9") for i in range(10)]).empty


def test_model_implements_swappable_interface_and_describes_itself():
    m = get_model()
    assert isinstance(m, AnomalyModel)
    d = m.describe()
    assert d["algorithm"] == "IsolationForest" and d["training_windows"] > 400 and d["features"] == FEATURES


def test_scores_bounded_and_explained():
    res = get_model().score(extract_features(attack_records()))
    assert res and all(0 <= r.risk <= 100 for r in res)
    top = res[0]
    assert top.entity == "10.0.20.22" and top.is_anomaly
    assert top.contributions and top.contributions[0].z > 6


def test_too_little_training_data_is_rejected():
    with pytest.raises(ValueError):
        IsolationForestModel().fit(_benign_training_frame(1).head(10))


def test_ml_detector_flags_attack_as_ml_class_without_naming_an_attack():
    (f,) = MLAnomalyDetector().detect(attack_records())
    assert f.detection_class == "ML" and f.event_type == "ml_anomaly" and f.mitre_techniques == []
    assert "Statistical outlier" in f.explanation and "Top drivers" in f.explanation
    assert f.facts["drivers"] and f.evidence_ids


@pytest.mark.parametrize("seed", [4242, 777])
def test_no_ml_alerts_on_held_out_benign_windows(seed):
    """Held-out benign windows (seeds not used in training) must not pass the alert gate."""
    frame = _benign_training_frame(seed)
    flagged = [r for r in get_model().score(frame) if r.risk >= 50 and max(abs(c.z) for c in r.contributions) >= 6]
    assert flagged == []
