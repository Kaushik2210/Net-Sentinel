from datetime import UTC, datetime

import pytest

from app.detection import EventRecord
from app.detection.ml import MLAnomalyDetector
from app.ml import service as ml_service
from app.ml.features import FEATURES, MIN_EVENTS, extract_features
from app.ml.model import AnomalyModel, IsolationForestModel
from app.ml.service import _benign_training_frame, get_model, score_events
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


def _benign_records(seconds: float):
    from datetime import timedelta

    from app.services.simulation import SimulationSource

    specs = topology.build_devices(1337)
    devs = [{"id": f"d{i}", "hostname": s.hostname, "ip": s.ip, "device_type": s.device_type} for i, s in enumerate(specs)]
    t = [NOW]
    src = SimulationSource(devs, seed=31, now_fn=lambda: t[0])
    out = []
    for _ in range(int(seconds * 4)):
        e = src.next_event()
        out.append(EventRecord(id=e["id"], ts=t[0], src_ip=e["src_ip"], dst_ip=e["dst_ip"], dst_port=e["dst_port"], protocol=e["protocol"],
                               event_type=e["event_type"], bytes_sent=e["bytes_sent"], bytes_received=e["bytes_received"],
                               duration_ms=e["duration_ms"], attributes=e["attributes"]))
        t[0] += timedelta(seconds=0.25)
    return out


def test_partial_window_is_not_scored_regression():
    """Regression: 30 s of benign traffic scored against 10-minute baselines made every host look anomalously quiet."""
    short = _benign_records(30)
    assert score_events(short) == []
    assert MLAnomalyDetector().detect(short) == []


def test_full_benign_window_raises_no_ml_alert_through_the_detector():
    assert MLAnomalyDetector().detect(_benign_records(600)) == []


def test_warmup_follows_ingest_uptime(monkeypatch):
    import time

    monkeypatch.setattr(ml_service, "_ingest_started", None)
    assert ml_service.is_warm()  # nothing live to wait for (idle mode, tests, replay)
    monkeypatch.setattr(ml_service, "_ingest_started", time.monotonic())
    assert not ml_service.is_warm()
    monkeypatch.setattr(ml_service, "_ingest_started", time.monotonic() - 0.76 * ml_service.WINDOW_SECONDS)
    assert ml_service.is_warm()


def test_live_cycle_drops_ml_alerts_during_warmup_even_with_backdated_events(client, monkeypatch):
    """Regression: a back-dated attack made the data span look full while benign traffic was minutes old."""
    import time
    from datetime import UTC, datetime

    from sqlalchemy import select

    from app.core.config import get_settings
    from app.db.session import SessionLocal
    from app.models import Alert, Device, NetworkEvent
    from app.services import scenarios
    from app.services.alerts import run_detection_cycle

    monkeypatch.setattr(ml_service, "_ingest_started", time.monotonic())  # just started
    get_settings().telemetry_mode = "simulation"
    try:
        with SessionLocal() as db:
            devs = [{"id": d.id, "hostname": d.hostname, "ip": d.ip, "device_type": d.device_type} for d in db.scalars(select(Device))]
            db.add_all(NetworkEvent(**e) for e in scenarios.generate_attack(devs, datetime.now(UTC), seed=99))
            db.commit()
            created = run_detection_cycle(db, 900)
            assert created and {a.detection_class for a in created}.isdisjoint({"ML"})
            assert any(a.detection_class == "RULE" for a in created)  # rules are unaffected by warm-up
            for model in (Alert,):
                db.query(model).delete()
            db.query(NetworkEvent).filter(NetworkEvent.source == scenarios.SOURCE).delete()
            db.commit()
    finally:
        get_settings().telemetry_mode = "idle"
