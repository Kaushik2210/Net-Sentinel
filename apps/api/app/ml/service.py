"""Training and scoring entry points. The model is trained lazily on synthetic benign telemetry."""

import threading
from datetime import UTC, datetime, timedelta

import pandas as pd

from app.detection.base import EventRecord
from app.ml.features import WINDOW_SECONDS, extract_features
from app.ml.model import AnomalyModel, AnomalyResult, IsolationForestModel
from app.services import topology
from app.services.simulation import SimulationSource

_lock = threading.Lock()
_model: AnomalyModel | None = None

TRAIN_RUNS = 12  # independent benign 10-minute windows, each contributing one row per active device
EVENT_RATE = 4.0  # events/second, matching the default simulation rate


def _benign_training_frame(seed: int) -> pd.DataFrame:
    specs = topology.build_devices(seed)
    devices = [{"id": f"dev_{i}", "hostname": s.hostname, "ip": s.ip, "device_type": s.device_type} for i, s in enumerate(specs)]
    frames = []
    start = datetime(2026, 1, 1, tzinfo=UTC)
    n_events = int(WINDOW_SECONDS * EVENT_RATE)
    for run in range(TRAIN_RUNS):
        t = [start]
        src = SimulationSource(devices, seed=seed + run * 17, now_fn=lambda t=t: t[0])
        recs = []
        for _ in range(n_events):
            e = src.next_event()
            recs.append(
                EventRecord(
                    id=e["id"], ts=t[0], src_ip=e["src_ip"], dst_ip=e["dst_ip"], dst_port=e["dst_port"], protocol=e["protocol"],
                    event_type=e["event_type"], bytes_sent=e["bytes_sent"], bytes_received=e["bytes_received"],
                    duration_ms=e["duration_ms"], attributes=e["attributes"],
                )
            )
            t[0] += timedelta(seconds=1 / EVENT_RATE)
        frames.append(extract_features(recs))
    return pd.concat(frames, ignore_index=True)


def get_model(seed: int = 1337) -> AnomalyModel:
    global _model
    with _lock:
        if _model is None:
            m = IsolationForestModel()
            m.fit(_benign_training_frame(seed))
            _model = m
        return _model


def score_events(events: list[EventRecord]) -> list[AnomalyResult]:
    if not events:
        return []
    latest = max(e.ts for e in events)
    window = [e for e in events if e.ts >= latest - timedelta(seconds=WINDOW_SECONDS)]
    return get_model().score(extract_features(window))
