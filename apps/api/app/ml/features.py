"""Per-source feature extraction for the anomaly model.

One row per source IP over a fixed window. Count-like features are normalised to per-minute
rates so windows of different length stay comparable; "unique" features are raw because their
growth with time is itself informative.
"""

import math
from collections import Counter, defaultdict

import pandas as pd

from app.detection.base import EventRecord, is_internal

WINDOW_SECONDS = 600
MIN_EVENTS = 5  # below this a source has too little data to score honestly

FEATURES = [
    "conn_per_min",
    "bytes_sent_per_min",
    "bytes_recv_per_min",
    "unique_destinations",
    "unique_ports",
    "failed_per_min",
    "dns_per_min",
    "protocol_entropy",
    "mean_duration_ms",
    "outbound_ratio",
]

FEATURE_LABELS = {
    "conn_per_min": "connection rate",
    "bytes_sent_per_min": "bytes sent / min",
    "bytes_recv_per_min": "bytes received / min",
    "unique_destinations": "unique destinations",
    "unique_ports": "unique destination ports",
    "failed_per_min": "failed connections / min",
    "dns_per_min": "DNS queries / min",
    "protocol_entropy": "protocol diversity",
    "mean_duration_ms": "mean connection duration",
    "outbound_ratio": "outbound / inbound byte ratio",
}


def _entropy(values: list[str]) -> float:
    c = Counter(values)
    n = len(values)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


def extract_features(events: list[EventRecord], window_seconds: int = WINDOW_SECONDS, internal_only: bool = True) -> pd.DataFrame:
    """Return a DataFrame indexed by source IP with columns ``FEATURES``.

    ``internal_only`` restricts profiling to RFC1918-style internal hosts (the live default); datasets that use public-looking
    addresses pass False.
    """
    minutes = window_seconds / 60
    by_src: dict[str, list[EventRecord]] = defaultdict(list)
    for e in events:
        if not internal_only or is_internal(e.src_ip):
            by_src[e.src_ip].append(e)

    rows, index = [], []
    for src, evs in by_src.items():
        if len(evs) < MIN_EVENTS:
            continue
        sent = sum(e.bytes_sent for e in evs)
        recv = sum(e.bytes_received for e in evs)
        failed = sum(1 for e in evs if e.event_type == "auth_failure" or (e.event_type == "conn_attempt"))
        rows.append({
            "conn_per_min": len(evs) / minutes,
            "bytes_sent_per_min": sent / minutes,
            "bytes_recv_per_min": recv / minutes,
            "unique_destinations": len({e.dst_ip for e in evs}),
            "unique_ports": len({e.dst_port for e in evs if e.dst_port}),
            "failed_per_min": failed / minutes,
            "dns_per_min": sum(1 for e in evs if e.event_type == "dns_query") / minutes,
            "protocol_entropy": _entropy([e.protocol for e in evs]),
            "mean_duration_ms": sum(e.duration_ms for e in evs) / len(evs),
            "outbound_ratio": sent / (recv + 1),
        })
        index.append(src)
    return pd.DataFrame(rows, index=index, columns=FEATURES)
