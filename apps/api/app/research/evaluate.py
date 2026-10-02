"""Evaluation harness: rule-based vs ML vs hybrid on labelled synthetic trials.

Unit of evaluation: one *source host in one 10-minute window*. A window is benign background traffic from all
46 simulated devices; an attack trial additionally injects one behaviour from one chosen host. The label of a
(window, source) pair is 1 only for the injected host. A detector "flags" a source if it emits a finding for it.

Honesty (surfaced in the UI and docs): the benign model, the attacks and the detector thresholds were all written
by the same author. These numbers demonstrate the methodology and the rule/ML trade-off on controlled cases. They are
NOT evidence of real-world accuracy; that requires public datasets (see docs/DATASETS.md).

Each attack type runs at two intensities: *strong* (clearly above rule thresholds) and *subtle* (deliberately below).
"""

import random
import statistics
import string
from datetime import UTC, datetime, timedelta

from app.detection import DetectionEngine, EventRecord, registry
from app.detection.ml import MLAnomalyDetector
from app.ml.service import get_model
from app.models.base import new_id
from app.services import topology
from app.services.simulation import SimulationSource

WINDOW_S = 600
RATE = 4.0
T0 = datetime(2026, 3, 1, tzinfo=UTC)
EXTERNAL = "198.51.100.200"
ATTACKS = ["port_scan", "brute_force", "exfiltration", "dns_tunnel", "lateral_movement"]
# (strong, subtle) intensity per attack type; subtle sits below the default detector thresholds.
INTENSITY = {
    "port_scan": (40, 8), "brute_force": (40, 6), "exfiltration": (6, 2), "dns_tunnel": (40, 8), "lateral_movement": (4, 2),
}
METHODS = ("rule", "ml", "hybrid")


def _rec(i, ts, src, dst, port, proto, etype, sent=0, recv=0, dur=0, **attrs) -> EventRecord:
    return EventRecord(id=new_id("evt"), ts=ts, src_ip=src, dst_ip=dst, dst_port=port, protocol=proto, event_type=etype,
                       bytes_sent=sent, bytes_received=recv, duration_ms=dur, attributes=attrs)


def _background(devices: list[dict], seed: int) -> list[EventRecord]:
    t = [T0]
    src = SimulationSource(devices, seed=seed, now_fn=lambda: t[0])
    out = []
    for _ in range(int(WINDOW_S * RATE)):
        e = src.next_event()
        out.append(EventRecord(id=e["id"], ts=t[0], src_ip=e["src_ip"], dst_ip=e["dst_ip"], dst_port=e["dst_port"], protocol=e["protocol"],
                               event_type=e["event_type"], bytes_sent=e["bytes_sent"], bytes_received=e["bytes_received"],
                               duration_ms=e["duration_ms"], attributes=e["attributes"]))
        t[0] += timedelta(seconds=1 / RATE)
    return out


def _inject(kind: str, n: int, attacker: dict, devices: list[dict], rng: random.Random) -> list[EventRecord]:
    """Events for one attack behaviour, spread across minutes 2-8 of the window."""
    src = attacker["ip"]
    others = [d for d in devices if d["ip"] != src and d["device_type"] != "internet"]
    when = lambda k: T0 + timedelta(seconds=120 + (360 * k / max(n, 1)))  # noqa: E731
    out: list[EventRecord] = []
    if kind == "port_scan":
        victim = rng.choice(others)["ip"]
        for k, port in enumerate(rng.sample(range(20, 9000), n)):
            out.append(_rec(k, when(k), src, victim, port, "tcp", "conn_attempt", state="rejected"))
    elif kind == "brute_force":
        victim = rng.choice(others)["ip"]
        for k in range(n):
            out.append(_rec(k, when(k), src, victim, 22, "ssh", "auth_failure", user=rng.choice(["root", "admin", "deploy"])))
    elif kind == "exfiltration":
        for k in range(n):
            out.append(_rec(k, when(k), src, EXTERNAL, 443, "tls", "tls_session", sent=20_000_000 if n <= 2 else 30_000_000, recv=3000, dur=4000))
    elif kind == "dns_tunnel":
        for k in range(n):
            label = "".join(rng.choices(string.ascii_lowercase + string.digits, k=26))
            out.append(_rec(k, when(k), src, "10.0.10.14", 53, "dns", "dns_query", sent=180, domain=f"{label}.bench.example"))
    elif kind == "lateral_movement":
        for k, victim in enumerate(rng.sample(others, n)):
            out.append(_rec(k, when(k), src, victim["ip"], 22, "ssh", "auth_success", user="svc"))
    return out


def _flagged(events: list[EventRecord], rule_engine: DetectionEngine, ml: MLAnomalyDetector) -> dict[str, set[str]]:
    rule = {f.source for f in rule_engine.run(events)}
    mlf = {f.source for f in ml.detect(events)}
    return {"rule": rule, "ml": mlf, "hybrid": rule | mlf}


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else (0.0 if prec is not None and rec is not None else None)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": prec, "recall": rec, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else None, "accuracy": (tp + tn) / (tp + fp + tn + fn)}


def run_evaluation(seed: int = 2024, benign_trials: int = 30, repeats: int = 4, latency_repeats: int = 2) -> dict:
    rng = random.Random(seed)  # noqa: S311 - deterministic benchmark data
    specs = topology.build_devices(1337)
    devices = [{"id": f"dev_{i}", "hostname": s.hostname, "ip": s.ip, "device_type": s.device_type} for i, s in enumerate(specs)]
    internal = [d for d in devices if d["device_type"] not in ("internet",)]
    rule_engine = DetectionEngine([cls() for n, cls in registry().items() if n != "MLAnomalyDetector"])
    ml = MLAnomalyDetector()

    counts = {m: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for m in METHODS}
    by_type: dict[str, dict[str, dict[str, list[int]]]] = {a: {i: {m: [] for m in METHODS} for i in ("strong", "subtle")} for a in ATTACKS}
    trials = 0

    def score(events: list[EventRecord], attacker_ip: str | None):
        flagged = _flagged(events, rule_engine, ml)
        sources = {e.src_ip for e in events if e.src_ip.startswith(("10.", "172."))}
        for m in METHODS:
            for s in sources:
                truth, pred = s == attacker_ip, s in flagged[m]
                key = ("tp" if pred else "fn") if truth else ("fp" if pred else "tn")
                counts[m][key] += 1
        return flagged

    for k in range(benign_trials):
        score(_background(devices, seed + 1000 + k), None)
        trials += 1

    for attack in ATTACKS:
        for intensity, n in zip(("strong", "subtle"), INTENSITY[attack], strict=True):
            for _ in range(repeats):
                attacker = rng.choice(internal)
                bg = _background(devices, seed + 5000 + trials)
                ev = sorted(bg + _inject(attack, n, attacker, devices, rng), key=lambda e: e.ts)
                flagged = score(ev, attacker["ip"])
                for m in METHODS:
                    by_type[attack][intensity][m].append(1 if attacker["ip"] in flagged[m] else 0)
                trials += 1

    # Detection latency: seconds from the first injected event until the first 60 s checkpoint at which the host is flagged.
    latencies: dict[str, list[float]] = {m: [] for m in METHODS}
    missed: dict[str, int] = {m: 0 for m in METHODS}
    for attack in ATTACKS:
        for _ in range(latency_repeats):
            attacker = rng.choice(internal)
            injected = _inject(attack, INTENSITY[attack][0], attacker, devices, rng)
            ev = sorted(_background(devices, seed + 9000 + trials) + injected, key=lambda e: e.ts)
            trials += 1
            start = min(e.ts for e in injected)
            first = dict.fromkeys(METHODS)
            for cp in range(60, WINDOW_S + 1, 60):
                cutoff = T0 + timedelta(seconds=cp)
                if cutoff <= start:
                    continue  # latency is only meaningful once the attack has begun
                part = [e for e in ev if e.ts <= cutoff]
                flagged = _flagged(part, rule_engine, ml)
                for m in METHODS:
                    if first[m] is None and attacker["ip"] in flagged[m]:
                        first[m] = max(0.0, (cutoff - start).total_seconds())
            for m in METHODS:
                if first[m] is None:
                    missed[m] += 1
                else:
                    latencies[m].append(first[m])

    results = {}
    for m in METHODS:
        c = counts[m]
        lat = latencies[m]
        results[m] = {**_metrics(**c), "latency_median_s": statistics.median(lat) if lat else None,
                      "latency_p90_s": sorted(lat)[int(0.9 * (len(lat) - 1))] if lat else None, "latency_missed": missed[m]}
    recall_by_type = {
        a: {i: {m: (sum(v) / len(v)) for m, v in by_type[a][i].items()} for i in ("strong", "subtle")} for a in ATTACKS
    }
    desc = get_model().describe()
    return {
        "generated_at": datetime.now(UTC).isoformat(), "seed": seed, "trials": trials,
        "dataset": {"name": "synthetic-benchmark", "kind": "synthetic", "benign_windows": benign_trials, "attack_windows": len(ATTACKS) * 2 * repeats,
                    "unit": "source host x 10-minute window", "attacks": ATTACKS, "intensities": {"strong": "above rule thresholds", "subtle": "below rule thresholds"}},
        "model": {"algorithm": desc["algorithm"], "features": desc["features"], "training_windows": desc["training_windows"], "trained_on": desc["trained_on"]},
        "methods": results, "recall_by_attack": recall_by_type,
        "latency_note": "Measured at 60-second checkpoints on strong attacks, so resolution is 60 s.",
        "caveats": [
            "Synthetic data authored alongside the detectors: demonstrates methodology, not real-world accuracy.",
            "Benign traffic comes from one homogeneous simulator; real networks are noisier, so false-positive rates here are optimistic.",
            "Subtle intensities were chosen to sit below rule thresholds, which favours any method that is not threshold-based.",
        ],
    }
