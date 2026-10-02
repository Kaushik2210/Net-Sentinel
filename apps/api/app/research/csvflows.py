"""Evaluate rule / ML / hybrid on a labelled flow CSV (CICIDS2017-style or UNSW-NB15-style).

NetSentinel does not bundle these datasets. Obtain them from their publishers under their licences, then:

    python -m app.research.csvflows --schema cicids2017 --csv Monday-WorkingHours.pcap_ISCX.csv --max-rows 300000

Method
* Each flow row becomes a normalized event (same vocabulary as PCAP/Zeek). The datasets carry no handshake state, so a
  flow with no payload in either direction is treated as a ``conn_attempt`` (documented heuristic).
* Unit of evaluation: (source host, 10-minute window). Its label is 1 if any flow from that host in that window is labelled malicious.
* Chronological split: the ML model is trained **only on benign units from the first half of the time range**; all methods are scored
  on units from the second half. Rules need no training. This avoids training on test data.
* The ML gate is the same as in live detection (risk >= 50 and a >= 6 sigma deviation on some feature).

Validation status (honest): this loader was tested on small hand-built CSVs that follow the published column names, not on the
real datasets, which were not available when it was written. Column names and timestamp formats of real files may need adjusting in ``SCHEMAS``.
"""

import argparse
import json

import pandas as pd

from app.detection import DetectionEngine, EventRecord, registry
from app.ingest.pcap import flow_event
from app.ml.features import extract_features
from app.ml.model import IsolationForestModel
from app.research.evaluate import METHODS, _metrics

WINDOW_S = 600
SCHEMAS = {
    "cicids2017": {
        "ts": "Timestamp", "src": "Source IP", "dst": "Destination IP", "dport": "Destination Port", "dur": "Flow Duration", "dur_scale": 1e-6,
        "fwd": "Total Length of Fwd Packets", "bwd": "Total Length of Bwd Packets", "label": "Label", "benign": "BENIGN", "epoch": False,
        "ts_formats": ["%m/%d/%Y %H:%M", "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"], "ml_internal_only": True,
    },
    "unsw-nb15": {
        "ts": "stime", "src": "srcip", "dst": "dstip", "dport": "dsport", "dur": "dur", "dur_scale": 1.0,
        "fwd": "sbytes", "bwd": "dbytes", "label": "label", "benign": "0", "epoch": True, "ts_formats": [], "ml_internal_only": False,
    },
}


def _epoch(ts: pd.Series) -> pd.Series:
    # total_seconds() is independent of the datetime resolution pandas chose (ns, us, ...); astype(int64) is not.
    return (ts - pd.Timestamp("1970-01-01")).dt.total_seconds()


def _parse_ts(series: pd.Series, schema: dict) -> pd.Series:
    if schema["epoch"]:
        return pd.to_numeric(series, errors="coerce")
    for fmt in schema["ts_formats"]:
        parsed = pd.to_datetime(series, format=fmt, errors="coerce")
        if parsed.notna().mean() > 0.9:
            return _epoch(parsed)
    return _epoch(pd.to_datetime(series, errors="coerce"))


def load_flows(path: str, schema_name: str, max_rows: int = 500_000) -> tuple[list[EventRecord], dict[str, bool], dict]:
    s = SCHEMAS[schema_name]
    events, labels = [], {}
    rows = skipped = 0
    for chunk in pd.read_csv(path, chunksize=100_000, low_memory=False, skipinitialspace=True):
        chunk.columns = chunk.columns.str.strip()
        missing = [c for c in (s["ts"], s["src"], s["dst"], s["dport"], s["dur"], s["fwd"], s["bwd"], s["label"]) if c not in chunk.columns]
        if missing:
            raise ValueError(f"columns missing for schema '{schema_name}': {missing}")
        chunk = chunk.assign(_t=_parse_ts(chunk[s["ts"]], s))
        for r in chunk.itertuples(index=False):
            rows += 1
            if rows > max_rows:
                break
            row = dict(zip(chunk.columns, r, strict=False))
            try:
                t = float(row["_t"])
                dport = int(float(row[s["dport"]]))
                fwd, bwd = max(int(float(row[s["fwd"]])), 0), max(int(float(row[s["bwd"]])), 0)
                dur = float(row[s["dur"]]) * s["dur_scale"]
            except (TypeError, ValueError):
                skipped += 1
                continue
            if t != t or not isinstance(row[s["src"]], str) or not isinstance(row[s["dst"]], str) or ":" in row[s["src"]]:
                skipped += 1
                continue
            ev = flow_event(row[s["src"]], row[s["dst"]], dport, t, dur, fwd, bwd, unanswered=(fwd == 0 and bwd == 0))
            events.append(ev)
            labels[ev.id] = str(row[s["label"]]).strip().upper() != s["benign"].upper()
        if rows > max_rows:
            break
    events.sort(key=lambda e: e.ts)
    return events, labels, {"rows_read": min(rows, max_rows), "rows_skipped": skipped, "events": len(events), "malicious_flows": sum(labels.values())}


def evaluate_flows(events: list[EventRecord], labels: dict[str, bool], schema_name: str = "cicids2017", min_train_units: int = 50) -> dict:
    if not events:
        raise ValueError("no events to evaluate")
    s = SCHEMAS[schema_name]
    t0 = events[0].ts
    win = lambda e: int((e.ts - t0).total_seconds() // WINDOW_S)  # noqa: E731
    by_window: dict[int, list[EventRecord]] = {}
    for e in events:
        by_window.setdefault(win(e), []).append(e)
    indices = sorted(by_window)
    split = indices[len(indices) // 2]

    engine = DetectionEngine([cls() for n, cls in registry().items() if n != "MLAnomalyDetector"])
    train_rows: list[pd.Series] = []
    unit_truth: dict[tuple[int, str], bool] = {}
    for w, evs in by_window.items():
        for e in evs:
            unit_truth[(w, e.src_ip)] = unit_truth.get((w, e.src_ip), False) or labels.get(e.id, False)
    feats = {}
    for w, evs in by_window.items():
        f = extract_features(evs, internal_only=s["ml_internal_only"])
        for src in f.index:
            feats[(w, src)] = f.loc[src]
        if w < split:
            for src in f.index:
                if not unit_truth.get((w, src), False):
                    train_rows.append(f.loc[src])
    if len(train_rows) < min_train_units:
        raise ValueError(f"only {len(train_rows)} benign training units in the first half (need {min_train_units}); use a larger slice")
    model = IsolationForestModel()
    model.fit(pd.DataFrame(train_rows).reset_index(drop=True))

    counts = {m: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for m in METHODS}
    for w in indices:
        if w < split:
            continue
        rule = {f.source for f in engine.run(by_window[w])}
        units = [(src, truth) for (ww, src), truth in unit_truth.items() if ww == w]
        frame = pd.DataFrame([feats[(w, src)] for src, _ in units if (w, src) in feats], index=[src for src, _ in units if (w, src) in feats])
        ml = {r.entity for r in model.score(frame) if r.risk >= 50 and max(abs(c.z) for c in r.contributions) >= 6} if len(frame) else set()
        for src, truth in units:
            for m, flagged in (("rule", rule), ("ml", ml), ("hybrid", rule | ml)):
                pred = src in flagged
                counts[m][("tp" if pred else "fn") if truth else ("fp" if pred else "tn")] += 1
    return {
        "dataset": {"schema": schema_name, "unit": "source host x 10-minute window", "train_units_benign": len(train_rows), "test_windows": len([i for i in indices if i >= split]),
                    "split": "chronological: ML trained on benign units from the first half only; all methods scored on the second half"},
        "methods": {m: _metrics(**counts[m]) for m in METHODS},
        "caveats": [
            "Flow CSVs carry no handshake state or authentication events, so several rule detectors have little or no input.",
            "Labels are per flow; a unit is malicious if any flow from that host in the window is.",
            "Validated only on hand-built CSVs in these schemas, not on the published datasets.",
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate rule/ML/hybrid on a labelled flow CSV")
    ap.add_argument("--schema", choices=sorted(SCHEMAS), required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--max-rows", type=int, default=500_000)
    a = ap.parse_args()
    events, labels, info = load_flows(a.csv, a.schema, a.max_rows)
    result = evaluate_flows(events, labels, a.schema)
    result["load"] = info
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()

