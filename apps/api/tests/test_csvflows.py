import random

import pandas as pd
import pytest

from app.research.csvflows import SCHEMAS, evaluate_flows, load_flows

T0 = pd.Timestamp("2017-07-05 09:00:00")
COLS = [" Source IP", " Destination IP", " Destination Port", " Timestamp", " Flow Duration", " Total Length of Fwd Packets", " Total Length of Bwd Packets", " Label"]  # CICIDS headers carry leading spaces


def make_cicids_csv(path, seed=5):
    """A tiny CSV that follows the published CICIDS2017 column names. Mechanics only: not the real dataset."""
    rng = random.Random(seed)
    rows = []
    hosts = [f"192.168.10.{h}" for h in range(10, 40)]
    for minute in range(0, 120):  # two hours of benign traffic
        for h in hosts:
            if rng.random() < 0.6:
                t = T0 + pd.Timedelta(minutes=minute, seconds=rng.randint(0, 59))
                rows.append((h, f"203.0.113.{rng.randint(2, 40)}", 443, t.strftime("%m/%d/%Y %H:%M"), rng.randint(50_000, 3_000_000), rng.randint(300, 2000), rng.randint(1000, 8000), "BENIGN"))
    attacker = "192.168.10.99"
    for k in range(60):  # second half: port scan, zero-payload flows to one host
        t = T0 + pd.Timedelta(minutes=80, seconds=k)
        rows.append((attacker, "192.168.10.5", 1000 + k, t.strftime("%m/%d/%Y %H:%M"), 100, 0, 0, "PortScan"))
    for k in range(30):  # brute force: short, low-payload ssh
        t = T0 + pd.Timedelta(minutes=95, seconds=k)
        rows.append((attacker, "192.168.10.50", 22, t.strftime("%m/%d/%Y %H:%M"), 400_000, 120, 140, "SSH-Patator"))
    pd.DataFrame(rows, columns=COLS).sample(frac=1, random_state=1).to_csv(path, index=False)


@pytest.fixture(scope="module")
def csv_path(tmp_path_factory):
    p = tmp_path_factory.mktemp("flows") / "cicids_like.csv"
    make_cicids_csv(p)
    return str(p)


def test_loader_handles_cicids_headers_and_labels(csv_path):
    events, labels, info = load_flows(csv_path, "cicids2017")
    assert info["rows_skipped"] == 0 and info["events"] == len(events) == info["rows_read"]
    assert info["malicious_flows"] == 90 and sum(labels.values()) == 90
    assert [e.ts for e in events] == sorted(e.ts for e in events)
    assert events[0].ts.year == 2017 and events[-1].ts.year == 2017  # regression: pandas datetime resolution once produced 1970
    assert any(e.event_type == "conn_attempt" for e in events)  # zero-payload flows
    assert any(e.event_type == "auth_failure" for e in events)  # short ssh flows


def test_evaluation_uses_a_chronological_split_and_finds_the_attacker(csv_path):
    events, labels, _ = load_flows(csv_path, "cicids2017")
    r = evaluate_flows(events, labels, "cicids2017", min_train_units=20)
    assert "ML trained on benign units from the first half only" in r["dataset"]["split"]
    m = r["methods"]
    assert m["rule"]["tp"] >= 1 and m["rule"]["fn"] >= 0  # the scan/brute force are in the test half
    for k in ("rule", "ml", "hybrid"):
        assert m[k]["tp"] + m[k]["fn"] == m["rule"]["tp"] + m["rule"]["fn"]  # same units for every method
        assert m[k]["fpr"] is None or m[k]["fpr"] < 0.2
    assert m["hybrid"]["tp"] >= m["rule"]["tp"]
    assert any("not on the published datasets" in c for c in r["caveats"])


def test_missing_columns_and_too_little_training_data_fail_clearly(tmp_path):
    bad = tmp_path / "bad.csv"
    pd.DataFrame({"foo": [1]}).to_csv(bad, index=False)
    with pytest.raises(ValueError, match="columns missing"):
        load_flows(str(bad), "cicids2017")
    tiny = tmp_path / "tiny.csv"
    pd.DataFrame([("192.168.10.1", "203.0.113.2", 443, "07/05/2017 09:00", 1000, 100, 100, "BENIGN")] * 3 + [("192.168.10.1", "203.0.113.2", 443, "07/05/2017 12:00", 1000, 100, 100, "BENIGN")],
                 columns=COLS).to_csv(tiny, index=False)
    events, labels, _ = load_flows(str(tiny), "cicids2017")
    with pytest.raises(ValueError, match="benign training units"):
        evaluate_flows(events, labels, "cicids2017")


def test_schemas_describe_both_published_datasets():
    assert set(SCHEMAS) == {"cicids2017", "unsw-nb15"}
    assert SCHEMAS["unsw-nb15"]["epoch"] is True and SCHEMAS["unsw-nb15"]["ml_internal_only"] is False
