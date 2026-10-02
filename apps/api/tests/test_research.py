import pytest

from app.research.evaluate import ATTACKS, METHODS, run_evaluation


@pytest.fixture(scope="module")
def small():
    return run_evaluation(seed=7, benign_trials=3, repeats=1, latency_repeats=1)


def test_confusion_counts_are_consistent(small):
    totals = {sum(small["methods"][m][k] for k in ("tp", "fp", "tn", "fn")) for m in METHODS}
    assert len(totals) == 1  # every method is scored on the same (window, source) pairs
    for m in METHODS:
        v = small["methods"][m]
        assert v["tp"] + v["fn"] == len(ATTACKS) * 2  # one attacker per attack trial
        for k in ("precision", "recall", "f1", "fpr", "accuracy"):
            assert v[k] is None or 0.0 <= v[k] <= 1.0


def test_hybrid_is_the_union_so_it_never_recalls_less(small):
    m = small["methods"]
    assert m["hybrid"]["recall"] >= max(m["rule"]["recall"], m["ml"]["recall"])
    assert m["hybrid"]["tp"] >= m["rule"]["tp"] and m["hybrid"]["tp"] >= m["ml"]["tp"]


def test_rules_catch_strong_but_not_subtle_attacks(small):
    for a in ATTACKS:
        assert small["recall_by_attack"][a]["strong"]["rule"] == 1.0, a
        assert small["recall_by_attack"][a]["subtle"]["rule"] == 0.0, a  # subtle sits below thresholds by construction


def test_deterministic_and_honest_about_limits(small):
    again = run_evaluation(seed=7, benign_trials=3, repeats=1, latency_repeats=1)
    assert again["methods"] == small["methods"]
    assert small["dataset"]["kind"] == "synthetic"
    assert any("not real-world accuracy" in c for c in small["caveats"])


def test_latency_is_never_negative(small):
    for m in METHODS:
        v = small["methods"][m]["latency_median_s"]
        assert v is None or v >= 0


def test_endpoint_roles(client, viewer):
    assert client.get("/api/v1/research", headers=viewer).status_code == 200
    assert client.post("/api/v1/research/run", headers=viewer).status_code == 403
    body = client.get("/api/v1/research", headers=viewer).json()
    assert {d["kind"] for d in body["supported_datasets"]} >= {"synthetic", "pcap", "cicids", "unsw-nb15"}
    assert all("not bundled" in d["status"] or d["status"] == "available" for d in body["supported_datasets"])
