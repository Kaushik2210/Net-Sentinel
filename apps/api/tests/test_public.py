from app.core.config import get_settings


def run(client, **body):
    return client.post("/api/v1/public/playground", json=body)


def test_options_need_no_login(client):
    r = client.get("/api/v1/public/playground")
    assert r.status_code == 200
    body = r.json()
    assert {s["id"] for s in body["scenarios"]} == {"full", "recon", "bruteforce", "exfil", "noisy", "benign"}
    assert all(d["about"] for d in body["detectors"])


def test_full_scenario_detects_and_benign_is_quiet(client):
    full = run(client, scenario="full").json()["result"]
    assert len(full["alerts"]) >= 5 and full["incident"]
    benign = run(client, scenario="benign").json()["result"]
    assert benign["alerts"] == []


def test_threshold_changes_the_outcome(client):
    base = run(client, scenario="recon").json()["result"]
    assert any(a["event_type"] == "port_scan" or "scan" in a["event_type"] for a in base["alerts"])
    strict = run(client, scenario="recon", thresholds={"PortScanDetector": {"min_ports": 200, "min_hosts": 100}}).json()["result"]
    assert len(strict["alerts"]) < len(base["alerts"])


def test_thresholds_are_clamped_and_validated(client):
    r = run(client, scenario="recon", thresholds={"PortScanDetector": {"min_ports": -5}})
    assert r.json()["result"]["settings"]["overrides"]["PortScanDetector"]["min_ports"] == 3
    assert run(client, scenario="nope").status_code == 422
    assert run(client, thresholds={"Evil": {"x": 1}}).status_code == 422
    assert run(client, thresholds={"PortScanDetector": {"__class__": 1}}).status_code == 422


def test_guest_access_is_off_by_default_and_viewer_only_when_on(client):
    assert client.post("/api/v1/auth/guest").status_code == 404
    get_settings().guest_access = True
    try:
        r = client.post("/api/v1/auth/guest")
        assert r.status_code == 200 and r.json()["user"]["role"] == "VIEWER"
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        assert client.post("/api/v1/replay/sample", headers=h).status_code == 403
    finally:
        get_settings().guest_access = False


def challenge(client, thresholds=None):
    r = client.post("/api/v1/public/challenge", json={"thresholds": thresholds or {}})
    assert r.status_code == 200, r.text
    return r.json()


def test_noisy_scenario_is_quiet_at_defaults_but_flags_when_over_tuned(client):
    assert run(client, scenario="noisy").json()["result"]["alerts"] == []
    tight = run(client, scenario="noisy", thresholds={"PortScanDetector": {"min_ports": 5, "min_hosts": 3}}).json()["result"]
    assert tight["alerts"]


def test_challenge_default_is_perfect_and_over_tuning_costs_points(client):
    base = challenge(client)
    assert base["perfect"] and base["score"] == 100
    sloppy = challenge(client, {"PortScanDetector": {"min_ports": 5, "min_hosts": 3}, "BruteForceDetector": {"min_failures": 3}})
    assert sloppy["false_alarms"] and sloppy["score"] < 100
    blind = challenge(client, {"PortScanDetector": {"min_ports": 200, "min_hosts": 100}})
    assert not next(s for s in blind["stages"] if s["detector"] == "PortScanDetector")["caught"]
    assert blind["score"] < 100
