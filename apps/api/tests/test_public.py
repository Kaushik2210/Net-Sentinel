from app.core.config import get_settings


def run(client, **body):
    return client.post("/api/v1/public/playground", json=body)


def test_options_need_no_login(client):
    r = client.get("/api/v1/public/playground")
    assert r.status_code == 200
    body = r.json()
    assert {s["id"] for s in body["scenarios"]} == {"full", "recon", "bruteforce", "exfil", "benign"}
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
