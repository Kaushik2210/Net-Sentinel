import pytest

from app.core.config import get_settings
from app.intel.providers import IndicatorError, normalize
from app.response.engine import ACTIONS, SimulatedActuator


@pytest.fixture
def sim_mode():
    s = get_settings()
    s.telemetry_mode = "simulation"
    yield
    s.telemetry_mode = "idle"


def login(client, user, pw):
    r = client.post("/api/v1/auth/login", json={"username": user, "password": pw})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.mark.parametrize("kind,value,expected", [
    ("ip", " 198.51.100.77 ", "198.51.100.77"),
    ("domain", "Evil.Example.COM.", "evil.example.com"),
    ("hash", "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
    ("url", "https://bad.example.com/path?x=1", "https://bad.example.com/path?x=1"),
])
def test_normalization(kind, value, expected):
    assert normalize(kind, value) == expected


@pytest.mark.parametrize("kind,value", [
    ("ip", "999.1.1.1"), ("ip", "not-an-ip"), ("domain", "no_tld"), ("domain", "-bad.example.com"),
    ("hash", "xyz"), ("hash", "abcd"), ("url", "javascript:alert(1)"), ("url", "ftp://x.example.com"), ("kind", "x"),
])
def test_invalid_indicators_rejected(kind, value):
    with pytest.raises(IndicatorError):
        normalize(kind, value)


def test_indicator_crud_roles_and_dedupe(client, viewer):
    analyst, admin = login(client, "analyst", "analyst-test-pw"), login(client, "admin", "admin-test-pw")
    assert client.post("/api/v1/threat-intel", json={"kind": "ip", "value": "203.0.113.9"}, headers=viewer).status_code == 403
    assert client.post("/api/v1/threat-intel", json={"kind": "ip", "value": "999.9.9.9"}, headers=analyst).status_code == 422
    ok = client.post("/api/v1/threat-intel", json={"kind": "domain", "value": "Bad.Example.org", "description": "test entry", "confidence": 70}, headers=analyst)
    assert ok.status_code == 201 and ok.json()["value"] == "bad.example.org"
    assert client.post("/api/v1/threat-intel", json={"kind": "domain", "value": "bad.example.org"}, headers=analyst).status_code == 409

    chk = client.post("/api/v1/threat-intel/check", json={"kind": "domain", "value": "BAD.example.org."}, headers=viewer).json()
    assert chk["matched"] and chk["providers_checked"] == ["local-store"] and chk["hits"][0]["confidence"] == 70
    assert client.post("/api/v1/threat-intel/check", json={"kind": "domain", "value": "clean.example.org"}, headers=viewer).json()["matched"] is False

    assert client.delete(f"/api/v1/threat-intel/{ok.json()['id']}", headers=analyst).status_code == 403
    assert client.delete(f"/api/v1/threat-intel/{ok.json()['id']}", headers=admin).status_code == 204
    assert client.get("/api/v1/threat-intel?kind=domain&q=bad.example", headers=viewer).json()["total"] == 0


def test_indicator_matches_recent_telemetry(client, sim_mode):
    analyst, admin = login(client, "analyst", "analyst-test-pw"), login(client, "admin", "admin-test-pw")
    client.post("/api/v1/detections/reset-simulation", headers=admin)
    ind = client.post("/api/v1/threat-intel", json={"kind": "ip", "value": "198.51.100.77", "source": "analyst-note", "description": "test"}, headers=analyst).json()
    client.post("/api/v1/detections/simulate-attack", headers=analyst)
    m = [x for x in client.get("/api/v1/threat-intel/matches", headers=analyst).json() if x["indicator_id"] == ind["id"]]
    assert m and m[0]["alert_ids"] and m[0]["event_ids"] and m[0]["where"] == "alerts and events"
    client.delete(f"/api/v1/threat-intel/{ind['id']}", headers=admin)
    client.post("/api/v1/detections/reset-simulation", headers=admin)


def test_simulated_actuator_never_claims_a_real_change():
    a = SimulatedActuator()
    assert a.real is False
    for action in ACTIONS:
        msg = a.execute(action, "10.0.20.22")
        assert "WOULD" in msg and msg.endswith("No real network modification occurs.")


def test_recommendations_are_evidence_backed_and_simulation_only(client, sim_mode):
    analyst, admin = login(client, "analyst", "analyst-test-pw"), login(client, "admin", "admin-test-pw")
    viewer = login(client, "viewer", "viewer-test-pw")
    client.post("/api/v1/detections/reset-simulation", headers=admin)
    client.post("/api/v1/detections/simulate-attack", headers=analyst)
    iid = client.get("/api/v1/incidents", headers=analyst).json()["items"][0]["id"]

    recs = client.get(f"/api/v1/response/incidents/{iid}", headers=viewer).json()
    actions = {(r["action"], r["target"]) for r in recs}
    assert ("isolate_device", "10.0.20.22") in actions and ("block_destination", "198.51.100.77") in actions
    assert ("disable_account", "svc_backup") in actions
    assert all(r["state"] == "proposed" and r["mode"] == "RECOMMENDATION ONLY" and "evidence: alt_" in r["rationale"] for r in recs)
    assert client.get(f"/api/v1/response/incidents/{iid}", headers=viewer).json() == recs  # stable, not duplicated

    iso = next(r for r in recs if r["action"] == "isolate_device")
    assert iso["label"] == "SIMULATE ISOLATION"
    assert client.post(f"/api/v1/response/{iso['id']}/simulate", headers=viewer).status_code == 403
    res = client.post(f"/api/v1/response/{iso['id']}/simulate", headers=analyst).json()
    assert res["message"] == "DEVICE 10.0.20.22 WOULD BE ISOLATED. No real network modification occurs." and res["real_changes_made"] is False
    assert res["recommendation"]["state"] == "simulated"

    trail = client.get(f"/api/v1/investigations/{iid}/audit", headers=viewer).json()
    sim = next(t for t in trail if t["action"] == "incident.response_simulated")
    assert sim["detail"]["real"] is False
    assert client.post("/api/v1/response/rec_missing/simulate", headers=analyst).status_code == 404
    assert client.get("/api/v1/response/incidents/inc_missing", headers=viewer).status_code == 404
    client.post("/api/v1/detections/reset-simulation", headers=admin)
