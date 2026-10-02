import pytest

from app.core.config import get_settings


@pytest.fixture
def sim_mode():
    s = get_settings()
    s.telemetry_mode = "simulation"
    yield
    s.telemetry_mode = "idle"


def login(client, user, pw):
    r = client.post("/api/v1/auth/login", json={"username": user, "password": pw})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_detectors_listed_with_mitre(client, viewer):
    items = client.get("/api/v1/detections", headers=viewer).json()
    names = {d["name"]: d for d in items}
    assert names["BruteForceDetector"]["mitre"] == ["T1110"] and names["BruteForceDetector"]["enabled"]


def test_viewer_cannot_simulate_or_toggle(client, viewer, sim_mode):
    assert client.post("/api/v1/detections/simulate-attack", headers=viewer).status_code == 403
    assert client.patch("/api/v1/detections/PortScanDetector", json={"enabled": False}, headers=viewer).status_code == 403
    assert client.post("/api/v1/detections/reset-simulation", headers=viewer).status_code == 403


def test_simulation_refused_when_not_in_simulation_mode(client):
    h = login(client, "analyst", "analyst-test-pw")
    assert client.post("/api/v1/detections/simulate-attack", headers=h).status_code == 409


def test_attack_simulation_produces_explained_alerts_then_dedupes_and_resets(client, sim_mode):
    analyst = login(client, "analyst", "analyst-test-pw")
    admin = login(client, "admin", "admin-test-pw")

    r = client.post("/api/v1/detections/simulate-attack", headers=analyst)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["events_injected"] > 100
    types = {a["event_type"] for a in body["alerts_created"]}
    assert {"credential_attack", "lateral_movement", "possible_exfiltration"} <= types
    assert all(a["detection_class"] == "RULE" for a in body["alerts_created"])

    alert_id = next(a["id"] for a in body["alerts_created"] if a["event_type"] == "credential_attack")
    detail = client.get(f"/api/v1/alerts/{alert_id}", headers=analyst).json()
    assert detail["mitre_techniques"] == ["T1110"] and detail["explanation"]
    kinds = {e["kind"] for e in detail["evidence"]}
    assert kinds == {"facts", "event"}
    assert any(e["event_id"] for e in detail["evidence"])

    # Running again must not duplicate alerts for the same behaviour (dedupe window).
    again = client.post("/api/v1/detections/simulate-attack", headers=analyst).json()
    assert again["alerts_created"] == []

    summary = client.get("/api/v1/analytics/summary", headers=analyst).json()
    assert summary["critical_alerts"] >= 0
    listed = client.get("/api/v1/alerts?severity=high&limit=5", headers=analyst).json()
    assert all(a["severity"] == "high" for a in listed["items"])

    assert client.post("/api/v1/detections/reset-simulation", headers=admin).status_code == 204
    assert client.get("/api/v1/alerts", headers=admin).json()["total"] == 0


def test_alert_filters_validated(client, viewer):
    assert client.get("/api/v1/alerts?severity=bogus", headers=viewer).status_code == 422
    assert client.get("/api/v1/alerts/alt_missing", headers=viewer).status_code == 404
