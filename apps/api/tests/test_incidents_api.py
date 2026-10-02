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


def test_attack_is_reconstructed_into_one_incident_with_evidence(client, sim_mode):
    analyst = login(client, "analyst", "analyst-test-pw")
    admin = login(client, "admin", "admin-test-pw")
    client.post("/api/v1/detections/reset-simulation", headers=admin)

    assert client.post("/api/v1/detections/simulate-attack", headers=analyst).status_code == 200
    listing = client.get("/api/v1/incidents", headers=analyst).json()
    assert listing["total"] == 1
    inc = listing["items"][0]
    assert inc["classification"] == "CORRELATED" and inc["severity"] in {"high", "critical"}

    d = client.get(f"/api/v1/incidents/{inc['id']}", headers=analyst).json()
    stages = [s["stage"] for s in d["steps"]]
    assert stages[0] == "Reconnaissance" and stages[-1] == "Possible Exfiltration"
    assert {"Credential Attack", "Initial Access", "Lateral Movement"} <= set(stages)
    times = [s["timestamp"] for s in d["steps"]]
    assert times == sorted(times)
    assert all(s["evidence_event_ids"] and s["explanation"] and s["link_reason"] for s in d["steps"])
    assert {t["id"] for t in d["techniques"]} >= {"T1046", "T1110", "T1021", "T1041", "T1078"}
    assert d["risk_score"] == min(100, sum(f["points"] for f in d["risk_factors"]))
    assert d["evidence_count"] > 50
    assert {s["detection_class"] for s in d["supporting"]} <= {"ML", "BEHAVIORAL"} and d["supporting"]

    # Re-correlating must keep the same incident id (stable references for notes and links).
    again = client.post("/api/v1/incidents/correlate", headers=analyst).json()
    assert [i["id"] for i in again] == [inc["id"]]
    assert client.get("/api/v1/incidents", headers=analyst).json()["total"] == 1

    assert client.post("/api/v1/detections/reset-simulation", headers=admin).status_code == 204
    assert client.get("/api/v1/incidents", headers=admin).json()["total"] == 0


def test_incident_lookup_and_filters(client, viewer):
    assert client.get("/api/v1/incidents/inc_missing", headers=viewer).status_code == 404
    assert client.get("/api/v1/incidents?status=bogus", headers=viewer).status_code == 422
    assert client.post("/api/v1/incidents/correlate", headers=viewer).status_code == 403
