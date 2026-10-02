import pytest

from app.analyst.answers import INSUFFICIENT, Answer, CitationError, Claim, answer_incident, validate
from app.analyst.evidence import IncidentPackage
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


@pytest.fixture
def incident(client, sim_mode):
    analyst, admin = login(client, "analyst", "analyst-test-pw"), login(client, "admin", "admin-test-pw")
    client.post("/api/v1/detections/reset-simulation", headers=admin)
    client.post("/api/v1/detections/simulate-attack", headers=analyst)
    inc = client.get("/api/v1/incidents", headers=analyst).json()["items"][0]
    yield inc["id"], analyst, admin
    client.post("/api/v1/detections/reset-simulation", headers=admin)


def test_validate_rejects_invented_citations():
    ok = Answer("explain", [Claim("fine", ["alt_1"])])
    assert validate(ok, {"alt_1"}) is ok
    with pytest.raises(CitationError):
        validate(Answer("explain", [Claim("made up", ["evt_does_not_exist"])]), {"alt_1"})


def test_empty_incident_yields_insufficient_evidence():
    empty = IncidentPackage("inc_x", "t", "open", "low", 0, [], "", "", "", [], [], [])
    a = answer_incident("explain", empty)
    assert a.insufficient and [c.text for c in a.claims] == [INSUFFICIENT]


def test_workflow_notes_assignment_and_audit_trail(client, incident):
    iid, analyst, admin = incident
    viewer = login(client, "viewer", "viewer-test-pw")

    assert client.post(f"/api/v1/investigations/{iid}/notes", json={"body": "x"}, headers=viewer).status_code == 403
    assert client.post(f"/api/v1/investigations/{iid}/notes", json={"body": ""}, headers=analyst).status_code == 422
    assert client.post(f"/api/v1/investigations/{iid}/notes", json={"body": "y" * 4001}, headers=analyst).status_code == 422
    n = client.post(f"/api/v1/investigations/{iid}/notes", json={"body": "Checked auth logs on JUMP-01."}, headers=analyst)
    assert n.status_code == 201 and n.json()["author"] == "analyst"
    assert client.get(f"/api/v1/investigations/{iid}/notes", headers=viewer).json()[0]["body"].startswith("Checked")

    assert client.patch(f"/api/v1/investigations/{iid}", json={"status": "bogus"}, headers=analyst).status_code == 422
    assert client.patch(f"/api/v1/investigations/{iid}", json={"status": "investigating", "assignee": "analyst"}, headers=analyst).json() == {
        "id": iid, "status": "investigating", "assignee": "analyst"}
    assert client.patch(f"/api/v1/investigations/{iid}", json={"assignee": "viewer"}, headers=analyst).status_code == 422
    assert client.patch(f"/api/v1/investigations/{iid}", json={"status": "escalated"}, headers=viewer).status_code == 403

    inc = client.get(f"/api/v1/incidents/{iid}", headers=analyst).json()
    assert inc["status"] == "investigating" and inc["assignee"] == "analyst"

    trail = client.get(f"/api/v1/investigations/{iid}/audit", headers=viewer).json()
    actions = [t["action"] for t in trail]
    assert {"incident.note", "incident.status", "incident.assign"} <= set(actions)
    status_entry = next(t for t in trail if t["action"] == "incident.status")
    assert status_entry["detail"] == {"from": "open", "to": "investigating"} and status_entry["actor"] == "analyst"

    assert {a["username"] for a in client.get("/api/v1/investigations/analysts", headers=viewer).json()} == {"admin", "analyst"}
    assert client.patch(f"/api/v1/investigations/{iid}", json={"assignee": None}, headers=analyst).json()["assignee"] is None


def test_every_incident_answer_cites_only_real_evidence(client, incident):
    iid, analyst, _ = incident
    detail = client.get(f"/api/v1/incidents/{iid}", headers=analyst).json()
    real_alerts = {s["alert_id"] for s in detail["steps"]}
    real_events = {e for s in detail["steps"] for e in s["evidence_event_ids"]} | {a["id"] for a in detail["supporting"]}

    for q in ("explain", "what_changed", "timeline", "evidence", "next_steps", "related_events", "exfiltration", "report"):
        r = client.post("/api/v1/analyst/ask", json={"question": q, "incident_id": iid}, headers=analyst)
        assert r.status_code == 200, (q, r.text)
        body = r.json()
        assert body["mode"] == "deterministic" and "No language model" in body["notice"]
        assert body["claims"] and not body["insufficient"], q
        known = real_alerts | real_events | {iid} | {t["id"] for t in detail["techniques"]}
        assert set(body["citations"]) <= known, (q, set(body["citations"]) - known)
        assert all(c["cites"] for c in body["claims"]), f"uncited claim in {q}"

    report = client.post("/api/v1/analyst/ask", json={"question": "report", "incident_id": iid}, headers=analyst).json()
    assert any("Risk factor" in c["text"] for c in report["claims"])


def test_analyst_says_insufficient_when_evidence_missing(client, incident):
    iid, analyst, admin = incident
    # Disable the exfiltration chain step by asking about a device with no alerts and no deviation.
    quiet = next(d for d in client.get("/api/v1/devices?limit=200", headers=analyst).json()["items"] if d["risk_score"] == 0 and d["device_type"] == "workstation")
    r = client.post("/api/v1/analyst/ask", json={"question": "why_suspicious", "device_id": quiet["id"]}, headers=analyst).json()
    assert r["insufficient"] and r["claims"][0]["text"] == INSUFFICIENT


def test_device_answer_uses_scored_factors_and_alerts(client, incident):
    iid, analyst, _ = incident
    pc07 = client.get("/api/v1/devices?q=PC-07", headers=analyst).json()["items"][0]
    r = client.post("/api/v1/analyst/ask", json={"question": "why_suspicious", "device_id": pc07["id"]}, headers=analyst).json()
    assert not r["insufficient"] and pc07["id"] in r["citations"]
    assert any("+20 SSH connection rate" in c["text"] for c in r["claims"])
    assert any(c.startswith("alt_") for c in r["citations"])


def test_ask_validation(client, viewer):
    assert client.post("/api/v1/analyst/ask", json={"question": "explain"}, headers=viewer).status_code == 422  # no target
    assert client.post("/api/v1/analyst/ask", json={"question": "explain", "incident_id": "a", "device_id": "b"}, headers=viewer).status_code == 422
    assert client.post("/api/v1/analyst/ask", json={"question": "why_suspicious", "incident_id": "inc_x"}, headers=viewer).status_code == 422
    assert client.post("/api/v1/analyst/ask", json={"question": "tell me a story", "incident_id": "inc_x"}, headers=viewer).status_code == 422
    assert client.post("/api/v1/analyst/ask", json={"question": "explain", "incident_id": "inc_missing"}, headers=viewer).status_code == 404
