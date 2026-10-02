import json
from pathlib import Path

import pytest

from app.api.v1.mitre import TACTIC_ORDER
from app.core.config import get_settings
from app.detection import registry


@pytest.fixture
def sim_mode():
    s = get_settings()
    s.telemetry_mode = "simulation"
    yield
    s.telemetry_mode = "idle"


def login(client, user, pw):
    r = client.post("/api/v1/auth/login", json={"username": user, "password": pw})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_catalogue_is_structured_data_and_covers_every_detector_technique():
    data = json.loads((Path(__file__).resolve().parent.parent / "app" / "data" / "mitre.json").read_text(encoding="utf-8"))
    ids = {t["id"] for t in data}
    assert len(ids) == len(data) and {t["tactic"] for t in data} <= set(TACTIC_ORDER)
    for name, cls in registry().items():
        assert set(cls.mitre) <= ids, f"{name} references techniques missing from the catalogue"


def test_matrix_shape(client, viewer):
    m = client.get("/api/v1/mitre", headers=viewer).json()
    assert [t["name"] for t in m["tactics"]] == TACTIC_ORDER
    assert m["total_techniques"] >= 30
    assert client.get("/api/v1/mitre/T9999", headers=viewer).status_code == 404


def test_observed_techniques_follow_alerts_and_expose_chain_position(client, sim_mode):
    analyst = login(client, "analyst", "analyst-test-pw")
    admin = login(client, "admin", "admin-test-pw")
    client.post("/api/v1/detections/reset-simulation", headers=admin)
    assert client.get("/api/v1/mitre", headers=analyst).json()["observed_techniques"] == 0

    client.post("/api/v1/detections/simulate-attack", headers=analyst)
    m = client.get("/api/v1/mitre", headers=analyst).json()
    observed = {t["id"] for tac in m["tactics"] for t in tac["techniques"] if t["observed"]}
    assert {"T1046", "T1595", "T1110", "T1021", "T1041", "T1078", "T1071.004"} <= observed
    assert 0 < m["observed_techniques"] < m["total_techniques"]  # honest: most of the matrix is unobserved

    d = client.get("/api/v1/mitre/T1110", headers=analyst).json()
    assert d["tactic"] == "Credential Access" and d["alert_count"] >= 1 and d["evidence_event_ids"]
    a = d["alerts"][0]
    assert a["incident_id"] and a["chain_position"] and a["chain_length"] >= a["chain_position"]
    assert a["stage"] in {"Credential Attack", "Initial Access"}

    cold = client.get("/api/v1/mitre/T1486", headers=analyst).json()
    assert cold["observed"] is False and cold["alerts"] == [] and cold["max_confidence"] is None
    client.post("/api/v1/detections/reset-simulation", headers=admin)
