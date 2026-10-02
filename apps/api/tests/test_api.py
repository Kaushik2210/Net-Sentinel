def test_health_is_public(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_protected_routes_require_auth(client):
    for path in ("/api/v1/devices", "/api/v1/events", "/api/v1/network/topology", "/api/v1/analytics/summary"):
        assert client.get(path).status_code == 401, path


def test_login_rejects_bad_credentials_and_hides_which_part_was_wrong(client):
    bad_pw = client.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"})
    bad_user = client.post("/api/v1/auth/login", json={"username": "ghost", "password": "nope"})
    assert bad_pw.status_code == bad_user.status_code == 401
    assert bad_pw.json() == bad_user.json()


def test_login_validates_input(client):
    r = client.post("/api/v1/auth/login", json={"username": "a", "password": "x" * 200})
    assert r.status_code == 422


def test_garbage_token_rejected(client):
    r = client.get("/api/v1/devices", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401


def test_me_returns_role(client, viewer):
    r = client.get("/api/v1/auth/me", headers=viewer)
    assert r.status_code == 200 and r.json()["role"] == "VIEWER"
    assert "password_hash" not in r.json()


def test_seeded_network_and_listing(client, viewer):
    r = client.get("/api/v1/devices?limit=200", headers=viewer)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 47
    risks = [d["risk_score"] for d in body["items"]]
    assert risks == sorted(risks, reverse=True)  # riskiest first


def test_device_search_and_filters(client, viewer):
    by_name = client.get("/api/v1/devices?q=pc-07", headers=viewer).json()
    assert [d["hostname"] for d in by_name["items"]] == ["PC-07"]
    iot = client.get("/api/v1/devices?device_type=iot", headers=viewer).json()
    assert iot["total"] == 7
    assert client.get("/api/v1/devices?min_risk=101", headers=viewer).status_code == 422


def test_device_intelligence_is_explainable(client, viewer):
    pc07 = client.get("/api/v1/devices?q=PC-07", headers=viewer).json()["items"][0]
    d = client.get(f"/api/v1/devices/{pc07['id']}", headers=viewer).json()
    assert d["risk_score"] >= 50 and d["risk_severity"] in {"high", "critical"}
    assert sum(f["points"] for f in d["risk_factors"]) >= d["risk_score"]  # capped at 100
    assert any(m["deviated"] for m in d["metrics"])
    assert any(c["suspicious"] for c in d["connections"])
    assert d["connection_count"] == len(d["connections"])


def test_unknown_device_404(client, viewer):
    assert client.get("/api/v1/devices/dev_missing", headers=viewer).status_code == 404


def test_topology_is_consistent(client, viewer):
    t = client.get("/api/v1/network/topology", headers=viewer).json()
    ids = {n["id"] for n in t["nodes"]}
    assert len(ids) == 47
    assert all(e["source"] in ids and e["target"] in ids for e in t["edges"])
    assert any(e["suspicious"] for e in t["edges"])


def test_summary_labels_simulation_honestly(client, viewer):
    s = client.get("/api/v1/analytics/summary", headers=viewer).json()
    assert s["mode"] == "IDLE"  # tests run with telemetry disabled
    assert s["active_devices"] == 46  # excludes the INTERNET pseudo-node
    assert s["high_risk_devices"] >= 1


def test_events_pagination_params_validated(client, viewer):
    assert client.get("/api/v1/events?limit=0", headers=viewer).status_code == 422
    assert client.get("/api/v1/events?limit=500", headers=viewer).status_code == 422
    assert client.get("/api/v1/events?limit=5", headers=viewer).status_code == 200


def test_timestamps_are_timezone_aware(client, viewer):
    dev = client.get("/api/v1/devices?limit=1", headers=viewer).json()["items"][0]
    assert dev["last_seen"].endswith(("Z", "+00:00"))


def test_pc07_demo_score_matches_published_example(client, viewer):
    """The landing page and docs quote this breakdown; keep them honest."""
    pc07 = client.get("/api/v1/devices?q=PC-07", headers=viewer).json()["items"][0]
    d = client.get(f"/api/v1/devices/{pc07['id']}", headers=viewer).json()
    pts = {f["key"]: f["points"] for f in d["risk_factors"]}
    assert pts == {"ssh_per_hour": 20, "upload_mb_per_day": 20, "dns_per_hour": 15,
                   "new_destinations_per_day": 9, "criticality": 3}
    assert d["risk_score"] == 67


def test_topology_layout_is_screen_shaped(client, viewer):
    nodes = client.get("/api/v1/network/topology", headers=viewer).json()["nodes"]
    xs = [n["position"]["x"] for n in nodes]
    ys = [n["position"]["y"] for n in nodes]
    assert 0.8 < (max(xs) - min(xs)) / (max(ys) - min(ys)) < 2.4
