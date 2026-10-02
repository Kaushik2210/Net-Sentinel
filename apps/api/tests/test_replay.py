import io

import pytest

from app.ingest.pcap import MAX_BYTES, PcapError, parse_pcap, validate_upload
from app.ingest.sample import SAMPLE_OVERRIDES, build_sample_pcap
from app.replay.engine import build_replay


@pytest.fixture(scope="module")
def sample_bytes():
    return build_sample_pcap()


@pytest.fixture(scope="module")
def parsed(sample_bytes):
    return parse_pcap(sample_bytes)


def login(client, user, pw):
    r = client.post("/api/v1/auth/login", json={"username": user, "password": pw})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_validation_rejects_bad_input():
    with pytest.raises(PcapError):
        validate_upload(b"this is not a capture at all, just text" * 3)
    with pytest.raises(PcapError):
        validate_upload(b"\xd4\xc3\xb2\xa1" + b"\x00" * (MAX_BYTES + 1))
    with pytest.raises(PcapError):
        validate_upload(b"")


def test_garbage_with_valid_magic_fails_cleanly():
    with pytest.raises(PcapError):
        parse_pcap(b"\xd4\xc3\xb2\xa1" + b"\xff" * 64)


def test_parser_maps_packets_to_event_vocabulary(parsed):
    events, stats = parsed
    types = {e.event_type for e in events}
    assert {"conn_attempt", "dns_query", "tls_session", "auth_failure", "auth_success"} <= types
    assert stats.packets > 1000 and stats.flows > 100 and not stats.truncated
    assert [e.ts for e in events] == sorted(e.ts for e in events)
    # Heuristic outcomes are flagged so analysts can see they are inferred, not observed.
    assert all(e.attributes.get("inferred") for e in events if e.event_type in {"auth_failure", "auth_success"})
    dns = [e for e in events if e.event_type == "dns_query"]
    assert all(e.attributes["domain"] for e in dns)


def test_exfil_flow_bytes_are_counted_from_initiator(parsed):
    events, _ = parsed
    big = [e for e in events if e.dst_ip == "198.51.100.77"]
    assert len(big) == 4 and all(e.bytes_sent >= 1_000_000 and e.src_ip == "10.0.20.22" for e in big)


def test_replay_detects_attack_incrementally_and_correlates(parsed):
    events, _ = parsed
    r = build_replay(events, SAMPLE_OVERRIDES)
    kinds = {a["event_type"] for a in r["alerts"]}
    assert {"horizontal_sweep", "vertical_port_scan", "credential_attack", "possible_credential_compromise", "lateral_movement",
            "possible_exfiltration"} <= kinds
    assert all(a["source"] == "10.0.20.22" for a in r["alerts"])  # benign hosts raise nothing
    # Incremental: the exfil alert is only detectable late, the sweep early.
    by = {a["event_type"]: a["detected_offset_s"] for a in r["alerts"]}
    assert by["horizontal_sweep"] < by["credential_attack"] < by["possible_exfiltration"]
    frames = r["frames"]
    assert [f["t"] for f in frames] == sorted(f["t"] for f in frames)
    assert frames[0]["chain"] == 0 and frames[-1]["chain"] >= 5
    assert frames[-1]["threat"] > frames[0]["threat"]
    inc = r["incident"]
    assert inc["steps"][0]["stage"] == "Reconnaissance" and inc["risk_score"] == min(100, sum(f["points"] for f in inc["risk_factors"]))
    assert r["settings"]["overrides"] == SAMPLE_OVERRIDES and "MLAnomalyDetector" in r["settings"]["excluded_detectors"]


def test_without_override_small_exfil_is_not_flagged(parsed):
    events, _ = parsed
    r = build_replay(events)
    assert "possible_exfiltration" not in {a["event_type"] for a in r["alerts"]}  # honest default threshold (100 MB)


def test_empty_capture_result():
    assert build_replay([])["empty"] is True


def test_endpoints_roles_validation_and_flow(client, sample_bytes):
    analyst, admin = login(client, "analyst", "analyst-test-pw"), login(client, "admin", "admin-test-pw")
    viewer = login(client, "viewer", "viewer-test-pw")
    assert client.post("/api/v1/replay/sample", headers=viewer).status_code == 403
    assert client.get("/api/v1/replay").status_code == 401

    bad = client.post("/api/v1/replay/upload", headers=analyst, files={"file": ("x.pcap", io.BytesIO(b"hello world" * 10), "application/octet-stream")})
    assert bad.status_code == 422 and "magic" in bad.json()["detail"]

    ok = client.post("/api/v1/replay/upload", headers=analyst, files={"file": ("../../evil/name.pcap", io.BytesIO(sample_bytes), "application/octet-stream")})
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["status"] == "complete" and body["filename"] == "name.pcap"  # path components stripped
    assert body["packet_count"] > 1000 and len(body["sha256"]) == 64

    s = client.post("/api/v1/replay/sample", headers=analyst).json()
    assert s["status"] == "complete" and s["alert_count"] >= 6

    detail = client.get(f"/api/v1/replay/{s['id']}", headers=viewer).json()
    assert detail["result"]["incident"] and detail["result"]["ingest"]["heuristics"]
    assert len(client.get("/api/v1/replay", headers=viewer).json()) >= 2

    assert client.delete(f"/api/v1/replay/{s['id']}", headers=analyst).status_code == 403
    assert client.delete(f"/api/v1/replay/{s['id']}", headers=admin).status_code == 204
    assert client.get(f"/api/v1/replay/{s['id']}", headers=admin).status_code == 404
