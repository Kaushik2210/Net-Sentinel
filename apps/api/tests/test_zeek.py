import io
import json
import random
import string

import pytest

from app.ingest.pcap import PcapError
from app.ingest.zeek import looks_like_zeek, parse_zeek
from app.replay.engine import build_replay

T0 = 1_790_000_000.0
CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state"]
ATTACKER = "10.0.20.22"


def conn_row(ts, src, dst, dport, dur="-", ob="-", rb="-", state="S0", proto="tcp"):
    return {"ts": f"{ts:.6f}", "uid": "C" + "".join(random.choices(string.ascii_letters, k=8)), "id.orig_h": src, "id.orig_p": str(random.randint(30000, 60000)),
            "id.resp_h": dst, "id.resp_p": str(dport), "proto": proto, "service": "-", "duration": str(dur), "orig_bytes": str(ob), "resp_bytes": str(rb), "conn_state": state}


def attack_rows():
    rng = random.Random(3)
    rows = []
    for i in range(24):  # sweep: unanswered SYNs
        rows.append(conn_row(T0 + 30 + i, ATTACKER, f"10.0.30.{40 + i}", 443, state="S0"))
    for i, port in enumerate(rng.sample(range(20, 9000), 40)):  # port scan: rejected
        rows.append(conn_row(T0 + 90 + i * 0.4, ATTACKER, "10.0.30.12", port, state="REJ"))
    for i in range(40):  # brute force: short low-payload ssh
        rows.append(conn_row(T0 + 150 + i, ATTACKER, "10.0.20.35", 22, dur=0.6, ob=120, rb=140, state="SF"))
    rows.append(conn_row(T0 + 210, ATTACKER, "10.0.20.35", 22, dur=40, ob=9000, rb=14000, state="SF"))
    for k, host in enumerate(("10.0.20.12", "10.0.30.12", "10.0.20.14")):  # lateral
        rows.append(conn_row(T0 + 232 + k * 8, ATTACKER, host, 22, dur=25, ob=8000, rb=12000, state="SF"))
    for i in range(4):  # exfil
        rows.append(conn_row(T0 + 330 + i * 8, ATTACKER, "198.51.100.77", 443, dur=6, ob=1_000_000, rb=2000, state="SF"))
    for h in range(6):  # benign background
        for i in range(8):
            rows.append(conn_row(T0 + i * 50 + h, f"10.0.20.{12 + h}", f"198.51.100.{h + 2}", 443, dur=1, ob=500, rb=4000, state="SF"))
    return rows


def to_tsv(rows, path="conn"):
    head = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", f"#path\t{path}", "#open\t2026-10-02-00-00-00",
            "#fields\t" + "\t".join(CONN_FIELDS), "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring"]
    body = ["\t".join(r[f] for f in CONN_FIELDS) for r in rows]
    return ("\n".join(head + body) + "\n#close\t2026-10-02-00-10-00\n").encode()


def test_detection_of_zeek_format():
    assert looks_like_zeek(to_tsv(attack_rows()))
    assert looks_like_zeek(b'{"ts":1790000000.0,"id.orig_h":"10.0.0.1"}\n')
    assert not looks_like_zeek(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    assert not looks_like_zeek(b"hello world")


def test_tsv_conn_log_maps_states_to_events():
    events, stats = parse_zeek(to_tsv(attack_rows()))
    types = {e.event_type for e in events}
    assert {"conn_attempt", "auth_failure", "auth_success", "tls_session"} <= types
    attempts = {e.attributes["state"] for e in events if e.event_type == "conn_attempt"}
    assert attempts == {"unanswered", "rejected"}  # S0 vs REJ
    assert all(e.attributes.get("inferred") for e in events if e.event_type in {"auth_failure", "auth_success"})
    assert stats.flows == len(attack_rows()) and [e.ts for e in events] == sorted(e.ts for e in events)
    exfil = [e for e in events if e.dst_ip == "198.51.100.77"]
    assert len(exfil) == 4 and all(e.bytes_sent == 1_000_000 for e in exfil)


def test_json_lines_variant_gives_the_same_events():
    rows = attack_rows()
    tsv_events, _ = parse_zeek(to_tsv(rows))
    jl = "\n".join(json.dumps({"ts": float(r["ts"]), "id.orig_h": r["id.orig_h"], "id.resp_h": r["id.resp_h"], "id.resp_p": int(r["id.resp_p"]), "proto": "tcp",
                               **({"duration": float(r["duration"])} if r["duration"] != "-" else {}), **({"orig_bytes": int(r["orig_bytes"])} if r["orig_bytes"] != "-" else {}),
                               **({"resp_bytes": int(r["resp_bytes"])} if r["resp_bytes"] != "-" else {}), "conn_state": r["conn_state"]}) for r in rows).encode()
    json_events, _ = parse_zeek(jl)
    key = lambda es: sorted((e.event_type, e.src_ip, e.dst_ip, e.dst_port) for e in es)  # noqa: E731
    assert key(json_events) == key(tsv_events)


def test_dns_log_rows_become_dns_queries():
    head = ["#separator \\x09", "#path\tdns", "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tquery", "#types\ttime\taddr\taddr\tport\tstring"]
    rows = [f"{T0 + i}\t10.0.20.22\t10.0.10.14\t53\t{''.join(random.choices(string.ascii_lowercase, k=26))}.bench.example." for i in range(20)]
    events, stats = parse_zeek(("\n".join(head + rows) + "\n").encode())
    assert stats.dns_queries == 20 and {e.event_type for e in events} == {"dns_query"}
    assert all(not e.attributes["domain"].endswith(".") for e in events)


def test_pipeline_detects_the_attack_from_zeek_logs():
    events, _ = parse_zeek(to_tsv(attack_rows()))
    r = build_replay(events, {"DataExfiltrationDetector": {"min_bytes": 3_000_000}})
    kinds = {a["event_type"] for a in r["alerts"]}
    assert {"horizontal_sweep", "vertical_port_scan", "credential_attack", "possible_credential_compromise", "lateral_movement", "possible_exfiltration"} <= kinds
    assert {a["source"] for a in r["alerts"]} == {ATTACKER}  # benign hosts stay quiet
    assert r["incident"] and len(r["incident"]["steps"]) >= 5


def test_bad_inputs_rejected_cleanly():
    with pytest.raises(PcapError):
        parse_zeek(b"just some text that is not a zeek log at all")
    with pytest.raises(PcapError):
        parse_zeek(b"#separator \\x09\n#fields\tts\tid.orig_h\n1790000000.0\t::1\n")  # IPv6 only
    with pytest.raises(PcapError):
        parse_zeek(b"x" * (26 * 1024 * 1024) + b'{"ts":1}')


def test_upload_endpoint_accepts_zeek_logs(client):
    r = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst-test-pw"})
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    up = client.post("/api/v1/replay/upload", headers=h, files={"file": ("conn.log", io.BytesIO(to_tsv(attack_rows())), "text/plain")})
    assert up.status_code == 200, up.text
    assert up.json()["status"] == "complete" and up.json()["alert_count"] >= 4
    detail = client.get(f"/api/v1/replay/{up.json()['id']}", headers=h).json()
    assert detail["result"]["ingest"]["source_format"] == "zeek"
    bad = client.post("/api/v1/replay/upload", headers=h, files={"file": ("x.log", io.BytesIO(b"nope nope nope " * 5), "text/plain")})
    assert bad.status_code == 422
