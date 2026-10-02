import time

import pytest
from jose import jwt
from starlette.websockets import WebSocketDisconnect

from app.core.config import get_settings
from app.services import loginguard


@pytest.fixture(autouse=True)
def _fresh_guard():
    loginguard.reset_all()
    yield
    loginguard.reset_all()


def token_for(client, user="viewer", pw="viewer-test-pw"):
    return client.post("/api/v1/auth/login", json={"username": user, "password": pw}).json()["access_token"]


def test_lockout_after_repeated_failures_even_for_unknown_users(client, monkeypatch):
    monkeypatch.setattr(loginguard, "MAX_FAILURES", 3)
    for _ in range(3):
        assert client.post("/api/v1/auth/login", json={"username": "ghost-user", "password": "x"}).status_code == 401
    r = client.post("/api/v1/auth/login", json={"username": "ghost-user", "password": "x"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    # Case-insensitive key, so changing the case does not bypass the throttle.
    assert client.post("/api/v1/auth/login", json={"username": "GHOST-USER", "password": "x"}).status_code == 429


def test_lockout_blocks_the_real_password_too_but_not_other_accounts(client, monkeypatch):
    monkeypatch.setattr(loginguard, "MAX_FAILURES", 3)
    for _ in range(3):
        client.post("/api/v1/auth/login", json={"username": "viewer", "password": "wrong"})
    assert client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewer-test-pw"}).status_code == 429
    assert client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst-test-pw"}).status_code == 200


def test_success_clears_the_failure_counter(client, monkeypatch):
    monkeypatch.setattr(loginguard, "MAX_FAILURES", 3)
    for _ in range(2):
        client.post("/api/v1/auth/login", json={"username": "viewer", "password": "wrong"})
    assert client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewer-test-pw"}).status_code == 200
    for _ in range(2):
        client.post("/api/v1/auth/login", json={"username": "viewer", "password": "wrong"})
    assert client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewer-test-pw"}).status_code == 200


def test_throttle_events_are_audited(client, monkeypatch):
    from sqlalchemy import select

    from app.db.session import SessionLocal
    from app.models import AuditLog

    monkeypatch.setattr(loginguard, "MAX_FAILURES", 1)
    client.post("/api/v1/auth/login", json={"username": "audit-probe", "password": "wrong"})
    assert client.post("/api/v1/auth/login", json={"username": "audit-probe", "password": "wrong"}).status_code == 429
    with SessionLocal() as db:
        actions = {a for (a,) in db.execute(select(AuditLog.action).where(AuditLog.actor == "audit-probe"))}
    assert {"auth.login_failed", "auth.login_throttled"} <= actions


def test_ws_accepts_valid_token_and_rejects_bad_ones(client):
    with client.websocket_connect("/api/v1/ws/stream") as ws:
        ws.send_json({"type": "auth", "token": token_for(client)})
        assert ws.receive_json() == {"type": "ready"}
    for bad in ({"type": "auth", "token": "garbage"}, {"type": "hello"}, {"type": "auth"}):
        with client.websocket_connect("/api/v1/ws/stream") as ws:
            ws.send_json(bad)
            with pytest.raises(WebSocketDisconnect) as exc:
                ws.receive_json()
            assert exc.value.code == 4401


def test_ws_rejects_disallowed_origin(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/v1/ws/stream", headers={"origin": "https://evil.example"}):
            pass
    with client.websocket_connect("/api/v1/ws/stream", headers={"origin": "http://localhost:3000"}) as ws:
        ws.send_json({"type": "auth", "token": token_for(client)})
        assert ws.receive_json()["type"] == "ready"


def test_ws_closes_when_token_expires(client):
    s = get_settings()
    short = jwt.encode({"sub": "x", "role": "VIEWER", "exp": time.time() + 1.2}, s.jwt_secret, algorithm=s.jwt_algorithm)
    with client.websocket_connect("/api/v1/ws/stream") as ws:
        ws.send_json({"type": "auth", "token": short})
        assert ws.receive_json()["type"] == "ready"
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 4401
