import os
import tempfile
from pathlib import Path

# Must be set before the app (and its cached settings) is imported.
_tmp = Path(tempfile.mkdtemp(prefix="netsentinel-test-"))
os.environ.update(
    ENVIRONMENT="test",
    DATABASE_URL=f"sqlite:///{(_tmp / 'test.db').as_posix()}",
    JWT_SECRET="test-secret-not-for-production",
    SEED_ADMIN_PASSWORD="admin-test-pw",
    SEED_ANALYST_PASSWORD="analyst-test-pw",
    SEED_VIEWER_PASSWORD="viewer-test-pw",
    TELEMETRY_MODE="idle",
    RATE_LIMIT_LOGIN="1000/minute",
    RATE_LIMIT_DEFAULT="100000/minute",
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


def _login(client, username, password) -> dict:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin(client):
    return _login(client, "admin", "admin-test-pw")


@pytest.fixture(scope="session")
def viewer(client):
    return _login(client, "viewer", "viewer-test-pw")
