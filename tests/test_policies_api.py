"""GET /v1/policies/active tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def client(db_available: bool) -> TestClient:
    if not db_available:
        pytest.skip("PostgreSQL not available")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_dev_org.py")],
        check=True,
        cwd=ROOT,
    )
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_dev_policy.py")],
        check=True,
        cwd=ROOT,
    )
    from app.main import app

    return TestClient(app)


def test_get_active_policy(client: TestClient) -> None:
    response = client.get(
        "/v1/policies/active",
        headers={"x-api-key": "org_demo_key"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["version"] == "v1"
    assert body["engine"] == "json"
    assert len(body["rules"]["rules"]) >= 5
