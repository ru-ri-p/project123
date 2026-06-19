"""Multi-tenancy and org settings tests (Phase 2 Week 5)."""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
ORG_A_KEY = "org_demo_key"
ORG_B_KEY = "org_other_key"


@pytest.fixture(scope="module")
def client(db_available: bool) -> TestClient:
    if not db_available:
        pytest.skip("PostgreSQL not available — run: docker compose up -d")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_dev_org.py")],
        check=True,
        cwd=ROOT,
    )
    from app.main import app

    return TestClient(app)


def _post_event(client: TestClient, api_key: str, trace_id: str, seq: int = 1) -> None:
    response = client.post(
        "/v1/event",
        headers={"x-api-key": api_key},
        json={
            "trace_id": trace_id,
            "seq": seq,
            "type": "model_completion",
            "payload": {"tenant": api_key[:8]},
        },
    )
    assert response.status_code == 200, response.text


def test_org_me_returns_settings(client: TestClient) -> None:
    response = client.get("/v1/org/me", headers={"x-api-key": ORG_A_KEY})
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "org_demo"
    assert body["region"] == "uae"
    assert body["fail_mode"] == "deny_on_error"


def test_patch_org_settings(client: TestClient) -> None:
    response = client.patch(
        "/v1/org/settings",
        headers={"x-api-key": ORG_B_KEY},
        json={"fail_mode": "allow_with_flag", "region": "mena"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["fail_mode"] == "allow_with_flag"
    assert body["region"] == "mena"

    # restore for other tests
    client.patch(
        "/v1/org/settings",
        headers={"x-api-key": ORG_B_KEY},
        json={"region": "uae"},
    )


def test_cross_tenant_replay_returns_403(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    _post_event(client, ORG_A_KEY, trace_id)

    response = client.get(
        f"/v1/trace/{trace_id}/replay",
        headers={"x-api-key": ORG_B_KEY},
    )
    assert response.status_code == 403


def test_cross_tenant_evidence_export_returns_403(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    _post_event(client, ORG_A_KEY, trace_id)

    response = client.get(
        f"/v1/evidence/{trace_id}/export",
        headers={"x-api-key": ORG_B_KEY},
    )
    assert response.status_code == 403


def test_cross_tenant_event_post_returns_403(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    _post_event(client, ORG_A_KEY, trace_id)

    response = client.post(
        "/v1/event",
        headers={"x-api-key": ORG_B_KEY},
        json={
            "trace_id": trace_id,
            "seq": 2,
            "type": "model_completion",
            "payload": {"attack": True},
        },
    )
    assert response.status_code == 403


def test_invalid_api_key_returns_401(client: TestClient) -> None:
    response = client.get("/v1/org/me", headers={"x-api-key": "totally-invalid"})
    assert response.status_code == 401
