"""Dashboard API and approvals tests."""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
API_KEY = "org_demo_key"


@pytest.fixture(scope="module")
def client(db_available: bool) -> TestClient:
    if not db_available:
        pytest.skip("PostgreSQL not available")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_dev_org.py")],
        check=True,
        cwd=ROOT,
    )
    from app.main import app

    return TestClient(app)


def test_list_traces(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    client.post(
        "/v1/event",
        headers={"x-api-key": API_KEY},
        json={
            "trace_id": trace_id,
            "seq": 1,
            "type": "model_completion",
            "payload": {"note": "dashboard test"},
        },
    )
    response = client.get("/v1/traces", headers={"x-api-key": API_KEY})
    assert response.status_code == 200
    traces = response.json()
    assert any(item["trace_id"] == trace_id for item in traces)


def test_approval_resolve_flow(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    client.post(
        "/v1/event",
        headers={"x-api-key": API_KEY},
        json={
            "trace_id": trace_id,
            "seq": 1,
            "type": "model_completion",
            "payload": {"risk": "high"},
        },
    )
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "seed_pending_approval.py"),
            "--trace-id",
            trace_id,
        ],
        check=True,
        cwd=ROOT,
    )

    pending = client.get("/v1/approvals?status=pending", headers={"x-api-key": API_KEY})
    assert pending.status_code == 200
    items = pending.json()
    approval = next(a for a in items if a["trace_id"] == trace_id)

    resolve = client.post(
        f"/v1/approvals/{approval['id']}/resolve",
        headers={"x-api-key": API_KEY},
        json={"status": "approved", "approver_id": "risk_officer_1", "comment": "Reviewed"},
    )
    assert resolve.status_code == 200
    assert resolve.json()["status"] == "approved"

    replay = client.get(f"/v1/trace/{trace_id}/replay", headers={"x-api-key": API_KEY})
    assert replay.json()["all_verified"] is True
    assert any(e["type"] == "approval_action" for e in replay.json()["events"])
