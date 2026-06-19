"""Week 10 — approvals end-to-end and workflow gate."""

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
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_dev_policy.py")],
        check=True,
        cwd=ROOT,
    )
    from app.main import app

    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"x-api-key": API_KEY}


def test_red_precheck_gate_approve_resume(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())

    precheck = client.post(
        "/v1/precheck",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "action": "wire_transfer",
            "payload": {"amount_aed": 25000},
        },
    )
    assert precheck.status_code == 200, precheck.text
    body = precheck.json()
    approval_id = body["approval_id"]
    assert approval_id is not None

    gate = client.get(f"/v1/trace/{trace_id}/gate", headers=_headers())
    assert gate.status_code == 200
    assert gate.json()["workflow_status"] == "blocked_pending_approval"
    assert gate.json()["resume_allowed"] is False

    resolve = client.post(
        f"/v1/approvals/{approval_id}/resolve",
        headers=_headers(),
        json={
            "status": "approved",
            "approver_id": "risk_officer_1",
            "comment": "Reviewed wire transfer",
        },
    )
    assert resolve.status_code == 200, resolve.text
    resolved = resolve.json()
    assert resolved["resume_allowed"] is True
    assert resolved["workflow_status"] == "proceed"

    gate_after = client.get(f"/v1/trace/{trace_id}/gate", headers=_headers())
    assert gate_after.json()["resume_allowed"] is True
    assert gate_after.json()["workflow_status"] == "proceed"

    record = client.post(
        "/v1/event",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 3,
            "type": "model_completion",
            "payload": {"output": "Transfer prepared after approval"},
        },
    )
    assert record.status_code == 200, record.text

    replay = client.get(f"/v1/trace/{trace_id}/replay", headers=_headers())
    types = [e["type"] for e in replay.json()["events"]]
    assert "policy_decision" in types
    assert "approval_action" in types
    assert "model_completion" in types


def test_deny_blocks_resume(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    precheck = client.post(
        "/v1/precheck",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "action": "wire_transfer",
            "payload": {"amount_aed": 1000},
        },
    )
    approval_id = precheck.json()["approval_id"]

    client.post(
        f"/v1/approvals/{approval_id}/resolve",
        headers=_headers(),
        json={"status": "denied", "approver_id": "officer_1", "comment": "Not authorised"},
    )

    gate = client.get(f"/v1/trace/{trace_id}/gate", headers=_headers())
    assert gate.json()["workflow_status"] == "blocked_denied"
    assert gate.json()["resume_allowed"] is False


def test_yellow_mitigate_then_proceed(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    precheck = client.post(
        "/v1/precheck",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "action": "model_completion",
            "payload": {"prompt": "Summarise markets", "citations": 0},
        },
    )
    assert precheck.json()["tier"] == "yellow"
    mitigations = precheck.json().get("mitigations") or []
    assert len(mitigations) > 0

    client.post(
        "/v1/mitigate",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 2,
            "mitigation_ids": mitigations[:1],
            "source_payload": {"prompt": "Summarise markets", "citations": 0},
            "policy_decision_seq": 1,
        },
    )

    gate = client.get(f"/v1/trace/{trace_id}/gate", headers=_headers())
    assert gate.json()["resume_allowed"] is True
