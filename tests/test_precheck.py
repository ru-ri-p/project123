"""Phase 3 Week 8 — precheck tiers and policy engine."""

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


def test_precheck_green(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    response = client.post(
        "/v1/precheck",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "action": "model_completion",
            "payload": {"prompt": "Summarise sector trends", "citations": 2},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tier"] == "green"
    assert body["allowed"] is True
    assert body["decision"] == "allow"
    assert body["approval_id"] is None


def test_precheck_red_wire_transfer(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    response = client.post(
        "/v1/precheck",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "action": "wire_transfer",
            "payload": {"amount_aed": 50000, "beneficiary": "ACME LLC"},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tier"] == "red"
    assert body["allowed"] is False
    assert body["decision"] == "deny"
    assert body["rule_id"] == "wire_transfer"
    assert body["approval_id"] is not None

    pending = client.get("/v1/approvals?status=pending", headers=_headers())
    assert any(a["id"] == body["approval_id"] for a in pending.json())

    replay = client.get(f"/v1/trace/{trace_id}/replay", headers=_headers())
    assert any(e["type"] == "policy_decision" for e in replay.json()["events"])


def test_precheck_orange_pii(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    response = client.post(
        "/v1/precheck",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "action": "model_completion",
            "payload": {"prompt": "Email client at ali@example.com", "citations": 1},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tier"] == "orange"
    assert body["allowed"] is True
    assert body["approval_id"] is not None


def test_precheck_yellow_low_citations(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    response = client.post(
        "/v1/precheck",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "action": "model_completion",
            "payload": {"prompt": "Quick summary", "citations": 0},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tier"] == "yellow"
    assert body["allowed"] is True
    assert body["approval_id"] is None
