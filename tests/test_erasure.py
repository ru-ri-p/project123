"""PII redaction, encryption, and crypto-shredding tests (Phase 2 Week 6)."""

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
        pytest.skip("PostgreSQL not available — run: docker compose up -d")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_dev_org.py")],
        check=True,
        cwd=ROOT,
    )
    from app.main import app

    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"x-api-key": API_KEY}


def test_pii_is_redacted_before_storage(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    response = client.post(
        "/v1/event",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "type": "model_completion",
            "payload": {
                "prompt": "Contact ali@example.com",
                "emirates_id": "784-1990-1234567-1",
            },
        },
    )
    assert response.status_code == 200

    export = client.get(f"/v1/evidence/{trace_id}/export", headers=_headers())
    assert export.status_code == 200
    event = export.json()["events"][0]
    assert "[REDACTED:email]" in event["payload"]["prompt"]
    assert "[REDACTED:emirates_id]" in event["payload"]["emirates_id"]
    assert "email" in event["pii_redacted"]


def test_crypto_shred_and_erasure_event(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    client.post(
        "/v1/event",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "type": "model_completion",
            "payload": {"output": f"Sensitive market note {trace_id}"},
        },
    )

    erase = client.post(
        "/v1/erasure",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "target_seq": 1,
            "approver_id": "officer_1",
            "reason": "PDPL erasure request",
        },
    )
    assert erase.status_code == 200, erase.text
    body = erase.json()
    assert body["target_seq"] == 1
    assert body["erasure_seq"] == 2

    export = client.get(f"/v1/evidence/{trace_id}/export", headers=_headers())
    events = export.json()["events"]
    assert events[0]["payload"] is None
    assert events[0]["payload_erased"] is True
    assert events[1]["type"] == "erasure"

    replay = client.get(f"/v1/trace/{trace_id}/replay", headers=_headers())
    assert replay.json()["all_verified"] is True


def test_double_erasure_returns_409(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    client.post(
        "/v1/event",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "type": "model_completion",
            "payload": {"output": "data"},
        },
    )
    client.post(
        "/v1/erasure",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "target_seq": 1,
            "approver_id": "officer_1",
            "reason": "first erasure",
        },
    )
    again = client.post(
        "/v1/erasure",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "target_seq": 1,
            "approver_id": "officer_1",
            "reason": "duplicate",
        },
    )
    assert again.status_code == 409
