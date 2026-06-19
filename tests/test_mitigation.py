"""Auto-mitigation tests."""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.services.mitigation import apply_mitigation_ids

ROOT = Path(__file__).resolve().parents[1]
API_KEY = "org_demo_key"


def test_apply_mitigation_ids_redacts_pii() -> None:
    payload = {"prompt": "Email ali@example.com", "citations": 1}
    mitigated, applied = apply_mitigation_ids(payload, ["redact_pii_before_send"])
    assert "redact_pii_before_send" in applied
    assert "[REDACTED:email]" in mitigated["prompt"]


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


def test_mitigate_endpoint(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    client.post(
        "/v1/event",
        headers={"x-api-key": API_KEY},
        json={
            "trace_id": trace_id,
            "seq": 1,
            "type": "model_completion",
            "payload": {"output": "Draft", "citations": 0},
        },
    )
    response = client.post(
        "/v1/mitigate",
        headers={"x-api-key": API_KEY},
        json={
            "trace_id": trace_id,
            "seq": 2,
            "mitigation_ids": ["append_verify_disclaimer"],
            "source_payload": {"output": "Draft with claims"},
            "policy_decision_seq": 1,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "attest_disclaimer" in body["mitigated_payload"]

    replay = client.get(f"/v1/trace/{trace_id}/replay", headers={"x-api-key": API_KEY})
    assert any(e["type"] == "mitigation" for e in replay.json()["events"])
