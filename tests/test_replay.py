"""Replay and tamper-detection tests — the core product guarantee."""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db.models import Event
from app.db.session import SessionLocal

ROOT = Path(__file__).resolve().parents[1]
DEV_API_KEY = "org_demo_key"
VERIFY_SCRIPT = ROOT / "app" / "bundle" / "verify.py"


@pytest.fixture(scope="module")
def client(db_available: bool) -> TestClient:
    if not db_available:
        pytest.skip("PostgreSQL not available — run: docker compose up -d")
    from app.main import app

    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"x-api-key": DEV_API_KEY}


def _record_trace(client: TestClient, event_count: int = 3) -> str:
    trace_id = str(uuid.uuid4())
    for seq in range(1, event_count + 1):
        response = client.post(
            "/v1/event",
            headers=_headers(),
            json={
                "trace_id": trace_id,
                "seq": seq,
                "type": "model_completion",
                "payload": {"step": seq, "prompt": f"step {seq}"},
                "policy_version": "v0",
            },
        )
        assert response.status_code == 200, response.text
    return trace_id


def test_replay_intact_trace_all_verified(client: TestClient) -> None:
    trace_id = _record_trace(client)
    response = client.get(f"/v1/trace/{trace_id}/replay", headers=_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["all_verified"] is True
    assert len(body["events"]) == 3
    assert all(event["verified"] for event in body["events"])


def test_tampering_is_detected(client: TestClient) -> None:
    trace_id = _record_trace(client)
    assert client.get(f"/v1/trace/{trace_id}/replay", headers=_headers()).json()["all_verified"]

    db = SessionLocal()
    try:
        event = (
            db.query(Event)
            .filter(Event.trace_id == uuid.UUID(trace_id), Event.seq == 2)
            .one()
        )
        event.hash = "0" * 64
        db.commit()
    finally:
        db.close()

    response = client.get(f"/v1/trace/{trace_id}/replay", headers=_headers())
    body = response.json()
    assert body["all_verified"] is False
    assert body["events"][1]["verified"] is False
    assert body["events"][1]["seq"] == 2


def test_evidence_export_and_verify_script(client: TestClient, tmp_path: Path) -> None:
    trace_id = _record_trace(client, event_count=2)
    response = client.get(f"/v1/evidence/{trace_id}/export", headers=_headers())
    assert response.status_code == 200
    bundle = response.json()
    assert bundle["replay_summary"]["all_verified"] is True
    assert bundle["verify_script"]
    assert bundle["public_key_pem"]

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), str(bundle_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "ALL EVENTS VERIFIED" in result.stdout


def test_evidence_zip_export(client: TestClient) -> None:
    trace_id = _record_trace(client, event_count=1)
    response = client.get(
        f"/v1/evidence/{trace_id}/export?format=zip",
        headers=_headers(),
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert len(response.content) > 100
