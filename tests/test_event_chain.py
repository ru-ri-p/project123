"""Integration tests for hash-chained event ingestion."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_api_key
from app.db.models import Org
from app.main import app

DEV_API_KEY = "org_demo_key"


@pytest.fixture(scope="module")
def client(db_available: bool) -> TestClient:
    if not db_available:
        pytest.skip("PostgreSQL not available — run: docker compose up -d")
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def seed_org(db_available: bool) -> None:
    if not db_available:
        return
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        if db.query(Org).filter(Org.id == "org_demo").one_or_none() is None:
            db.add(
                Org(
                    id="org_demo",
                    name="Demo Organisation",
                    api_key_hash=hash_api_key(DEV_API_KEY),
                )
            )
            db.commit()
    finally:
        db.close()


def _headers() -> dict[str, str]:
    return {"x-api-key": DEV_API_KEY}


def test_post_three_events_chains_hashes(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    prev_hash = ""

    for seq in (1, 2, 3):
        response = client.post(
            "/v1/event",
            headers=_headers(),
            json={
                "trace_id": trace_id,
                "seq": seq,
                "type": "model_completion",
                "payload": {"step": seq, "prompt": f"Q{seq}"},
                "policy_version": "v0",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["seq"] == seq
        assert body["hash"]
        assert body["signature"]
        if seq == 1:
            assert body["prev_hash"] == ""
        else:
            assert body["prev_hash"] == prev_hash
        prev_hash = body["hash"]


def test_out_of_order_seq_rejected(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    client.post(
        "/v1/event",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "type": "tool_call",
            "payload": {"tool": "search"},
        },
    )
    response = client.post(
        "/v1/event",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 5,
            "type": "tool_call",
            "payload": {"tool": "skip"},
        },
    )
    assert response.status_code == 409
    assert "out-of-order seq" in response.json()["detail"]


def test_custom_event_type_is_accepted(client: TestClient) -> None:
    # A non-standard type (e.g. TradeEasy's "risk_assessment") records fine —
    # the type field accepts any non-empty label, not just the six standard ones.
    trace_id = str(uuid.uuid4())
    response = client.post(
        "/v1/event",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "type": "risk_assessment",
            "payload": {"score": 0.2, "result": "low"},
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["hash"]

    replay = client.get(f"/v1/trace/{trace_id}/replay", headers=_headers())
    assert replay.json()["all_verified"] is True


def test_empty_event_type_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/v1/event",
        headers=_headers(),
        json={"trace_id": str(uuid.uuid4()), "seq": 1, "type": "", "payload": {}},
    )
    assert response.status_code == 422  # Pydantic min_length rejects empty


def test_invalid_api_key_returns_401(client: TestClient) -> None:
    response = client.post(
        "/v1/event",
        headers={"x-api-key": "bad-key"},
        json={
            "trace_id": str(uuid.uuid4()),
            "seq": 1,
            "type": "model_completion",
            "payload": {},
        },
    )
    assert response.status_code == 401
