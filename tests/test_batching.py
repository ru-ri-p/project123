"""Batch sealing and RFC 3161 anchoring integration tests."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.db.models import Anchor, Event
from app.db.session import SessionLocal
from app.main import app
from app.repositories import batches as batch_repo
from app.services.anchor_batches import anchor_batch
from app.services.batching import seal_batch

DEV_API_KEY = "org_demo_key"


@pytest.fixture(scope="module")
def client(db_available: bool) -> TestClient:
    if not db_available:
        pytest.skip("PostgreSQL not available — run: docker compose up -d")
    return TestClient(app)


def _post_event(client: TestClient, trace_id: str, seq: int) -> None:
    response = client.post(
        "/v1/event",
        headers={"x-api-key": DEV_API_KEY},
        json={
            "trace_id": trace_id,
            "seq": seq,
            "type": "model_completion",
            "payload": {"step": seq},
        },
    )
    assert response.status_code == 200, response.text


def test_seal_batch_merkle_root_and_assigns_events(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    _post_event(client, trace_id, 1)
    _post_event(client, trace_id, 2)

    db = SessionLocal()
    try:
        sealed = seal_batch(db)
        assert sealed is not None
        assert sealed.event_count >= 2
        db.commit()

        batch = batch_repo.batch_by_id(db, sealed.batch_id)
        assert batch is not None
        assert batch.root == sealed.root
        assert batch.signature

        for event_id in batch.event_ids:
            event = db.query(Event).filter(Event.id == uuid.UUID(event_id)).one()
            assert event.batch_id == batch.id
    finally:
        db.close()


def test_seal_batch_twice_second_call_is_none(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    _post_event(client, trace_id, 1)

    db = SessionLocal()
    try:
        first = seal_batch(db)
        assert first is not None
        db.commit()

        second = seal_batch(db)
        assert second is None
    finally:
        db.close()


def test_anchor_batch_stores_rfc3161_token(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace_id = str(uuid.uuid4())
    _post_event(client, trace_id, 1)

    db = SessionLocal()
    try:
        sealed = seal_batch(db)
        assert sealed is not None
        db.commit()

        fake_token = b"fake-tsr-token-bytes"

        def fake_post(*_args: object, **_kwargs: object) -> MagicMock:
            mock = MagicMock()
            mock.content = fake_token
            mock.raise_for_status = MagicMock()
            return mock

        monkeypatch.setattr(
            "app.services.anchoring.decode_timestamp_response",
            lambda _content: object(),
        )
        monkeypatch.setattr("app.services.anchoring.requests.post", fake_post)

        result = anchor_batch(db, sealed.batch_id)
        db.commit()

        anchor = db.query(Anchor).filter(Anchor.batch_id == sealed.batch_id).one()
        assert anchor.kind == "rfc3161"
        assert result.anchor_id == anchor.id
    finally:
        db.close()
