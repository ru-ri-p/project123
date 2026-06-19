"""Append-only event recording with hash chaining and signing."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.crypto.algorithms import DEFAULT_ALGORITHM
from app.crypto.canonical import sha256_hex
from app.crypto.signing_provider import sign_message_hex
from app.db.models import EVENT_TYPES
from app.repositories import events as event_repo
from app.schemas import EventOut
from app.services.envelope import build_envelope, now_utc_iso
from app.services.pii import redact_payload


class EventSequenceError(ValueError):
    """Raised when seq is not strictly monotonic within a trace."""


class InvalidEventTypeError(ValueError):
    """Raised when event type is not in the allowed set."""


def record_event(
    db: Session,
    *,
    org_id: str,
    trace_id: uuid.UUID,
    seq: int,
    event_type: str,
    payload: dict[str, Any],
    policy_version: str | None,
) -> EventOut:
    if event_type not in EVENT_TYPES:
        msg = f"invalid event type: {event_type}"
        raise InvalidEventTypeError(msg)

    event_repo.get_or_create_trace(db, org_id, trace_id, policy_version)

    last = event_repo.last_event_for_trace(db, org_id, trace_id)
    expected_seq = 1 if last is None else last.seq + 1
    if seq != expected_seq:
        msg = f"out-of-order seq: expected {expected_seq}, got {seq}"
        raise EventSequenceError(msg)

    prev_hash = last.hash if last else None
    created_at_str = now_utc_iso()
    created_at = datetime.fromisoformat(created_at_str)

    redacted_payload, pii_labels = redact_payload(payload)
    payload_hash = sha256_hex(redacted_payload)
    alg = DEFAULT_ALGORITHM
    envelope = build_envelope(
        trace_id=str(trace_id),
        seq=seq,
        event_type=event_type,
        payload_hash=payload_hash,
        prev_hash=prev_hash,
        policy_version=policy_version,
        created_at=created_at_str,
        alg=alg,
    )
    event_hash = sha256_hex(envelope)
    signature = sign_message_hex(event_hash)

    event_repo.store_encrypted_payload(
        db,
        org_id=org_id,
        payload_hash=payload_hash,
        content=redacted_payload,
        pii_labels=pii_labels,
    )
    event = event_repo.insert_event(
        db,
        org_id=org_id,
        trace_id=trace_id,
        seq=seq,
        event_type=event_type,
        payload_hash=payload_hash,
        envelope=envelope,
        prev_hash=prev_hash,
        event_hash=event_hash,
        signature=signature,
        policy_version=policy_version,
        alg=alg,
        created_at=created_at.replace(tzinfo=UTC),
    )

    return EventOut(
        hash=event_hash,
        signature=signature,
        seq=seq,
        prev_hash=prev_hash or "",
        event_id=str(event.id),
    )
