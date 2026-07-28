"""Append-only event recording with hash chaining and signing."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.crypto.algorithms import DEFAULT_ALGORITHM
from app.crypto.canonical import sha256_hex
from app.repositories import events as event_repo
from app.schemas import EventOut
from app.services.envelope import build_envelope, now_utc_iso
from app.services.org_signing import sign_event_for_org
from app.services.pii import redact_payload


class EventSequenceError(ValueError):
    """Raised when seq is not strictly monotonic within a trace."""


class InvalidEventTypeError(ValueError):
    """Raised when event type is empty. Any non-empty label is accepted; the
    standard types (app.db.models.EVENT_TYPES) are recommended, not required."""


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
    # Accept any non-empty event type — customers record actions in their own
    # vocabulary. The standard types are recommended but not enforced.
    if not event_type or not event_type.strip():
        msg = "event type must be a non-empty string"
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
    signature, signing_key_id = sign_event_for_org(db, org_id, event_hash)

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
        signing_key_id=signing_key_id,
        created_at=created_at.replace(tzinfo=UTC),
    )

    return EventOut(
        hash=event_hash,
        signature=signature,
        seq=seq,
        prev_hash=prev_hash or "",
        event_id=str(event.id),
    )
