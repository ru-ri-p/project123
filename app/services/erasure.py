"""PDPL erasure via crypto-shredding with anchored erasure events."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.repositories import events as event_repo
from app.services.events import EventSequenceError, record_event
from app.services.payload_store import crypto_shred_payload
from app.services.trace_access import ensure_trace_access


class ErasureTargetError(LookupError):
    """Target event or payload not found."""


class PayloadAlreadyErasedError(ValueError):
    """Payload content was already crypto-shredded."""


def erase_event_payload(
    db: Session,
    *,
    org_id: str,
    trace_id: uuid.UUID,
    target_seq: int,
    approver_id: str,
    reason: str,
) -> dict[str, Any]:
    ensure_trace_access(db, org_id, trace_id)

    events = event_repo.events_for_trace(db, org_id, trace_id)
    target = next((event for event in events if event.seq == target_seq), None)
    if target is None:
        msg = f"event seq {target_seq} not found on trace"
        raise ErasureTargetError(msg)

    payload = event_repo.get_payload(db, org_id, target.payload_hash)
    if payload is None:
        msg = f"payload not found for seq {target_seq}"
        raise ErasureTargetError(msg)
    if payload.erased_at is not None:
        msg = f"payload already erased for seq {target_seq}"
        raise PayloadAlreadyErasedError(msg)

    shredded = crypto_shred_payload(db, org_id=org_id, payload_hash=target.payload_hash)
    if not shredded:
        msg = f"payload key missing for seq {target_seq}"
        raise ErasureTargetError(msg)

    next_seq = events[-1].seq + 1 if events else 1
    erasure_payload = {
        "target_payload_hash": target.payload_hash,
        "target_seq": target_seq,
        "approver_id": approver_id,
        "reason": reason,
    }

    try:
        result = record_event(
            db,
            org_id=org_id,
            trace_id=trace_id,
            seq=next_seq,
            event_type="erasure",
            payload=erasure_payload,
            policy_version=target.policy_version,
        )
    except EventSequenceError:
        # Race: re-fetch chain tip and append at correct seq
        events = event_repo.events_for_trace(db, org_id, trace_id)
        next_seq = events[-1].seq + 1
        result = record_event(
            db,
            org_id=org_id,
            trace_id=trace_id,
            seq=next_seq,
            event_type="erasure",
            payload=erasure_payload,
            policy_version=target.policy_version,
        )

    return {
        "trace_id": str(trace_id),
        "erasure_seq": result.seq,
        "target_seq": target_seq,
        "target_payload_hash": target.payload_hash,
        "hash": result.hash,
        "signature": result.signature,
    }
