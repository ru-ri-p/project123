"""Auto-mitigation — apply client/server instructions and record signed mitigation events."""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session

from app.services.events import EventSequenceError, record_event
from app.services.pii import redact_payload
from app.services.trace_access import ensure_trace_access

VERIFY_DISCLAIMER = (
    "Verify all figures and claims against primary sources before acting on this output."
)

KNOWN_MITIGATIONS: frozenset[str] = frozenset(
    {
        "redact_pii_before_send",
        "append_verify_disclaimer",
        "require_human_review",
        "soften_absolute_claims",
    }
)


def apply_mitigation_ids(
    payload: dict[str, Any],
    mitigation_ids: list[str],
) -> tuple[dict[str, Any], list[str]]:
    """Return a deep copy of payload with mitigations applied (pure, no I/O)."""
    result = copy.deepcopy(payload)
    applied: list[str] = []
    for mitigation_id in mitigation_ids:
        handler = _HANDLERS.get(mitigation_id)
        if handler is None:
            continue
        result = handler(result)
        applied.append(mitigation_id)
    return result, applied


def record_mitigation(
    db: Session,
    *,
    org_id: str,
    trace_id: uuid.UUID,
    seq: int,
    mitigation_ids: list[str],
    source_payload: dict[str, Any],
    policy_decision_seq: int | None = None,
    policy_version: str | None = None,
) -> dict[str, Any]:
    ensure_trace_access(db, org_id, trace_id)

    mitigated_payload, applied = apply_mitigation_ids(source_payload, mitigation_ids)
    if not applied:
        msg = "no valid mitigation_ids provided"
        raise ValueError(msg)

    event_payload: dict[str, Any] = {
        "mitigation_ids": applied,
        "policy_decision_seq": policy_decision_seq,
        "mitigated_fields": _diff_keys(source_payload, mitigated_payload),
        "mitigated_payload": mitigated_payload,
    }

    try:
        result = record_event(
            db,
            org_id=org_id,
            trace_id=trace_id,
            seq=seq,
            event_type="mitigation",
            payload=event_payload,
            policy_version=policy_version,
        )
    except EventSequenceError:
        raise

    return {
        "trace_id": str(trace_id),
        "seq": result.seq,
        "hash": result.hash,
        "mitigation_ids": applied,
        "mitigated_payload": mitigated_payload,
    }


def _redact_pii(payload: dict[str, Any]) -> dict[str, Any]:
    redacted, _ = redact_payload(payload)
    return redacted


def _append_disclaimer(payload: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(payload)
    updated["attest_disclaimer"] = VERIFY_DISCLAIMER
    return updated


def _soften_claims(payload: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(payload)
    for key in ("output", "summary", "prompt"):
        value = updated.get(key)
        if isinstance(value, str):
            updated[key] = (
                value.replace("guaranteed", "may").replace("risk-free", "subject to risk")
            )
    return updated


def _require_human_review_flag(payload: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(payload)
    updated["human_review_required"] = True
    return updated


_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "redact_pii_before_send": _redact_pii,
    "append_verify_disclaimer": _append_disclaimer,
    "soften_absolute_claims": _soften_claims,
    "require_human_review": _require_human_review_flag,
}


def _diff_keys(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    keys = set(before) | set(after)
    return sorted(key for key in keys if before.get(key) != after.get(key))
