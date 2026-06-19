"""Event envelope construction — shape must match on write and verify paths."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.crypto.algorithms import DEFAULT_ALGORITHM


def now_utc_iso() -> str:
    """Server-authoritative timestamp (instructions §4b)."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def build_envelope(
    trace_id: str,
    seq: int,
    event_type: str,
    payload_hash: str,
    prev_hash: str | None,
    policy_version: str | None,
    created_at: str,
    alg: str = DEFAULT_ALGORITHM,
) -> dict[str, Any]:
    # `alg` is part of the signed envelope so the algorithm suite cannot be
    # swapped undetected, and so a verifier knows which primitives to apply
    # (crypto-agility / post-quantum migration — CLAUDE.md rule 6).
    return {
        "alg": alg,
        "trace_id": str(trace_id),
        "seq": seq,
        "type": event_type,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "policy_version": policy_version,
        "created_at": created_at,
    }
