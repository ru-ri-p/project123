"""Shared event/trace verification logic (write path must match — instructions §4a)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from app.crypto.algorithms import is_supported
from app.crypto.canonical import sha256_hex
from app.crypto.signing import verify_hex
from app.services.envelope import build_envelope


@dataclass(frozen=True)
class EventVerifyResult:
    seq: int
    type: str
    verified: bool
    hash_ok: bool
    signature_ok: bool
    chain_ok: bool


@dataclass(frozen=True)
class TraceReplayResult:
    trace_id: str
    all_verified: bool
    events: list[EventVerifyResult]


class VerifiableEvent(Protocol):
    trace_id: Any
    seq: int
    type: str
    payload_hash: str
    prev_hash: str | None
    policy_version: str | None
    hash: str
    signature: str
    alg: str
    envelope: dict[str, Any]


def verify_single_event(
    event: VerifiableEvent,
    *,
    public_pem: bytes,
    expected_prev_hash: str | None,
) -> EventVerifyResult:
    created_at = event.envelope["created_at"]
    # Use the alg recorded on the event. It is part of the signed envelope, so a
    # tampered alg breaks the hash; an unknown alg fails closed below.
    alg = getattr(event, "alg", None) or event.envelope.get("alg") or ""
    rebuilt = build_envelope(
        trace_id=str(event.trace_id),
        seq=event.seq,
        event_type=event.type,
        payload_hash=event.payload_hash,
        prev_hash=event.prev_hash,
        policy_version=event.policy_version,
        created_at=created_at,
        alg=alg,
    )
    recomputed = sha256_hex(rebuilt)
    hash_ok = recomputed == event.hash
    # Refuse to honour a signature under an algorithm suite this build cannot
    # verify — we cannot vouch for primitives we do not implement.
    signature_ok = is_supported(alg) and verify_hex(public_pem, event.hash, event.signature)
    chain_ok = event.prev_hash == expected_prev_hash
    verified = hash_ok and signature_ok and chain_ok
    return EventVerifyResult(
        seq=event.seq,
        type=event.type,
        verified=verified,
        hash_ok=hash_ok,
        signature_ok=signature_ok,
        chain_ok=chain_ok,
    )


def verify_event_chain(
    trace_id: str,
    events: Sequence[VerifiableEvent],
    *,
    public_pem: bytes,
) -> TraceReplayResult:
    results: list[EventVerifyResult] = []
    prev_hash: str | None = None
    all_ok = True

    for event in events:
        result = verify_single_event(event, public_pem=public_pem, expected_prev_hash=prev_hash)
        all_ok = all_ok and result.verified
        results.append(result)
        prev_hash = event.hash

    return TraceReplayResult(trace_id=trace_id, all_verified=all_ok, events=results)
