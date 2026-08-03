"""Grafting events that were recorded while Attest was unreachable.

The SDK buffers during an outage and signs each event into its own local chain.
On recovery it posts the segment here. This module is the sceptic: it verifies
every claim before anything is written, and refuses the segment if the chain
does not hold.

What is and is not guaranteed, stated plainly because it matters:

  * The device's signature proves the claim came from that registered SDK
    instance and has not been edited since.
  * The local chain (prev_local links) proves no event was removed from the
    middle of the segment, or reordered.
  * `occurred_at` remains the CUSTOMER'S claim about when it happened. A
    compromised client could still lie about the clock, or withhold an event
    entirely and never send it. What it cannot do is alter a claim after
    signing, or quietly drop one from a segment it does submit.
  * Attest's own created_at records when we actually saw it. Both are stored;
    `deferred` marks the event so the gap is never mistaken for real-time.

That is a real, bounded guarantee — not perfect, and the dashboards say so
rather than implying the outage window is as strong as normal operation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.crypto.canonical import sha256_hex
from app.crypto.offline_envelope import build_offline_claim, offline_claim_hash
from app.crypto.signing import verify_hex
from app.db.models import Event, Org, SdkDevice
from app.services.gate import run_gate


class OfflineSegmentError(ValueError):
    """The submitted segment failed verification. Nothing is written."""


def register_device(
    db: Session, *, org_id: str, device_id: str, public_pem: str, label: str | None = None
) -> SdkDevice:
    """Record an SDK instance's public key. Idempotent for the same key.

    Re-registering a DIFFERENT key under an existing device id is refused: that
    is either a bug or an attempt to have an old device's signed history
    validate against a new key.
    """
    existing = (
        db.query(SdkDevice)
        .filter(SdkDevice.org_id == org_id, SdkDevice.device_id == device_id)
        .one_or_none()
    )
    if existing is not None:
        if existing.public_pem.strip() != public_pem.strip():
            msg = f"device {device_id} is already registered with a different key"
            raise OfflineSegmentError(msg)
        existing.last_seen_at = datetime.now(UTC)
        db.flush()
        return existing

    device = SdkDevice(
        org_id=org_id,
        device_id=device_id,
        public_pem=public_pem,
        label=label,
        last_seen_at=datetime.now(UTC),
    )
    db.add(device)
    db.flush()
    return device


def _verify_segment(
    device: SdkDevice, items: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Check signatures and local chain links. Returns (item, claim) pairs.

    Verified in full BEFORE anything is written: a segment is accepted or
    rejected as a whole, so a partially-valid submission cannot leave a half
    grafted trail behind.
    """
    public_pem = device.public_pem.encode("utf-8")
    verified: list[tuple[dict[str, Any], dict[str, Any]]] = []
    prev_local: str | None = None

    for index, item in enumerate(items):
        payload = item.get("output")
        if not isinstance(payload, dict):
            msg = f"item {index}: output must be an object"
            raise OfflineSegmentError(msg)

        claim = build_offline_claim(
            device_id=device.device_id,
            local_seq=int(item.get("local_seq", -1)),
            prev_local=item.get("prev_local"),
            occurred_at=str(item.get("occurred_at", "")),
            action=str(item.get("action", "")),
            payload_hash=sha256_hex(payload),
        )

        # The payload must be the one that was signed — otherwise the content
        # could be swapped after the fact while the signature still checks out.
        if claim["payload_hash"] != item.get("payload_hash"):
            msg = f"item {index}: payload does not match the signed payload_hash"
            raise OfflineSegmentError(msg)

        if index > 0 and claim["prev_local"] != prev_local:
            msg = f"item {index}: local chain broken (prev_local mismatch)"
            raise OfflineSegmentError(msg)

        digest = offline_claim_hash(claim)
        signature = str(item.get("client_signature", ""))
        if not verify_hex(public_pem, digest, signature):
            msg = f"item {index}: device signature invalid"
            raise OfflineSegmentError(msg)

        verified.append((item, claim))
        prev_local = digest

    return verified


def graft_offline_segment(
    db: Session, *, org: Org, device_id: str, items: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Verify a buffered segment and record it. All-or-nothing."""
    device = (
        db.query(SdkDevice)
        .filter(SdkDevice.org_id == org.id, SdkDevice.device_id == device_id)
        .one_or_none()
    )
    if device is None:
        msg = f"unknown device: {device_id}"
        raise OfflineSegmentError(msg)
    if device.revoked:
        msg = f"device is revoked: {device_id}"
        raise OfflineSegmentError(msg)

    verified = _verify_segment(device, items)

    results: list[dict[str, Any]] = []
    for item, claim in verified:
        trace_id = None
        raw_trace = item.get("trace_id")
        if raw_trace:
            try:
                trace_id = uuid.UUID(str(raw_trace))
            except ValueError as exc:
                msg = "invalid trace_id in segment"
                raise OfflineSegmentError(msg) from exc

        # Re-evaluated here against the live rulebooks: the SDK's offline verdict
        # was advisory and may have used a stale bundle. The server's answer is
        # authoritative, and the response reports both so divergence is visible.
        result = run_gate(
            db,
            org=org,
            action=str(item.get("action", "model_completion")),
            output=item["output"],
            trace_id=trace_id,
        )
        _mark_deferred(
            db,
            org_id=org.id,
            trace_id=uuid.UUID(result["trace_id"]),
            seq=result["output_seq"],
            occurred_at=claim["occurred_at"],
            device_id=device.device_id,
            signature=str(item.get("client_signature", "")),
        )
        result["deferred"] = True
        result["occurred_at"] = claim["occurred_at"]
        result["local_status"] = item.get("local_status")
        result["verdict_changed"] = (
            item.get("local_status") is not None and item["local_status"] != result["status"]
        )
        results.append(result)

    device.last_seen_at = datetime.now(UTC)
    db.flush()
    return results


def _mark_deferred(
    db: Session,
    *,
    org_id: str,
    trace_id: uuid.UUID,
    seq: int,
    occurred_at: str,
    device_id: str,
    signature: str,
) -> None:
    event = (
        db.query(Event)
        .filter(Event.org_id == org_id, Event.trace_id == trace_id, Event.seq == seq)
        .one_or_none()
    )
    if event is None:
        return
    event.deferred = True
    event.client_device_id = device_id
    event.client_signature = signature
    try:
        event.occurred_at = datetime.fromisoformat(occurred_at)
    except ValueError:
        event.occurred_at = None
    db.flush()
