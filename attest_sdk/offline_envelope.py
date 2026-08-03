"""The claim this SDK signs for an event recorded while Attest was unreachable.

BYTE-IDENTICAL COPY of app/crypto/offline_envelope.py. The SDK is a standalone
package and cannot import the server, so the definition is duplicated on purpose
— if the two ever diverge, signatures made here stop verifying there. A test in
the server repo asserts the function bodies match; do not edit one alone.

What the signature covers, and why each field is in it:

  device_id     — which SDK instance made the claim
  local_seq     — position in that device's own chain, so a dropped or reordered
                  event is detectable
  prev_local    — the previous local event's claim hash: chains the segment, so
                  an event cannot be removed from the middle
  occurred_at   — when the customer's system says it happened (the whole point:
                  Attest's own created_at can only be the later graft time)
  action        — what the AI did
  payload_hash  — SHA-256 of the canonicalised payload, so the content is bound
                  to the claim without the claim carrying the content
"""

from __future__ import annotations

from typing import Any

from .canonical import sha256_hex

OFFLINE_CLAIM_VERSION = "attest-offline-v1"


def build_offline_claim(
    *,
    device_id: str,
    local_seq: int,
    prev_local: str | None,
    occurred_at: str,
    action: str,
    payload_hash: str,
) -> dict[str, Any]:
    return {
        "v": OFFLINE_CLAIM_VERSION,
        "device_id": device_id,
        "local_seq": local_seq,
        "prev_local": prev_local or "",
        "occurred_at": occurred_at,
        "action": action,
        "payload_hash": payload_hash,
    }


def offline_claim_hash(claim: dict[str, Any]) -> str:
    """The digest actually signed, and the link the next claim points back to."""
    return sha256_hex(claim)
