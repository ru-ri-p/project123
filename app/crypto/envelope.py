"""The sealed envelope — the assembled crypto core.

We hash the ENVELOPE (metadata), not the raw content. The sealed-forever record
holds only a fingerprint of the content (payload_hash). The content itself —
which may hold personal data — is stored separately and encrypted (Week 2). This
split is what lets a privacy erasure later destroy the content while the
proof-of-existence survives. Designing it in now avoids a painful rewrite.
"""

from datetime import datetime, timezone

from app.crypto.canonical import sha256_hex
from app.crypto.signing import sign_hex


def now_utc_iso() -> str:
    # SERVER clock, always UTC. Client-supplied times are never trusted for
    # sealing — an attacker could backdate records otherwise.
    return datetime.now(timezone.utc).isoformat()


def build_envelope(trace_id, seq, etype, payload_hash, prev_hash, created_at) -> dict:
    """Frozen shape. Rename a field and ALL previously sealed events fail to verify.

    Returns EXACTLY these six keys and no others.
    """
    return {
        "trace_id": trace_id,
        "seq": seq,
        "type": etype,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "created_at": created_at,
    }


def seal(envelope: dict) -> tuple[str, str]:
    # Fingerprint the envelope, then sign that fingerprint. Returns
    # (sha256_hex of envelope, signature over that hash).
    h = sha256_hex(envelope)
    return h, sign_hex(h)
