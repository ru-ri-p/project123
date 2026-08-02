"""The consent ceremony's tamper-evident trail.

Every lifecycle action on an access request — filed, approved, denied/revoked,
and every successful read through a grant — is recorded as a signed,
hash-chained event in a dedicated per-request trace, through the SAME pipeline
as customer events (canonical envelope, SHA-256 chain, per-org Ed25519 signing,
Merkle batching and external anchoring). The access-control system is audited by
the very chain it protects: an insider who grants themselves access cannot later
deny it, and one who deletes the evidence breaks a signed chain and the anchor.

Security invariants enforced here:

- ATOMICITY — the consent event is written in the same DB transaction as the
  state change it describes. Either both commit or neither does; there is no
  window where access state and audit trail disagree.
- FAIL-CLOSED — callers treat a failure to record as a failure of the action
  itself. In particular a read via a grant that cannot be recorded MUST NOT
  return content ("no unrecorded vendor access").
- NO KEY MATERIAL — payloads carry hashes and fingerprints only: record hashes,
  a SHA-256 fingerprint of the grantee public key, never any PEM or wrapped key.
- SERIALISED APPENDS — the consent trace row is locked (SELECT ... FOR UPDATE)
  before computing the next seq, so concurrent approvals/reads cannot race the
  chain; the (trace_id, seq) unique constraint backstops the lock.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import AccessRequest, Trace
from app.repositories import events as event_repo
from app.services import events as event_service

# Consent-trail event types (recorded alongside, not instead of, the standard set).
TYPE_REQUEST = "access_request"
TYPE_APPROVAL = "access_approval"
TYPE_RESOLUTION = "access_resolution"
TYPE_READ = "access_read"


def key_fingerprint(pem: str) -> str:
    """SHA-256 fingerprint of a PEM — binds an event to a key without embedding it."""
    return hashlib.sha256(pem.encode("utf-8")).hexdigest()


def _locked_next_seq(db: Session, org_id: str, trace_id: uuid.UUID) -> int:
    """Lock the consent trace and return the next seq.

    The row lock serialises concurrent writers (two approvers clicking at once,
    an approval racing a read); without it both could compute the same seq and
    one insert would die on the unique constraint instead of queueing.
    """
    db.query(Trace).filter(Trace.id == trace_id).with_for_update().one()
    last = event_repo.last_event_for_trace(db, org_id, trace_id)
    return 1 if last is None else last.seq + 1


def start_consent_trace(db: Session, request: AccessRequest) -> uuid.UUID:
    """Create the request's consent trace (called once, when the request is filed)."""
    trace_id = uuid.uuid4()
    event_repo.get_or_create_trace(db, request.org_id, trace_id, policy_version=None)
    request.trace_id = trace_id
    db.flush()
    return trace_id


def record_consent_event(
    db: Session,
    *,
    request: AccessRequest,
    event_type: str,
    payload: dict[str, Any],
) -> None:
    """Append one consent event to the request's trace, inside the caller's txn.

    Raises on any failure — callers must let that abort the surrounding action
    (fail-closed). Requests that predate the consent trail (trace_id NULL) are
    skipped: there is no chain to extend and fabricating one retroactively would
    itself be a false record.
    """
    if request.trace_id is None:
        return
    seq = _locked_next_seq(db, request.org_id, request.trace_id)
    body = {"request_id": str(request.id), **payload}
    event_service.record_event(
        db,
        org_id=request.org_id,
        trace_id=request.trace_id,
        seq=seq,
        event_type=event_type,
        payload=body,
        policy_version=None,
    )
