"""Consent-gated access review (Slice 3).

Attest files a scoped request → the org approves (1 or M-of-N) → on the final
approval the org (holding its private key) re-wraps ONLY the approved records'
content keys to Attest's ephemeral grantee key → Attest can then open exactly
that slice, and only until the request expires. The request/approvals/grant rows
are the auditable trail (wiring them into the signed event chain is a follow-on).

The org private key is passed in by the caller (the org's environment) and is
never stored by Attest — consistent with customer-managed keys.
"""

from __future__ import annotations

import base64
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.crypto.org_encryption import (
    KeyWrappingError,
    generate_wrapping_keypair,
    regrant_key,
    unwrap_key,
)
from app.db.models import AccessApproval, AccessGrantKey, AccessRequest, Payload, PayloadKey
from app.services.payload_store import PayloadShreddedError, _aad, _decrypt_content

DEFAULT_TTL_SECONDS = 3600


class AccessReviewError(ValueError):
    """Raised for invalid access-review operations (unknown request, etc.)."""


def _now() -> datetime:
    return datetime.now(UTC)


def create_access_request(
    db: Session,
    *,
    org_id: str,
    requested_by: str,
    payload_hashes: Iterable[str],
    reason: str,
    required_approvals: int = 1,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> AccessRequest:
    """Attest files a request for a specific set of records, with a fresh ephemeral
    grantee keypair and an expiry. Status starts 'pending'; nothing is unlocked yet."""
    grantee_private, grantee_public = generate_wrapping_keypair()
    request = AccessRequest(
        org_id=org_id,
        requested_by=requested_by,
        reason=reason,
        status="pending",
        required_approvals=max(1, required_approvals),
        grantee_public_pem=grantee_public.decode("utf-8"),
        grantee_private_pem=grantee_private.decode("utf-8"),
        expires_at=_now() + timedelta(seconds=ttl_seconds),
    )
    db.add(request)
    db.flush()
    for payload_hash in payload_hashes:
        db.add(
            AccessGrantKey(request_id=request.id, payload_hash=payload_hash, wrapped_key_b64=None)
        )
    db.flush()
    return request


def _release_keys(db: Session, request: AccessRequest, org_private_pem: bytes) -> None:
    """Org side: re-wrap each in-scope record's content key to the grantee key."""
    grantee_public = request.grantee_public_pem.encode("utf-8")
    items = db.query(AccessGrantKey).filter(AccessGrantKey.request_id == request.id).all()
    for item in items:
        key_row = (
            db.query(PayloadKey)
            .filter(
                PayloadKey.org_id == request.org_id, PayloadKey.payload_hash == item.payload_hash
            )
            .one_or_none()
        )
        if key_row is None or key_row.wrap_alg is None:
            continue  # not a customer-key record (nothing to release)
        wrapped_for_org = base64.b64decode(key_row.key_b64.encode("ascii"))
        try:
            regranted = regrant_key(org_private_pem, wrapped_for_org, grantee_public)
        except KeyWrappingError:
            continue  # wrong org key — release nothing for this item
        item.wrapped_key_b64 = base64.b64encode(regranted).decode("ascii")
    db.flush()


def approve_access_request(
    db: Session, *, request_id: uuid.UUID, approver_id: str, org_private_pem: bytes
) -> AccessRequest:
    """Record an approver's approval; on reaching the required count, release keys."""
    request = db.get(AccessRequest, request_id)
    if request is None:
        msg = f"access request not found: {request_id}"
        raise AccessReviewError(msg)
    if request.status != "pending":
        return request  # already resolved — idempotent

    existing = (
        db.query(AccessApproval)
        .filter(AccessApproval.request_id == request_id, AccessApproval.approver_id == approver_id)
        .one_or_none()
    )
    if existing is None:
        db.add(AccessApproval(request_id=request_id, approver_id=approver_id))
        db.flush()

    count = db.query(AccessApproval).filter(AccessApproval.request_id == request_id).count()
    if count >= request.required_approvals:
        _release_keys(db, request, org_private_pem)
        request.status = "approved"
        db.flush()
    return request


def resolve_access_request(db: Session, *, request_id: uuid.UUID, status: str) -> AccessRequest:
    """Deny or revoke a request (status in {'denied','revoked'})."""
    request = db.get(AccessRequest, request_id)
    if request is None:
        msg = f"access request not found: {request_id}"
        raise AccessReviewError(msg)
    request.status = status
    db.flush()
    return request


def read_via_grant(
    db: Session, *, request_id: uuid.UUID, payload_hash: str
) -> dict[str, Any] | None:
    """Attest reads one record via an approved, unexpired grant — or None."""
    request = db.get(AccessRequest, request_id)
    if request is None or request.status != "approved":
        return None
    if request.expires_at <= _now():
        return None

    item = (
        db.query(AccessGrantKey)
        .filter(
            AccessGrantKey.request_id == request_id, AccessGrantKey.payload_hash == payload_hash
        )
        .one_or_none()
    )
    if item is None or item.wrapped_key_b64 is None:
        return None  # not in scope, or key not released

    grantee_private = request.grantee_private_pem.encode("utf-8")
    try:
        dek = unwrap_key(grantee_private, base64.b64decode(item.wrapped_key_b64.encode("ascii")))
    except KeyWrappingError:
        return None

    payload = (
        db.query(Payload)
        .filter(Payload.org_id == request.org_id, Payload.payload_hash == payload_hash)
        .one_or_none()
    )
    if payload is None or payload.erased_at is not None:
        return None

    aad = _aad(enc_alg=payload.enc_alg, org_id=request.org_id, payload_hash=payload_hash)
    try:
        return _decrypt_content(
            payload.encrypted_blob, base64.b64encode(dek).decode("ascii"), aad=aad
        )
    except PayloadShreddedError:
        return None
