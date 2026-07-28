"""Slice 3: consent-gated access review, end to end.

Attest cannot read a customer-key org's content until the org approves a scoped
request; then Attest can open exactly that slice, and only until it expires or is
revoked. Out-of-scope records and unmet M-of-N thresholds stay dark.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.crypto.org_encryption import generate_wrapping_keypair
from app.db.models import Org
from app.services import orgs as org_service
from app.services.access_review import (
    approve_access_request,
    create_access_request,
    read_via_grant,
    resolve_access_request,
)
from app.services.payload_store import read_payload_content, store_encrypted_payload


@pytest.fixture()
def db(db_available: bool):
    if not db_available:
        pytest.skip("PostgreSQL not available")
    from app.db.session import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _customer_key_org(db) -> tuple[str, bytes]:
    org_id = f"org_{uuid.uuid4().hex[:10]}"
    db.add(Org(id=org_id, name="Test", api_key_hash=uuid.uuid4().hex))
    db.flush()
    org_private, org_public = generate_wrapping_keypair()
    org_service.enable_customer_key_mode(db, org_id, org_public)
    return org_id, org_private


def _store(db, org_id: str, content: dict) -> str:
    ph = "h_" + uuid.uuid4().hex
    store_encrypted_payload(db, org_id=org_id, payload_hash=ph, content=content, pii_labels=[])
    return ph


def test_full_consent_ceremony(db) -> None:
    org_id, org_private = _customer_key_org(db)
    in_scope = _store(db, org_id, {"prompt": "wire AED 50000"})
    out_of_scope = _store(db, org_id, {"prompt": "unrelated"})

    # Baseline: Attest is dark.
    assert read_payload_content(db, org_id, in_scope) is None

    req = create_access_request(
        db,
        org_id=org_id,
        requested_by="attest_ops_1",
        payload_hashes=[in_scope],
        reason="dispute #42",
    )

    # Before approval: nothing readable.
    assert read_via_grant(db, request_id=req.id, payload_hash=in_scope) is None

    # Org approves (using its private key to release just this record's key).
    approve_access_request(
        db, request_id=req.id, approver_id="officer_1", org_private_pem=org_private
    )

    # Now Attest can open exactly the approved record...
    assert read_via_grant(db, request_id=req.id, payload_hash=in_scope) == {
        "prompt": "wire AED 50000"
    }
    # ...but not one that wasn't in scope.
    assert read_via_grant(db, request_id=req.id, payload_hash=out_of_scope) is None


def test_m_of_n_requires_all_approvals(db) -> None:
    org_id, org_private = _customer_key_org(db)
    ph = _store(db, org_id, {"x": 1})
    req = create_access_request(
        db,
        org_id=org_id,
        requested_by="ops",
        payload_hashes=[ph],
        reason="r",
        required_approvals=2,
    )

    approve_access_request(
        db, request_id=req.id, approver_id="officer_1", org_private_pem=org_private
    )
    assert req.status == "pending"
    assert read_via_grant(db, request_id=req.id, payload_hash=ph) is None

    approve_access_request(
        db, request_id=req.id, approver_id="officer_2", org_private_pem=org_private
    )
    assert req.status == "approved"
    assert read_via_grant(db, request_id=req.id, payload_hash=ph) == {"x": 1}


def test_expired_grant_is_dark_again(db) -> None:
    org_id, org_private = _customer_key_org(db)
    ph = _store(db, org_id, {"x": 2})
    req = create_access_request(
        db, org_id=org_id, requested_by="ops", payload_hashes=[ph], reason="r"
    )
    approve_access_request(db, request_id=req.id, approver_id="o1", org_private_pem=org_private)
    assert read_via_grant(db, request_id=req.id, payload_hash=ph) == {"x": 2}

    req.expires_at = datetime.now(UTC) - timedelta(hours=1)
    db.flush()
    assert read_via_grant(db, request_id=req.id, payload_hash=ph) is None


def test_revoked_request_is_dark(db) -> None:
    org_id, org_private = _customer_key_org(db)
    ph = _store(db, org_id, {"x": 3})
    req = create_access_request(
        db, org_id=org_id, requested_by="ops", payload_hashes=[ph], reason="r"
    )
    approve_access_request(db, request_id=req.id, approver_id="o1", org_private_pem=org_private)
    resolve_access_request(db, request_id=req.id, status="revoked")
    assert read_via_grant(db, request_id=req.id, payload_hash=ph) is None
