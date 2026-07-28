"""Slice 2: customer-key mode makes stored content dark to Attest.

Proves: for a customer-key org, Attest's read path returns nothing (the content
key is wrapped to the org's key), yet the content is fully recoverable with the
org's private key — while a default (attest_managed) org is unchanged.
"""

from __future__ import annotations

import base64
import uuid

import pytest

from app.crypto.org_encryption import generate_wrapping_keypair, unwrap_key
from app.db.models import Org, PayloadKey
from app.services import orgs as org_service
from app.services.payload_store import (
    _aad,
    _decrypt_content,
    read_payload_content,
    store_encrypted_payload,
)


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


def _new_org(db, *, customer_key: bool) -> tuple[str, bytes]:
    org_id = f"org_{uuid.uuid4().hex[:10]}"
    db.add(Org(id=org_id, name="Test", api_key_hash=uuid.uuid4().hex))
    db.flush()
    org_private = b""
    if customer_key:
        org_private, org_public = generate_wrapping_keypair()
        org_service.enable_customer_key_mode(db, org_id, org_public)
    return org_id, org_private


def test_customer_key_content_is_dark_to_attest_but_org_can_open(db) -> None:
    org_id, org_private = _new_org(db, customer_key=True)
    payload_hash = "h_" + uuid.uuid4().hex
    content = {"prompt": "wire AED 50000", "output": "done"}

    store_encrypted_payload(
        db, org_id=org_id, payload_hash=payload_hash, content=content, pii_labels=[]
    )

    # Attest cannot read it.
    assert read_payload_content(db, org_id, payload_hash) is None

    # ...but with the org's private key, the content comes back intact.
    key_row = db.query(PayloadKey).filter(PayloadKey.payload_hash == payload_hash).one()
    assert key_row.wrap_alg is not None  # the DEK is wrapped
    from app.db.models import Payload

    payload = db.query(Payload).filter(Payload.payload_hash == payload_hash).one()
    raw_dek = unwrap_key(org_private, base64.b64decode(key_row.key_b64))
    dek_b64 = base64.b64encode(raw_dek).decode("ascii")
    aad = _aad(enc_alg=payload.enc_alg, org_id=org_id, payload_hash=payload_hash)
    recovered = _decrypt_content(payload.encrypted_blob, dek_b64, aad=aad)
    assert recovered == content


def test_default_org_content_is_readable_by_attest(db) -> None:
    org_id, _ = _new_org(db, customer_key=False)
    payload_hash = "h_" + uuid.uuid4().hex
    content = {"prompt": "hello", "output": "hi"}

    store_encrypted_payload(
        db, org_id=org_id, payload_hash=payload_hash, content=content, pii_labels=[]
    )

    # Default (attest_managed) mode is unchanged — Attest can still read.
    assert read_payload_content(db, org_id, payload_hash) == content
    key_row = db.query(PayloadKey).filter(PayloadKey.payload_hash == payload_hash).one()
    assert key_row.wrap_alg is None
