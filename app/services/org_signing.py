"""Per-org signing keys (Slice 4).

Each org can have its own signing key, so a record's signature proves it came
from that org, and one org's key can rotate/revoke without affecting others.
Every event records the key-id that signed it, so old events keep verifying under
the key that made them.

This slice implements Attest-managed per-org keys (Attest generates and holds the
private key per org). Customer-controlled signing (private key never leaves the
org, signing happens client-side in the SDK) is the follow-on — the model already
supports it via private_pem = NULL.

Orgs without a provisioned key fall back to the global service key, so existing
deployments (e.g. the live pilot) are unchanged.
"""

from __future__ import annotations

import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session

from app.crypto.algorithms import DEFAULT_ALGORITHM
from app.crypto.signing import sign_hex
from app.crypto.signing_provider import sign_message_hex
from app.db.models import OrgSigningKey


def _generate_ed25519_pair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    private_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def active_signing_key(db: Session, org_id: str) -> OrgSigningKey | None:
    return (
        db.query(OrgSigningKey)
        .filter(OrgSigningKey.org_id == org_id, OrgSigningKey.status == "active")
        .order_by(OrgSigningKey.created_at.desc())
        .first()
    )


def provision_managed_signing_key(db: Session, org_id: str) -> OrgSigningKey:
    """Give an org its own Attest-managed signing key. Retires any current active
    key (rotation): old events still verify under the retired key's id."""
    for existing in (
        db.query(OrgSigningKey)
        .filter(OrgSigningKey.org_id == org_id, OrgSigningKey.status == "active")
        .all()
    ):
        existing.status = "retired"

    private_pem, public_pem = _generate_ed25519_pair()
    key = OrgSigningKey(
        org_id=org_id,
        alg=DEFAULT_ALGORITHM,
        public_pem=public_pem.decode("utf-8"),
        private_pem=private_pem.decode("utf-8"),
        status="active",
    )
    db.add(key)
    db.flush()
    return key


def sign_event_for_org(db: Session, org_id: str, message_hex: str) -> tuple[str, uuid.UUID | None]:
    """Sign with the org's active key if it has one (returns its key-id), else fall
    back to the global service key (returns None)."""
    key = active_signing_key(db, org_id)
    if key is not None and key.private_pem:
        return sign_hex(key.private_pem.encode("utf-8"), message_hex), key.key_id
    return sign_message_hex(message_hex), None


def public_pem_for_key(db: Session, key_id: uuid.UUID) -> bytes:
    """The public key for a given signing-key-id (used to verify that event)."""
    key = db.get(OrgSigningKey, key_id)
    if key is None:
        msg = f"signing key not found: {key_id}"
        raise LookupError(msg)
    return key.public_pem.encode("utf-8")
