"""Encrypted payload storage with per-record keys (crypto-shredding — instructions §5).

Content is encrypted with AES-256-GCM (CLAUDE.md rule 6): a fresh 256-bit key
per record, a random 96-bit nonce, and Additional Authenticated Data (AAD) that
binds the ciphertext to its own {enc_alg, org_id, payload_hash}. The AAD means a
blob cannot be silently moved onto a different record or relabelled — GCM's
integrity tag covers it. Erasure (crypto-shred) deletes the per-record key, after
which the ciphertext is unrecoverable while the signed event chain stays intact.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from app.crypto.algorithms import DEFAULT_CONTENT_ALGORITHM, is_supported_content
from app.crypto.canonical import canonical_bytes
from app.crypto.org_encryption import DEFAULT_WRAP_ALGORITHM, wrap_key
from app.db.models import Org, Payload, PayloadKey

_NONCE_BYTES = 12  # 96-bit nonce, the standard size for AES-GCM
_KEY_BITS = 256


class PayloadShreddedError(LookupError):
    """Raised when payload content was crypto-shredded or is otherwise unreadable."""


def _aad(*, enc_alg: str, org_id: str, payload_hash: str) -> bytes:
    """Authenticated context bound into the ciphertext (not encrypted, but tamper-evident).

    Reconstructable at decrypt time from stored fields, so it must be deterministic.
    """
    return canonical_bytes(
        {"alg": enc_alg, "org_id": org_id, "payload_hash": payload_hash}
    )


def _encrypt_content(content: dict[str, Any], *, aad: bytes) -> tuple[str, str]:
    key = AESGCM.generate_key(bit_length=_KEY_BITS)
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(
        nonce, json.dumps(content, ensure_ascii=False).encode("utf-8"), aad
    )
    blob = nonce + ciphertext  # tag is appended to ciphertext by AESGCM
    return base64.b64encode(blob).decode("ascii"), base64.b64encode(key).decode("ascii")


def _decrypt_content(encrypted_blob_b64: str, key_b64: str, *, aad: bytes) -> dict[str, Any]:
    key = base64.b64decode(key_b64.encode("ascii"))
    blob = base64.b64decode(encrypted_blob_b64.encode("ascii"))
    nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError) as exc:
        # Wrong/shredded key, tampered blob, mismatched AAD, or a malformed key
        # (e.g. a record written under a different scheme) — all unreadable.
        # Fail closed rather than raise out of the read path.
        msg = "payload decryption failed"
        raise PayloadShreddedError(msg) from exc
    data: dict[str, Any] = json.loads(plaintext.decode("utf-8"))
    return data


def store_encrypted_payload(
    db: Session,
    *,
    org_id: str,
    payload_hash: str,
    content: dict[str, Any],
    pii_labels: list[str],
) -> None:
    existing = (
        db.query(Payload)
        .filter(Payload.org_id == org_id, Payload.payload_hash == payload_hash)
        .one_or_none()
    )
    if existing is not None:
        return

    enc_alg = DEFAULT_CONTENT_ALGORITHM
    aad = _aad(enc_alg=enc_alg, org_id=org_id, payload_hash=payload_hash)
    encrypted_blob, key_b64 = _encrypt_content(content, aad=aad)

    # Customer-key mode: wrap the content key (DEK) to the org's public key so
    # Attest can store it but cannot open it (dark at rest). Default mode leaves
    # the DEK as-is, so existing orgs are unaffected.
    wrap_alg: str | None = None
    org = db.query(Org).filter(Org.id == org_id).one_or_none()
    if org is not None and org.confidentiality_mode == "customer_key" and org.wrapping_public_pem:
        raw_dek = base64.b64decode(key_b64.encode("ascii"))
        wrapped = wrap_key(org.wrapping_public_pem.encode("utf-8"), raw_dek)
        key_b64 = base64.b64encode(wrapped).decode("ascii")
        wrap_alg = DEFAULT_WRAP_ALGORITHM

    db.add(
        Payload(
            org_id=org_id,
            payload_hash=payload_hash,
            encrypted_blob=encrypted_blob,
            enc_alg=enc_alg,
            pii_labels=pii_labels,
        )
    )
    db.add(
        PayloadKey(
            org_id=org_id,
            payload_hash=payload_hash,
            key_b64=key_b64,
            wrap_alg=wrap_alg,
        )
    )
    db.flush()


def read_payload_content(db: Session, org_id: str, payload_hash: str) -> dict[str, Any] | None:
    payload = (
        db.query(Payload)
        .filter(Payload.org_id == org_id, Payload.payload_hash == payload_hash)
        .one_or_none()
    )
    if payload is None:
        return None
    if payload.erased_at is not None:
        return None
    if not is_supported_content(payload.enc_alg):
        # Unknown content-encryption suite — fail closed rather than guess.
        return None

    key_row = (
        db.query(PayloadKey)
        .filter(PayloadKey.org_id == org_id, PayloadKey.payload_hash == payload_hash)
        .one_or_none()
    )
    if key_row is None:
        return None
    if key_row.wrap_alg is not None:
        # The content key is wrapped to the org's key — Attest cannot open it.
        # Reading requires a consent-released key (a later slice), not this path.
        return None

    aad = _aad(enc_alg=payload.enc_alg, org_id=org_id, payload_hash=payload_hash)
    try:
        return _decrypt_content(payload.encrypted_blob, key_row.key_b64, aad=aad)
    except PayloadShreddedError:
        return None


def crypto_shred_payload(
    db: Session,
    *,
    org_id: str,
    payload_hash: str,
) -> bool:
    """Destroy the encryption key. Returns False if already shredded or missing."""
    key_row = (
        db.query(PayloadKey)
        .filter(PayloadKey.org_id == org_id, PayloadKey.payload_hash == payload_hash)
        .one_or_none()
    )
    if key_row is None:
        return False

    db.delete(key_row)
    payload = (
        db.query(Payload)
        .filter(Payload.org_id == org_id, Payload.payload_hash == payload_hash)
        .one_or_none()
    )
    if payload is not None and payload.erased_at is None:
        from app.services.envelope import now_utc_iso

        payload.erased_at = datetime.fromisoformat(now_utc_iso()).replace(tzinfo=UTC)
    db.flush()
    return True
