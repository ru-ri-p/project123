"""Encrypted payload storage with per-record keys (crypto-shredding — instructions §5)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from app.db.models import Payload, PayloadKey


class PayloadShreddedError(LookupError):
    """Raised when payload content was crypto-shredded and is unrecoverable."""


def _encrypt_content(content: dict[str, Any]) -> tuple[str, str]:
    key = Fernet.generate_key()
    blob = Fernet(key).encrypt(json.dumps(content, ensure_ascii=False).encode("utf-8"))
    return base64.b64encode(blob).decode("ascii"), base64.b64encode(key).decode("ascii")


def _decrypt_content(encrypted_blob_b64: str, key_b64: str) -> dict[str, Any]:
    key = base64.b64decode(key_b64.encode("ascii"))
    blob = base64.b64decode(encrypted_blob_b64.encode("ascii"))
    try:
        plaintext = Fernet(key).decrypt(blob)
    except InvalidToken as exc:
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

    encrypted_blob, key_b64 = _encrypt_content(content)
    db.add(
        Payload(
            org_id=org_id,
            payload_hash=payload_hash,
            encrypted_blob=encrypted_blob,
            pii_labels=pii_labels,
        )
    )
    db.add(
        PayloadKey(
            org_id=org_id,
            payload_hash=payload_hash,
            key_b64=key_b64,
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

    key_row = (
        db.query(PayloadKey)
        .filter(PayloadKey.org_id == org_id, PayloadKey.payload_hash == payload_hash)
        .one_or_none()
    )
    if key_row is None:
        return None

    try:
        return _decrypt_content(payload.encrypted_blob, key_row.key_b64)
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
