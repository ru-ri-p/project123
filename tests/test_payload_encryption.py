"""AES-256-GCM payload encryption: round-trips, and fails closed when the key,
ciphertext, or bound AAD context is wrong (CLAUDE.md rule 6)."""

from __future__ import annotations

import base64

import pytest

from app.services.payload_store import (
    PayloadShreddedError,
    _aad,
    _decrypt_content,
    _encrypt_content,
)

ENC_ALG = "aes-256-gcm-v1"
CONTENT = {"prompt": "Summarise Q1", "output": "…", "note": "تم الاعتماد"}


def test_round_trip_recovers_content() -> None:
    aad = _aad(enc_alg=ENC_ALG, org_id="org_demo", payload_hash="h1")
    blob, key = _encrypt_content(CONTENT, aad=aad)
    assert _decrypt_content(blob, key, aad=aad) == CONTENT


def test_key_is_256_bit() -> None:
    aad = _aad(enc_alg=ENC_ALG, org_id="org_demo", payload_hash="h1")
    _blob, key_b64 = _encrypt_content(CONTENT, aad=aad)
    assert len(base64.b64decode(key_b64)) == 32  # 256-bit AES key


def test_wrong_key_fails_closed() -> None:
    aad = _aad(enc_alg=ENC_ALG, org_id="org_demo", payload_hash="h1")
    blob, _key = _encrypt_content(CONTENT, aad=aad)
    _b2, other_key = _encrypt_content(CONTENT, aad=aad)
    with pytest.raises(PayloadShreddedError):
        _decrypt_content(blob, other_key, aad=aad)


def test_tampered_ciphertext_fails_closed() -> None:
    aad = _aad(enc_alg=ENC_ALG, org_id="org_demo", payload_hash="h1")
    blob, key = _encrypt_content(CONTENT, aad=aad)
    raw = bytearray(base64.b64decode(blob))
    raw[-1] ^= 0x01  # flip a bit in the tag/ciphertext
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(PayloadShreddedError):
        _decrypt_content(tampered, key, aad=aad)


def test_aad_mismatch_fails_closed() -> None:
    # A blob sealed for one record cannot be decrypted under another record's
    # context — GCM authenticates the AAD.
    aad = _aad(enc_alg=ENC_ALG, org_id="org_demo", payload_hash="h1")
    blob, key = _encrypt_content(CONTENT, aad=aad)
    other_aad = _aad(enc_alg=ENC_ALG, org_id="org_other", payload_hash="h1")
    with pytest.raises(PayloadShreddedError):
        _decrypt_content(blob, key, aad=other_aad)
