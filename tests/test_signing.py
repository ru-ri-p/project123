from __future__ import annotations

import pathlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.crypto.canonical import sha256_hex
from app.crypto.signing import sign_hex, verify_hex

ROOT = pathlib.Path(__file__).resolve().parents[1]
KEYS_DIR = ROOT / "keys"


@pytest.fixture(scope="module")
def key_pair() -> tuple[bytes, bytes]:
    private_path = KEYS_DIR / "ed25519_private.pem"
    public_path = KEYS_DIR / "ed25519_public.pem"
    if not private_path.exists():
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        KEYS_DIR.mkdir(exist_ok=True)
        private_path.write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        public_path.write_bytes(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return private_path.read_bytes(), public_path.read_bytes()


def test_sign_and_verify_sample_event(key_pair: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = key_pair
    event = {"trace_id": "t1", "seq": 1, "type": "model_completion"}
    event_hash = sha256_hex(event)
    sig = sign_hex(private_pem, event_hash)
    assert verify_hex(public_pem, event_hash, sig) is True


def test_tampered_data_fails_verification(key_pair: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = key_pair
    event = {"trace_id": "t1", "seq": 1, "type": "model_completion"}
    event_hash = sha256_hex(event)
    sig = sign_hex(private_pem, event_hash)

    tampered_hash = sha256_hex({**event, "seq": 99})
    assert verify_hex(public_pem, tampered_hash, sig) is False
