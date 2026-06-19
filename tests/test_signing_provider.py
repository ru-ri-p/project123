"""Signing provider tests — local PEM and KMS with injected client."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.config import Settings, get_settings
from app.crypto.canonical import sha256_hex
from app.crypto.signing import sign_hex, verify_hex
from app.crypto.signing_provider import (
    AwsKmsSigningProvider,
    LocalPemSigningProvider,
    get_signing_provider,
    sign_message_hex,
)

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / "keys" / "ed25519_private.pem"
PUBLIC = ROOT / "keys" / "ed25519_public.pem"


@pytest.fixture
def private_pem() -> bytes:
    if not PRIVATE.is_file():
        pytest.skip("run python scripts/generate_keys.py")
    return PRIVATE.read_bytes()


class _FakeKmsClient:
    """Simulates KMS Sign/GetPublicKey using local PEM (CI without AWS)."""

    def __init__(self, private_pem: bytes, public_pem: bytes) -> None:
        self._private_pem = private_pem
        self._public_der = serialization.load_pem_public_key(public_pem).public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, **kwargs: object) -> dict[str, bytes]:
        message = kwargs["Message"]
        assert isinstance(message, bytes)
        sig_hex = sign_hex(self._private_pem, message.hex())
        return {"Signature": bytes.fromhex(sig_hex)}

    def get_public_key(self, **kwargs: object) -> dict[str, bytes]:
        return {"PublicKey": self._public_der}


def test_local_provider_sign_and_verify(private_pem: bytes) -> None:
    settings = Settings(
        signing_backend="local",
        signing_private_key_path=PRIVATE,
        signing_public_key_path=PUBLIC,
    )
    provider = LocalPemSigningProvider(settings)
    digest = sha256_hex({"test": "kms-path"})
    sig = provider.sign_hex(digest)
    assert verify_hex(provider.public_key_pem(), digest, sig)


def test_kms_provider_with_fake_client(private_pem: bytes) -> None:
    public_pem = PUBLIC.read_bytes()
    client = _FakeKmsClient(private_pem, public_pem)
    provider = AwsKmsSigningProvider(
        key_id="alias/test",
        region="me-central-1",
        client=client,
    )
    digest = sha256_hex({"event": 1})
    sig = provider.sign_hex(digest)
    assert provider.backend == "kms"
    meta = provider.metadata()
    assert meta["kms_key_id"] == "alias/test"
    assert meta["kms_region"] == "me-central-1"
    assert verify_hex(provider.public_key_pem(), digest, sig)


def test_sign_message_hex_uses_cached_provider(private_pem: bytes) -> None:
    get_signing_provider.cache_clear()
    digest = sha256_hex({"roundtrip": True})
    sig = sign_message_hex(digest)
    settings = get_settings()
    public = settings.signing_public_key_path.read_bytes()
    assert verify_hex(public, digest, sig)


def test_generate_keys_produces_ed25519() -> None:
    if not PRIVATE.is_file():
        pytest.skip("keys not generated")
    key = serialization.load_pem_private_key(PRIVATE.read_bytes(), password=None)
    assert isinstance(key, Ed25519PrivateKey)
