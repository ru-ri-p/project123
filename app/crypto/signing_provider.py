"""Signing backends — local PEM (dev) or UAE-region KMS (production)."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings


class SigningKeyError(RuntimeError):
    """Raised when signing is requested but keys/KMS are unavailable."""


class SigningProvider(ABC):
    """Sign event/batch digests; expose public key for verification and bundles."""

    @property
    @abstractmethod
    def backend(self) -> str:
        """Short id: local | kms."""

    @abstractmethod
    def sign_hex(self, message_hex: str) -> str:
        """Sign a 32-byte digest (hex); return hex signature."""

    @abstractmethod
    def public_key_pem(self) -> bytes:
        """PEM-encoded Ed25519 public key."""

    def metadata(self) -> dict[str, Any]:
        """Non-secret metadata for health checks and evidence manifests."""
        pem = self.public_key_pem()
        fingerprint = hashlib.sha256(pem).hexdigest()
        return {
            "backend": self.backend,
            "public_key_fingerprint": fingerprint,
        }


class LocalPemSigningProvider(SigningProvider):
    """Development signing from PEM files on disk (instructions Phase 1–3)."""

    def __init__(self, settings: Settings) -> None:
        self._private_path = settings.signing_private_key_path
        self._public_path = settings.signing_public_key_path

    @property
    def backend(self) -> str:
        return "local"

    def _load_private(self) -> bytes:
        if not self._private_path.is_file():
            msg = f"signing private key not found: {self._private_path}"
            raise SigningKeyError(msg)
        return self._private_path.read_bytes()

    def sign_hex(self, message_hex: str) -> str:
        from app.crypto.signing import sign_hex

        return sign_hex(self._load_private(), message_hex)

    def public_key_pem(self) -> bytes:
        if not self._public_path.is_file():
            msg = f"signing public key not found: {self._public_path}"
            raise SigningKeyError(msg)
        return self._public_path.read_bytes()

    def metadata(self) -> dict[str, Any]:
        base = super().metadata()
        base["private_key_path"] = str(self._private_path)
        base["public_key_path"] = str(self._public_path)
        return base


class AwsKmsSigningProvider(SigningProvider):
    """Production signing via AWS KMS Ed25519 key in UAE region (me-central-1).

    Private key never leaves KMS. Requires boto3 and IAM kms:Sign + kms:GetPublicKey.
    """

    def __init__(
        self,
        *,
        key_id: str,
        region: str,
        public_key_pem_path: Path | None = None,
        client: Any | None = None,
    ) -> None:
        self._key_id = key_id
        self._region = region
        self._public_key_pem_path = public_key_pem_path
        self._client = client
        self._cached_public_pem: bytes | None = None

    @property
    def backend(self) -> str:
        return "kms"

    def _kms_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            msg = "KMS signing requires boto3 — pip install -r requirements-kms.txt"
            raise SigningKeyError(msg) from exc
        return boto3.client("kms", region_name=self._region)

    def sign_hex(self, message_hex: str) -> str:
        client = self._kms_client()
        try:
            response = client.sign(
                KeyId=self._key_id,
                Message=bytes.fromhex(message_hex),
                MessageType="RAW",
                SigningAlgorithm="ED25519",
            )
        except Exception as exc:
            msg = f"KMS Sign failed for key {self._key_id}: {exc}"
            raise SigningKeyError(msg) from exc
        signature: bytes = response["Signature"]
        return signature.hex()

    def public_key_pem(self) -> bytes:
        if self._cached_public_pem is not None:
            return self._cached_public_pem
        if self._public_key_pem_path is not None and self._public_key_pem_path.is_file():
            self._cached_public_pem = self._public_key_pem_path.read_bytes()
            return self._cached_public_pem
        client = self._kms_client()
        try:
            response = client.get_public_key(KeyId=self._key_id)
        except Exception as exc:
            msg = f"KMS GetPublicKey failed for key {self._key_id}: {exc}"
            raise SigningKeyError(msg) from exc
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        key = serialization.load_der_public_key(response["PublicKey"])
        pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        self._cached_public_pem = pem
        return pem

    def metadata(self) -> dict[str, Any]:
        base = super().metadata()
        base["kms_key_id"] = self._key_id
        base["kms_region"] = self._region
        return base


@lru_cache
def get_signing_provider() -> SigningProvider:
    settings = get_settings()
    if settings.signing_backend == "kms":
        if not settings.kms_key_id:
            msg = "ATTEST_SIGNING_BACKEND=kms requires KMS_KEY_ID"
            raise SigningKeyError(msg)
        return AwsKmsSigningProvider(
            key_id=settings.kms_key_id,
            region=settings.kms_region,
            public_key_pem_path=settings.kms_public_key_pem_path,
        )
    return LocalPemSigningProvider(settings)


def sign_message_hex(message_hex: str) -> str:
    """Sign using the configured provider (local PEM or KMS)."""
    return get_signing_provider().sign_hex(message_hex)
