"""Load signing public key for verification and evidence bundles."""

from __future__ import annotations

from functools import lru_cache

from app.crypto.signing_provider import SigningKeyError, get_signing_provider


@lru_cache
def load_public_pem() -> bytes:
    try:
        return get_signing_provider().public_key_pem()
    except SigningKeyError:
        from app.config import get_settings

        settings = get_settings()
        return settings.signing_public_key_path.read_bytes()
