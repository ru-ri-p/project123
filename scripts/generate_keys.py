#!/usr/bin/env python3
"""Generate Ed25519 key pair for local development.

Production: use UAE-region KMS/HSM (Phase 4). Never commit keys/ to git.
"""

from __future__ import annotations

import pathlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
KEYS_DIR = ROOT / "keys"


def generate_keys() -> tuple[pathlib.Path, pathlib.Path]:
    KEYS_DIR.mkdir(exist_ok=True)
    private_path = KEYS_DIR / "ed25519_private.pem"
    public_path = KEYS_DIR / "ed25519_public.pem"

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

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
    return private_path, public_path


def main() -> None:
    private_path, public_path = generate_keys()
    print(f"Keys written to {KEYS_DIR}/")
    print(f"  private: {private_path.name}")
    print(f"  public:  {public_path.name}")


if __name__ == "__main__":
    main()
