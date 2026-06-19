"""Ed25519 signing and verification.

Production: configure ATTEST_SIGNING_BACKEND=kms (UAE region, me-central-1).
Development: local PEM files via LocalPemSigningProvider.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def load_private_key(private_pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        msg = "expected Ed25519 private key"
        raise TypeError(msg)
    return key


def load_public_key(public_pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, Ed25519PublicKey):
        msg = "expected Ed25519 public key"
        raise TypeError(msg)
    return key


def sign_hex(private_pem: bytes, message_hex: str) -> str:
    """Sign a hex-encoded message digest; return hex signature."""
    priv = load_private_key(private_pem)
    sig = priv.sign(bytes.fromhex(message_hex))
    return sig.hex()


def verify_hex(public_pem: bytes, message_hex: str, signature_hex: str) -> bool:
    """Return True if the signature is valid for the message."""
    pub = load_public_key(public_pem)
    try:
        pub.verify(bytes.fromhex(signature_hex), bytes.fromhex(message_hex))
    except InvalidSignature:
        return False
    return True
