"""Org-side wrapping crypto for the consent ceremony (RSA-3072-OAEP-SHA256).

This is the CUSTOMER'S half of the "locked box only the customer can open" model.
It runs entirely in the org's environment and holds the org PRIVATE key, which
never reaches Attest. With it the org can:

  - generate a wrapping keypair (keep the private key, hand Attest the public one),
  - re-wrap ("regrant") a single record's content key from itself to a one-time
    Attest access key, when it approves a scoped request.

It must stay byte-compatible with the server's app/crypto/org_encryption.py — the
wrapping suite id and OAEP parameters are duplicated here on purpose, because the
SDK is a standalone package that cannot import the server. Keep the two in sync;
they are the same primitive on two sides of the wire.

Requires the `cryptography` package (install `attest-sdk[consent]`).
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Must equal app.crypto.org_encryption.DEFAULT_WRAP_ALGORITHM on the server.
WRAP_ALG_RSA_OAEP_SHA256 = "rsa3072-oaep-sha256"
DEFAULT_WRAP_ALGORITHM = WRAP_ALG_RSA_OAEP_SHA256

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


class KeyWrappingError(ValueError):
    """Raised when a key cannot be wrapped/unwrapped (bad key, wrong key, corrupt)."""


def generate_wrapping_keypair() -> tuple[bytes, bytes]:
    """Create an org wrapping keypair. Returns (private_pem, public_pem).

    Keep `private_pem` secret and in the org's custody (ideally a KMS/HSM in
    production). Hand Attest only `public_pem`.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def wrap_key(public_pem: bytes, data_key: bytes) -> bytes:
    """Lock a content key (DEK) to a public key (one-way for a public-key holder)."""
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, rsa.RSAPublicKey):
        msg = "expected an RSA public wrapping key"
        raise KeyWrappingError(msg)
    return key.encrypt(data_key, _OAEP)


def unwrap_key(private_pem: bytes, wrapped_key: bytes) -> bytes:
    """Recover a content key with the private key. Fails closed on a wrong/corrupt key."""
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        msg = "expected an RSA private wrapping key"
        raise KeyWrappingError(msg)
    try:
        return key.decrypt(wrapped_key, _OAEP)
    except ValueError as exc:
        msg = "could not unwrap content key"
        raise KeyWrappingError(msg) from exc


def regrant_key(
    org_private_pem: bytes, wrapped_for_org: bytes, grantee_public_pem: bytes
) -> bytes:
    """Release ONE record: unwrap its DEK with the org key, re-wrap to the grantee.

    This is the only place the org private key is used during an approval, and it
    releases exactly one record's key — never the org master key, never more
    records than the org chose to re-grant.
    """
    data_key = unwrap_key(org_private_pem, wrapped_for_org)
    return wrap_key(grantee_public_pem, data_key)
