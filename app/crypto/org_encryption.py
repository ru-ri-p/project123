"""Asymmetric envelope encryption — "a locked box only the customer can open".

The confidentiality model (Attest-hosted SaaS, customer-managed keys):

  - Each org has a WRAPPING KEYPAIR. Attest is given only the PUBLIC key; the
    PRIVATE key stays in the org's custody and never reaches Attest.
  - Content is encrypted with a random per-record data key (a "DEK"). Attest
    then WRAPS that DEK with the org's public key and stores the wrapped form.
    Holding only the public key, Attest can wrap (lock) but never unwrap (open),
    so stored content is dark to Attest.
  - To grant Attest a scoped view, the org (holding the private key) unwraps the
    DEKs for exactly the approved records and RE-WRAPS them to a one-time Attest
    access public key — a single-record key release, never the org master key.

This module is the crypto core of that scheme. It does NOT touch the database or
the request/approval workflow — those are later slices. Uses only `cryptography`
(RSA-OAEP), keeping the crypto surface small (instructions §4e).
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Content-key-wrapping suite id (stored per record for crypto-agility, like the
# event/content algorithm ids). Bump when the wrapping primitive changes.
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
    """Create an org wrapping keypair.

    Returns (private_pem, public_pem). The org keeps `private_pem`; Attest is
    given only `public_pem`. This runs in the ORG's environment in production
    (their KMS/HSM) — it is here so we can generate and test the pair.
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
    """Lock a content key (DEK) to a public key. Attest can do this; it is one-way
    for whoever holds only the public key."""
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, rsa.RSAPublicKey):
        msg = "expected an RSA public wrapping key"
        raise KeyWrappingError(msg)
    return key.encrypt(data_key, _OAEP)


def unwrap_key(private_pem: bytes, wrapped_key: bytes) -> bytes:
    """Recover a content key with the private key. Only the private-key holder
    (the org, or a grantee the org re-wrapped to) can do this. Fails closed."""
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        msg = "expected an RSA private wrapping key"
        raise KeyWrappingError(msg)
    try:
        return key.decrypt(wrapped_key, _OAEP)
    except ValueError as exc:  # wrong key / corrupt ciphertext
        msg = "could not unwrap content key"
        raise KeyWrappingError(msg) from exc


def regrant_key(org_private_pem: bytes, wrapped_for_org: bytes, grantee_public_pem: bytes) -> bytes:
    """The consent 'key release', for ONE record.

    Runs in the org's environment on approval: unwrap the record's DEK with the
    org private key, then re-wrap it to the grantee's (Attest's ephemeral access)
    public key. The grantee can then open exactly this record — and nothing else,
    because only the records the org chose to re-grant were released.
    """
    data_key = unwrap_key(org_private_pem, wrapped_for_org)
    return wrap_key(grantee_public_pem, data_key)
