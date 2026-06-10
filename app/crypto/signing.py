# TODO(KMS): production signing must move to a managed HSM/KMS — key never on disk
"""Ed25519 signing for Attest.

The hash proves the data is unchanged; the signature proves WHO vouched for it.
The secret private key creates a signature; the shareable public key verifies it;
nobody can forge a signature without the private key.

DEV ONLY: keys live in keys/ on disk. A key in a file is copyable by anyone who
reads the disk, and whoever holds it can forge records. This is acceptable for
the MVP on synthetic data only. Production moves signing into a cloud KMS/HSM in
the UAE region, where the private key never leaves the hardware and the app calls
a "sign this" API instead.
"""

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

KEYS = Path("keys")


def generate_dev_keys() -> None:
    """DEV ONLY. Production signing moves to a cloud KMS/HSM; key never on disk."""
    KEYS.mkdir(exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    (KEYS / "ed25519_private.pem").write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (KEYS / "ed25519_public.pem").write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def sign_hex(message_hex: str) -> str:
    priv = serialization.load_pem_private_key(
        (KEYS / "ed25519_private.pem").read_bytes(), password=None
    )
    return priv.sign(bytes.fromhex(message_hex)).hex()


def verify_hex(
    message_hex: str, signature_hex: str, public_pem: bytes | None = None
) -> bool:
    # A verifier must fail CLOSED: catch every error and return False rather than
    # raise. Bad input (malformed hex, wrong signature, corrupt key) is a failed
    # verification, never a crash.
    pub_bytes = public_pem or (KEYS / "ed25519_public.pem").read_bytes()
    pub = serialization.load_pem_public_key(pub_bytes)
    try:
        pub.verify(bytes.fromhex(signature_hex), bytes.fromhex(message_hex))
        return True
    except Exception:
        return False
