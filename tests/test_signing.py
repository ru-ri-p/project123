"""Ed25519 sign/verify roundtrip passes; a tampered hash fails verification."""

from app.crypto.canonical import sha256_hex
from app.crypto.signing import generate_dev_keys, sign_hex, verify_hex


def _ensure_keys():
    # Generate dev keys once if they don't already exist on disk.
    from app.crypto.signing import KEYS

    if not (KEYS / "ed25519_private.pem").exists():
        generate_dev_keys()


def test_sign_verify_roundtrip_passes():
    _ensure_keys()
    h = sha256_hex({"event": "model_completion", "ok": True})
    sig = sign_hex(h)
    assert verify_hex(h, sig) is True


def test_tampered_hash_fails_verification():
    _ensure_keys()
    h = sha256_hex({"event": "model_completion", "ok": True})
    sig = sign_hex(h)
    # Flip the message: a different hash must not verify against the same signature.
    tampered = sha256_hex({"event": "model_completion", "ok": False})
    assert verify_hex(tampered, sig) is False


def test_verifier_never_raises_on_garbage_input():
    # Fail closed: malformed input returns False, it does not throw.
    _ensure_keys()
    assert verify_hex("not-hex", "also-not-hex") is False
