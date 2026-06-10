"""An intact sealed event recomputes to the same hash and verifies; changing
ANY field makes the recomputed hash differ (tamper-evidence)."""

from app.crypto.canonical import sha256_hex
from app.crypto.signing import generate_dev_keys, verify_hex, KEYS
from app.crypto.envelope import build_envelope, seal, now_utc_iso


def _ensure_keys():
    if not (KEYS / "ed25519_private.pem").exists():
        generate_dev_keys()


def _sample_envelope():
    return build_envelope(
        trace_id="trace-abc12345",
        seq=1,
        etype="model_completion",
        payload_hash=sha256_hex({"output": "hello"}),
        prev_hash=None,
        created_at=now_utc_iso(),
    )


def test_intact_sealed_event_recomputes_and_verifies():
    _ensure_keys()
    env = _sample_envelope()
    h, sig = seal(env)
    # Recomputing the hash over the unchanged envelope yields the same value...
    assert sha256_hex(env) == h
    # ...and the signature over that hash verifies.
    assert verify_hex(h, sig) is True


def test_changing_any_field_changes_the_hash():
    _ensure_keys()
    env = _sample_envelope()
    h, sig = seal(env)
    # Simulate tampering: flip the event type. The recomputed hash must differ,
    # and the original signature must no longer verify against it.
    tampered = dict(env)
    tampered["type"] = "approval"
    assert sha256_hex(tampered) != h
    assert verify_hex(sha256_hex(tampered), sig) is False


def test_envelope_has_exactly_the_six_frozen_keys():
    env = _sample_envelope()
    assert set(env.keys()) == {
        "trace_id",
        "seq",
        "type",
        "payload_hash",
        "prev_hash",
        "created_at",
    }
