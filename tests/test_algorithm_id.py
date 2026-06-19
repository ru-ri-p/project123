"""Per-event algorithm id: present in the signed envelope, dispatched on at
verify time, and fail-closed for any suite this build does not implement
(CLAUDE.md rule 6 — crypto-agility for post-quantum migration)."""

from __future__ import annotations

from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.crypto.algorithms import DEFAULT_ALGORITHM, is_supported
from app.crypto.canonical import sha256_hex
from app.crypto.signing import sign_hex
from app.services.envelope import build_envelope
from app.services.verification import verify_single_event


def test_envelope_carries_algorithm_id() -> None:
    env = build_envelope(
        trace_id="trace-1",
        seq=1,
        event_type="model_completion",
        payload_hash="ph",
        prev_hash=None,
        policy_version=None,
        created_at="2026-01-01T00:00:00+00:00",
    )
    assert env["alg"] == DEFAULT_ALGORITHM


def test_is_supported_is_strict() -> None:
    assert is_supported(DEFAULT_ALGORITHM)
    assert not is_supported("rsa-md5-v0")
    assert not is_supported(None)


def _signed_event(alg: str) -> tuple[SimpleNamespace, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    env = build_envelope(
        trace_id="trace-1",
        seq=1,
        event_type="model_completion",
        payload_hash="ph",
        prev_hash=None,
        policy_version=None,
        created_at="2026-01-01T00:00:00+00:00",
        alg=alg,
    )
    event_hash = sha256_hex(env)
    signature = sign_hex(priv_pem, event_hash)
    event = SimpleNamespace(
        trace_id="trace-1",
        seq=1,
        type="model_completion",
        payload_hash="ph",
        prev_hash=None,
        policy_version=None,
        hash=event_hash,
        signature=signature,
        alg=alg,
        envelope=env,
    )
    return event, pub_pem


def test_supported_algorithm_verifies() -> None:
    event, pub_pem = _signed_event(DEFAULT_ALGORITHM)
    result = verify_single_event(event, public_pem=pub_pem, expected_prev_hash=None)
    assert result.verified is True


def test_unsupported_algorithm_fails_closed() -> None:
    # Correctly hashed AND correctly signed, but under a suite this build does
    # not implement. We must refuse it rather than honour an unknown primitive.
    event, pub_pem = _signed_event("rsa-md5-v0")
    result = verify_single_event(event, public_pem=pub_pem, expected_prev_hash=None)
    assert result.verified is False
    assert result.signature_ok is False
