#!/usr/bin/env python3
"""Day 5 demo: canonicalize a sample event, sign its hash, verify, and detect tampering."""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.crypto.canonical import sha256_hex
from app.crypto.signing import sign_hex, verify_hex

KEYS_DIR = ROOT / "keys"


def main() -> None:
    private_pem = (KEYS_DIR / "ed25519_private.pem").read_bytes()
    public_pem = (KEYS_DIR / "ed25519_public.pem").read_bytes()

    sample_event = {
        "trace_id": "00000000-0000-4000-8000-000000000001",
        "seq": 1,
        "type": "model_completion",
        "payload_hash": "abc123",
        "prev_hash": None,
        "policy_version": "v0",
        "created_at": "2026-05-31T12:00:00+00:00",
    }

    event_hash = sha256_hex(sample_event)
    signature = sign_hex(private_pem, event_hash)

    ok = verify_hex(public_pem, event_hash, signature)
    print(f"Original event verified: {ok}")
    assert ok is True

    tampered = {**sample_event, "seq": 2}
    tampered_hash = sha256_hex(tampered)
    tampered_ok = verify_hex(public_pem, tampered_hash, signature)
    print(f"Tampered event verified (should be False): {tampered_ok}")
    assert tampered_ok is False

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    if not (KEYS_DIR / "ed25519_private.pem").exists():
        print("Run: python scripts/generate_keys.py", file=sys.stderr)
        sys.exit(1)
    main()
