"""Canonical JSON serialization and SHA-256 hashing.

Rules (must match on write path AND verify path — see instructions.txt §4):
  json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    """Convert a dict to deterministic UTF-8 bytes for hashing."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(obj: dict[str, Any]) -> str:
    """SHA-256 fingerprint of a dict's canonical form."""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()
