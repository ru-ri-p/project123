"""THE canonical form for Attest. Never duplicate this logic. Both the
write path and the verify path import THIS function. Versioned by the
evidence format; changing it breaks all prior verification.

A hash fingerprints bytes, not meaning. {"a":1,"b":2} and {"b":2,"a":1} mean
the same but are different bytes -> different fingerprints. We force data into
exactly one written form (keys sorted, no stray spaces, UTF-8) so that the same
meaning always produces the same bytes, and therefore the same fingerprint.
"""

import json
import hashlib


def canonical_bytes(obj: dict) -> bytes:
    # sort_keys=True       -> key order can never change the bytes
    # separators=(",",":") -> no incidental whitespace between elements
    # ensure_ascii=False   -> non-ASCII (e.g. Arabic) kept as real UTF-8, not \u escapes
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(obj: dict) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()
