"""Per-event cryptographic algorithm identifiers (crypto-agility).

Every sealed event records the id of the algorithm suite used to hash and sign
it. The id lives INSIDE the signed envelope (see app/services/envelope.py), so
it cannot be altered without breaking the event hash and signature. This lets
us migrate primitives later — e.g. to a post-quantum signature — while still
verifying every event ever sealed under an older suite: the verifier dispatches
on the stored id (CLAUDE.md rule 6).

Suite id format: "<hash>-<signature>-v<n>". Bump the version (or add a new
constant) when a primitive changes; never silently redefine an existing id.
"""

from __future__ import annotations

# Current default suite: SHA-256 hashing + Ed25519 signatures (CLAUDE.md rule 6).
ALG_SHA256_ED25519_V1 = "sha256-ed25519-v1"

DEFAULT_ALGORITHM = ALG_SHA256_ED25519_V1

# Suites THIS build knows how to verify. An event whose alg is not in this set
# must fail verification closed — never raise, never silently pass.
SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({ALG_SHA256_ED25519_V1})


def is_supported(alg: str | None) -> bool:
    """Return True only for algorithm suites this build can verify (fail closed)."""
    return alg in SUPPORTED_ALGORITHMS
