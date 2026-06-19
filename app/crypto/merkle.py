"""Merkle tree over event hashes — batch commitment for external anchoring."""

from __future__ import annotations

import hashlib


def _digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root(leaf_hexes: list[str]) -> str:
    """Combine leaf hashes into a single root hash."""
    if not leaf_hexes:
        return _digest(b"").hex()

    level = [bytes.fromhex(leaf) for leaf in leaf_hexes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_digest(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


def merkle_proof(leaf_hexes: list[str], index: int) -> list[str]:
    """Sibling hashes from leaf to root (for evidence-bundle verification in Week 4)."""
    if not leaf_hexes:
        return []
    if index < 0 or index >= len(leaf_hexes):
        msg = f"index {index} out of range for {len(leaf_hexes)} leaves"
        raise IndexError(msg)

    level = [bytes.fromhex(leaf) for leaf in leaf_hexes]
    idx = index
    proof: list[str] = []

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling_idx = idx - 1 if idx % 2 == 1 else idx + 1
        proof.append(level[sibling_idx].hex())
        idx //= 2
        level = [_digest(level[i] + level[i + 1]) for i in range(0, len(level), 2)]

    return proof


def verify_merkle_proof(leaf_hex: str, index: int, proof: list[str], root_hex: str) -> bool:
    """Return True if leaf + proof recompute to root_hex."""
    current = bytes.fromhex(leaf_hex)
    idx = index

    for sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        if idx % 2 == 1:
            current = _digest(sibling + current)
        else:
            current = _digest(current + sibling)
        idx //= 2

    return current.hex() == root_hex
