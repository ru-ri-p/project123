"""Risk tier ordering."""

from __future__ import annotations

from sdk.policy.types import RiskTier

TIER_RANK: dict[str, int] = {
    "green": 0,
    "yellow": 1,
    "orange": 2,
    "red": 3,
}

TIERS: frozenset[str] = frozenset(TIER_RANK)


def max_tier(current: RiskTier, candidate: RiskTier) -> RiskTier:
    if TIER_RANK[candidate] > TIER_RANK[current]:
        return candidate
    return current
