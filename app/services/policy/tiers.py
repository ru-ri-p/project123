"""Risk tier ordering — worst tier wins."""

from __future__ import annotations

from typing import Literal

RiskTier = Literal["green", "yellow", "orange", "red"]

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
