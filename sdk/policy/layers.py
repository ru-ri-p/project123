"""Deterministic detection layers (SDK-local)."""

from __future__ import annotations

from sdk.policy.tiers import max_tier
from sdk.policy.types import FeatureVector, LayerResult


def run_deterministic_layers(features: FeatureVector) -> tuple[LayerResult, ...]:
    results: list[LayerResult] = []

    if features.has_pii:
        results.append(
            LayerResult(
                layer_id="pii",
                tier="orange",
                confidence=1.0,
                reasons=(f"PII detected: {', '.join(features.pii_labels)}",),
            )
        )

    if features.citation_count < 1:
        results.append(
            LayerResult(
                layer_id="citations",
                tier="yellow",
                confidence=1.0,
                reasons=("No citations provided for factual content",),
            )
        )

    if features.prohibited_phrases:
        results.append(
            LayerResult(
                layer_id="prohibited_phrases",
                tier="orange",
                confidence=1.0,
                reasons=(
                    "Prohibited marketing phrases: " + ", ".join(features.prohibited_phrases),
                ),
            )
        )

    if features.cross_border and not features.lawful_basis_present:
        results.append(
            LayerResult(
                layer_id="cross_border",
                tier="red",
                confidence=1.0,
                reasons=("Cross-border transfer without documented lawful basis",),
            )
        )

    if features.amount_aed is not None and features.amount_aed >= 100_000:
        results.append(
            LayerResult(
                layer_id="high_value",
                tier="orange",
                confidence=1.0,
                reasons=(f"High-value amount_aed={features.amount_aed}",),
            )
        )

    return tuple(results)


def layer_floor_tier(layers: tuple[LayerResult, ...]) -> str:
    tier = "green"
    for layer in layers:
        tier = max_tier(tier, layer.tier)  # type: ignore[arg-type]
    return tier
