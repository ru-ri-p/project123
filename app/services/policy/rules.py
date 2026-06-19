"""Rule matching against extracted features."""

from __future__ import annotations

from typing import Any

from app.domain.policy_contract import FeatureVector


class PolicyEngineError(ValueError):
    """Invalid policy document."""


def rule_matches(
    action: str,
    payload: dict[str, Any],
    features: FeatureVector,
    rule: dict[str, Any],
) -> bool:
    match = rule.get("match")
    if not isinstance(match, dict):
        return False

    if "action" in match:
        actions = match["action"]
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(actions, list) and action in actions:
            return True

    if match.get("has_pii") is True and features.has_pii:
        return True

    feature_key = match.get("feature")
    if feature_key == "citation_count" and "lt" in match:
        if features.citation_count < int(match["lt"]):
            return True
    if feature_key == "cross_border" and match.get("without_lawful_basis") is True:
        if features.cross_border and not features.lawful_basis_present:
            return True
    if feature_key == "prohibited_phrases" and match.get("any") is True:
        if features.prohibited_phrases:
            return True
    if feature_key == "classifier":
        hint = payload.get("_classifier_tier")
        if hint and match.get("equals") == hint:
            return True

    key = match.get("payload_key")
    if isinstance(key, str):
        value = payload.get(key)
        if "equals" in match and value == match["equals"]:
            return True
        if "gte" in match and isinstance(value, (int, float)) and value >= match["gte"]:
            return True
        if "lt" in match:
            if value is None:
                return True
            if isinstance(value, (int, float)) and value < match["lt"]:
                return True

    contains = match.get("payload_contains")
    if isinstance(contains, str) and _payload_contains(payload, contains):
        return True

    return False


def _payload_contains(payload: dict[str, Any], needle: str) -> bool:
    needle_lower = needle.lower()

    def walk(value: Any) -> bool:
        if isinstance(value, str) and needle_lower in value.lower():
            return True
        if isinstance(value, dict):
            return any(walk(v) for v in value.values())
        if isinstance(value, list):
            return any(walk(v) for v in value)
        return False

    return walk(payload)
