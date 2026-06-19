"""Local JSON policy evaluator (SDK — mirrors server logic)."""

from __future__ import annotations

from typing import Any

from sdk.policy.features import extract_features
from sdk.policy.layers import layer_floor_tier, run_deterministic_layers
from sdk.policy.rules import PolicyEngineError, rule_matches
from sdk.policy.tiers import TIERS, max_tier
from sdk.policy.types import FeatureVector, LocalEvaluation, PolicyDecision, RiskTier

TIER_SCORE: dict[str, int] = {
    "green": 10,
    "yellow": 35,
    "orange": 65,
    "red": 90,
}

MITIGATIONS_BY_TIER: dict[str, tuple[str, ...]] = {
    "yellow": ("append_verify_disclaimer",),
    "orange": ("redact_pii_before_send", "append_verify_disclaimer", "require_human_review"),
}

ESCALATION_TIERS: frozenset[str] = frozenset({"orange", "red"})


def evaluate_local(
    *,
    action: str,
    payload: dict[str, Any],
    rules_doc: dict[str, Any],
    fail_mode: str = "deny_on_error",
) -> LocalEvaluation:
    features = extract_features(action, payload)
    layers = run_deterministic_layers(features)
    floor = layer_floor_tier(layers)

    rule_hit = _first_matching_rule(
        action=action,
        payload=payload,
        features=features,
        rules_doc=rules_doc,
    )

    if rule_hit is not None:
        tier = max_tier(floor, rule_hit["tier"])  # type: ignore[arg-type]
        reasons: tuple[str, ...] = (rule_hit["reason"],)
        rule_id = rule_hit["rule_id"]
        decision = rule_hit["decision"]
    else:
        tier = floor  # type: ignore[assignment]
        rule_id = None
        decision = _default_decision(tier)
        reasons = _layer_reasons(layers) if layers else ("No policy rule matched",)

    allowed = _decision_allowed(tier, decision, fail_mode=fail_mode)
    mitigations = MITIGATIONS_BY_TIER.get(tier, ())

    return LocalEvaluation(
        tier=tier,
        decision=decision,
        allowed=allowed,
        reasons=reasons,
        rule_id=rule_id,
        risk_score=TIER_SCORE[tier],
        mitigations=mitigations,
        local_only=True,
    )


def needs_server_escalation(evaluation: LocalEvaluation) -> bool:
    return evaluation.tier in ESCALATION_TIERS or not evaluation.allowed


def _first_matching_rule(
    *,
    action: str,
    payload: dict[str, Any],
    features: FeatureVector,
    rules_doc: dict[str, Any],
) -> dict[str, Any] | None:
    raw_rules = rules_doc.get("rules")
    if raw_rules is None:
        return None
    if not isinstance(raw_rules, list):
        raise PolicyEngineError("policy.rules must be a list")

    sorted_rules = sorted(
        enumerate(raw_rules),
        key=lambda item: int(item[1].get("priority", 0)) if isinstance(item[1], dict) else 0,
        reverse=True,
    )

    for index, rule in sorted_rules:
        if not isinstance(rule, dict):
            raise PolicyEngineError(f"policy.rules[{index}] must be an object")
        rule_tier = rule.get("tier", "yellow")
        if rule_tier not in TIERS:
            raise PolicyEngineError(f"invalid tier in rule {rule.get('id', index)}")

        if rule_matches(action, payload, features, rule):
            decision = rule.get("decision", _default_decision(rule_tier))
            if decision not in ("allow", "deny", "flag"):
                decision = _default_decision(rule_tier)
            reason = str(rule.get("reason") or f"Rule matched: {rule.get('id', index)}")
            return {
                "tier": rule_tier,
                "decision": decision,
                "reason": reason,
                "rule_id": str(rule.get("id", f"rule_{index}")),
            }
    return None


def _default_decision(tier: RiskTier) -> PolicyDecision:
    if tier == "red":
        return "deny"
    if tier == "yellow":
        return "flag"
    return "allow"


def _decision_allowed(tier: RiskTier, decision: PolicyDecision, *, fail_mode: str) -> bool:
    if decision == "deny":
        return False
    if decision == "allow":
        return True
    if tier == "red":
        return fail_mode == "allow_with_flag"
    return True


def _layer_reasons(layers: tuple) -> tuple[str, ...]:
    reasons: list[str] = []
    for layer in layers:
        reasons.extend(layer.reasons)
    return tuple(reasons) if reasons else ("Layer detection only",)
