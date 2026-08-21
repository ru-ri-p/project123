"""JSON policy evaluator — OPA/Rego-ready contract (swap backend in Phase 3+)."""

from __future__ import annotations

from typing import Any

from app.domain.policy_contract import (
    FeatureVector,
    LayerResult,
    PolicyDecision,
    PolicyInput,
    PolicyOutput,
    RiskTier,
)
from app.services.policy.layers import layer_floor_tier, run_deterministic_layers
from app.services.policy.rules import PolicyEngineError, rule_matches
from app.services.policy.tiers import TIERS, max_tier

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


def evaluate_policy_input(policy_input: PolicyInput, rules_doc: dict[str, Any]) -> PolicyOutput:
    """Primary evaluation entry — used by precheck; OPA adapter will share this contract."""
    layers = run_deterministic_layers(policy_input.features)
    floor = layer_floor_tier(layers)

    rule_hit = _first_matching_rule(
        action=policy_input.action,
        payload=policy_input.payload,
        features=policy_input.features,
        rules_doc=rules_doc,
    )

    if rule_hit is not None:
        tier = max_tier(floor, rule_hit["tier"])
        reasons = (rule_hit["reason"],)
        rule_id = rule_hit["rule_id"]
        regulatory_refs = rule_hit["regulatory_refs"]
        decision = rule_hit["decision"]
        allowed = _decision_allowed(tier, decision, fail_mode=policy_input.fail_mode)
    else:
        tier = floor
        rule_id = None
        regulatory_refs = ()
        # No rule of the CUSTOMER'S matched — only Attest's built-in structural
        # layers raised the tier. Layers are ADVISORY: they raise risk and flag,
        # but they must never deny and never gate on approval, because "only
        # your own policy can block" is the promise the whole product makes.
        # (Caught live: a cross-border output was blocked by the built-in layer
        # for an org whose own policy said nothing about cross-border.) A
        # customer who wants these structural risks to block writes the rule
        # themselves — the starter policy shows how.
        decision = "flag" if _default_decision(tier) == "deny" else _default_decision(tier)
        reasons = _layer_reasons(layers) if layers else ("No policy rule matched",)
        allowed = True
    mitigations = MITIGATIONS_BY_TIER.get(tier, ())

    return PolicyOutput(
        tier=tier,
        decision=decision,
        allowed=allowed,
        reasons=reasons,
        rule_id=rule_id,
        regulatory_refs=regulatory_refs,
        risk_score=TIER_SCORE[tier],
        layer_results=layers,
        mitigations=mitigations,
    )


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
        msg = "policy.rules must be a list"
        raise PolicyEngineError(msg)

    sorted_rules = sorted(
        enumerate(raw_rules),
        key=lambda item: int(item[1].get("priority", 0)) if isinstance(item[1], dict) else 0,
        reverse=True,
    )

    for index, rule in sorted_rules:
        if not isinstance(rule, dict):
            msg = f"policy.rules[{index}] must be an object"
            raise PolicyEngineError(msg)
        rule_tier = rule.get("tier", "yellow")
        if rule_tier not in TIERS:
            msg = f"invalid tier in rule {rule.get('id', index)}"
            raise PolicyEngineError(msg)

        if rule_matches(action, payload, features, rule):
            decision = rule.get("decision", _default_decision(rule_tier))
            if decision not in ("allow", "deny", "flag"):
                decision = _default_decision(rule_tier)
            reason = str(rule.get("reason") or f"Rule matched: {rule.get('id', index)}")
            reg_ref = rule.get("regulatory_ref")
            refs = (str(reg_ref),) if reg_ref else ()
            return {
                "tier": rule_tier,  # type: ignore[typeddict-item]
                "decision": decision,
                "reason": reason,
                "rule_id": str(rule.get("id", f"rule_{index}")),
                "regulatory_refs": refs,
            }
    return None


def _default_decision(tier: RiskTier) -> PolicyDecision:
    if tier == "red":
        return "deny"
    if tier == "yellow":
        return "flag"
    return "allow"


def _decision_allowed(tier: RiskTier, decision: PolicyDecision, *, fail_mode: str) -> bool:
    """Only reached when a rule the CUSTOMER wrote matched (layer-only outcomes
    are always allowed — advisory). red + flag deliberately gates: it is the
    human-approval workflow, "pause for a person, then resume"."""
    if decision == "deny":
        return False
    if decision == "allow":
        return True
    # flag
    if tier == "red":
        return fail_mode == "allow_with_flag"
    return True


def _layer_reasons(layers: tuple[LayerResult, ...]) -> tuple[str, ...]:
    reasons: list[str] = []
    for layer in layers:
        reasons.extend(layer.reasons)
    return tuple(reasons) if reasons else ("Layer detection only",)
