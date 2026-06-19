"""Policy engine public exports."""

from __future__ import annotations

from typing import Any

from app.domain.policy_contract import PolicyInput, PolicyOutput
from app.services.policy.evaluator import evaluate_policy_input
from app.services.policy.rules import PolicyEngineError

__all__ = [
    "PolicyEngineError",
    "evaluate_policy_input",
    "evaluate_policy",
]


def evaluate_policy(
    *,
    action: str,
    payload: dict[str, Any],
    rules_doc: dict[str, Any],
) -> tuple[str, list[str]]:
    from app.services.policy.features import extract_features

    features = extract_features(action, payload)
    policy_input = PolicyInput(
        org_id="",
        action=action,
        payload=payload,
        fail_mode="deny_on_error",
        policy_version="",
        features=features,
    )
    output: PolicyOutput = evaluate_policy_input(policy_input, rules_doc)
    return output.tier, list(output.reasons)
