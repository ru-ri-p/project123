"""Unit tests for layered policy engine (no database)."""

from __future__ import annotations

from app.domain.default_policy import DEFAULT_POLICY_RULES
from app.domain.policy_contract import PolicyInput
from app.services.policy.evaluator import evaluate_policy_input
from app.services.policy.features import extract_features


def _evaluate(action: str, payload: dict) -> object:
    features = extract_features(action, payload)
    policy_input = PolicyInput(
        org_id="org_demo",
        action=action,
        payload=payload,
        fail_mode="deny_on_error",
        policy_version="v1",
        features=features,
    )
    return evaluate_policy_input(policy_input, DEFAULT_POLICY_RULES)


def test_wire_transfer_is_red() -> None:
    output = _evaluate("wire_transfer", {"amount_aed": 1000})
    assert output.tier == "red"
    assert output.decision == "deny"
    assert output.rule_id == "wire_transfer"
    assert output.allowed is False


def test_pii_rule_orange() -> None:
    output = _evaluate(
        "model_completion",
        {"prompt": "contact user@example.com", "citations": 2},
    )
    assert output.tier == "orange"
    assert output.rule_id == "pii_in_output"


def test_uncited_yellow() -> None:
    output = _evaluate("model_completion", {"prompt": "Market grew 5%", "citations": 0})
    assert output.tier == "yellow"
    assert output.rule_id == "uncited_factual_claim"


def test_cross_border_red() -> None:
    output = _evaluate(
        "model_completion",
        {"cross_border": True, "citations": 3},
    )
    assert output.tier == "red"
    assert output.rule_id == "cross_border_no_basis"


def test_prohibited_phrase_orange() -> None:
    output = _evaluate(
        "model_completion",
        {"output": "This investment is guaranteed risk-free", "citations": 2},
    )
    assert output.tier == "orange"
    assert output.rule_id in ("guaranteed_return_claim", "pii_in_output") or any(
        layer.layer_id == "prohibited_phrases" for layer in output.layer_results
    )


def test_layer_results_present() -> None:
    output = _evaluate("model_completion", {"prompt": "ali@example.com", "citations": 0})
    layer_ids = {layer.layer_id for layer in output.layer_results}
    assert "pii" in layer_ids
    assert "citations" in layer_ids
