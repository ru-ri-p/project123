"""SDK local policy evaluation (no network)."""

from __future__ import annotations

from attest_sdk.policy.bundle import PolicyBundle
from attest_sdk.policy.defaults import DEFAULT_POLICY_RULES
from attest_sdk.policy.evaluator import evaluate_local, needs_server_escalation


def test_local_green() -> None:
    result = evaluate_local(
        action="model_completion",
        payload={"prompt": "Summary", "citations": 2},
        rules_doc=DEFAULT_POLICY_RULES,
    )
    assert result.tier == "green"
    assert result.allowed is True
    assert not needs_server_escalation(result)


def test_local_wire_transfer_escalates() -> None:
    result = evaluate_local(
        action="wire_transfer",
        payload={"amount_aed": 1000},
        rules_doc=DEFAULT_POLICY_RULES,
    )
    assert result.tier == "red"
    assert needs_server_escalation(result)


def test_bundle_evaluate() -> None:
    bundle = PolicyBundle.default()
    result = bundle.evaluate("model_completion", {"citations": 0})
    assert result.tier == "yellow"
