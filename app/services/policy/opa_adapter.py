"""OPA/Rego backend placeholder — same PolicyInput/PolicyOutput contract as JSON evaluator."""

from __future__ import annotations

from typing import Any

from app.domain.policy_contract import PolicyInput, PolicyOutput
from app.services.policy.evaluator import evaluate_policy_input


class OpaNotConfiguredError(RuntimeError):
    """OPA endpoint not configured — use JSON evaluator."""


def evaluate_with_opa(policy_input: PolicyInput, rules_doc: dict[str, Any]) -> PolicyOutput:
    """Future: POST input JSON to OPA /v1/data/attest/decision.

    Until OPA is wired, fall back to the JSON evaluator so SDK contract stays stable.
    """
    _ = rules_doc
    if False:  # pragma: no cover — replace when OPA sidecar is deployed
        raise OpaNotConfiguredError("OPA URL not set")
    return evaluate_policy_input(policy_input, rules_doc)
