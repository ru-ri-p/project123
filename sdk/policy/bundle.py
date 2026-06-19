"""Signed policy bundle holder for local evaluation."""

from __future__ import annotations

from typing import Any

from sdk.policy.defaults import DEFAULT_POLICY_RULES
from sdk.policy.evaluator import evaluate_local
from sdk.policy.types import LocalEvaluation


class PolicyBundle:
    """In-memory policy document — load from server or use bundled defaults."""

    def __init__(
        self,
        rules_doc: dict[str, Any],
        *,
        version: str = "unknown",
        fail_mode: str = "deny_on_error",
    ) -> None:
        self.rules_doc = rules_doc
        self.version = version
        self.fail_mode = fail_mode

    def evaluate(self, action: str, payload: dict[str, Any]) -> LocalEvaluation:
        return evaluate_local(
            action=action,
            payload=payload,
            rules_doc=self.rules_doc,
            fail_mode=self.fail_mode,
        )

    @classmethod
    def from_api_response(
        cls,
        body: dict[str, Any],
        *,
        fail_mode: str = "deny_on_error",
    ) -> PolicyBundle:
        rules = body.get("rules")
        if not isinstance(rules, dict):
            rules = DEFAULT_POLICY_RULES
        version = str(body.get("version", "unknown"))
        return cls(rules, version=version, fail_mode=fail_mode)

    @classmethod
    def default(cls, *, fail_mode: str = "deny_on_error") -> PolicyBundle:
        return cls(DEFAULT_POLICY_RULES, version="bundled", fail_mode=fail_mode)
