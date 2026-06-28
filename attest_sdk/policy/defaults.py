"""Bundled starter policy — sync with app/domain/default_policy.py."""

from __future__ import annotations

from typing import Any

# Subset sufficient for local eval; full pack loaded from GET /v1/policies/active when online.
DEFAULT_POLICY_RULES: dict[str, Any] = {
    "schema_version": 1,
    "engine": "json",
    "rules": [
        {
            "id": "wire_transfer",
            "priority": 1000,
            "tier": "red",
            "decision": "deny",
            "match": {"action": ["wire_transfer"]},
            "reason": "High-risk financial action requires human approval",
        },
        {
            "id": "cross_border_no_basis",
            "priority": 980,
            "tier": "red",
            "decision": "deny",
            "match": {"feature": "cross_border", "without_lawful_basis": True},
            "reason": "Cross-border transfer without lawful basis",
        },
        {
            "id": "pii_in_output",
            "priority": 800,
            "tier": "orange",
            "decision": "flag",
            "match": {"has_pii": True},
            "reason": "PII detected in request payload",
        },
        {
            "id": "uncited_factual_claim",
            "priority": 700,
            "tier": "yellow",
            "decision": "flag",
            "match": {"feature": "citation_count", "lt": 1},
            "reason": "Factual output without citations",
        },
    ],
}
