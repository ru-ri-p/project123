"""Appendix A reference policy pack — institutions customise (instructions §5, roadmap)."""

from __future__ import annotations

from typing import Any

DEFAULT_POLICY_RULES: dict[str, Any] = {
    "schema_version": 1,
    "engine": "json",
    "rules": [
        {
            "id": "wire_transfer",
            "priority": 1000,
            "tier": "red",
            "decision": "deny",
            "regulatory_ref": "CBUAE human oversight / high-risk payments",
            "match": {"action": ["wire_transfer"]},
            "reason": "High-risk financial action requires human approval",
        },
        {
            "id": "execute_trade",
            "priority": 990,
            "tier": "red",
            "decision": "deny",
            "regulatory_ref": "CBUAE human oversight / suitability",
            "match": {"action": ["execute_trade"]},
            "reason": "Trade execution requires human approval",
        },
        {
            "id": "cross_border_no_basis",
            "priority": 980,
            "tier": "red",
            "decision": "deny",
            "regulatory_ref": "PDPL cross-border transfer rules",
            "match": {"feature": "cross_border", "without_lawful_basis": True},
            "reason": "Cross-border personal data transfer without lawful basis",
        },
        {
            "id": "individualised_financial_advice",
            "priority": 970,
            "tier": "red",
            "decision": "deny",
            "regulatory_ref": "CBUAE consumer protection / suitability",
            "match": {"feature": "classifier", "equals": "individualised_advice"},
            "reason": "Individualised financial advice requires human review",
        },
        {
            "id": "discriminatory_lending_language",
            "priority": 960,
            "tier": "red",
            "decision": "deny",
            "regulatory_ref": "CBUAE fairness / non-discrimination",
            "match": {"feature": "classifier", "equals": "discriminatory_lending"},
            "reason": "Potential discriminatory lending or pricing language",
        },
        {
            "id": "pii_in_output",
            "priority": 800,
            "tier": "orange",
            "decision": "flag",
            "regulatory_ref": "PDPL data minimisation",
            "match": {"has_pii": True},
            "reason": "PII detected in request payload",
        },
        {
            "id": "guaranteed_return_claim",
            "priority": 750,
            "tier": "orange",
            "decision": "flag",
            "regulatory_ref": "CBUAE consumer protection",
            "match": {"feature": "prohibited_phrases", "any": True},
            "reason": "Absolute or guaranteed-return language detected",
        },
        {
            "id": "uncited_factual_claim",
            "priority": 700,
            "tier": "yellow",
            "decision": "flag",
            "regulatory_ref": "CBUAE transparency / explainability",
            "match": {"feature": "citation_count", "lt": 1},
            "reason": "Factual output without citations",
        },
        {
            "id": "high_value_transfer",
            "priority": 650,
            "tier": "orange",
            "decision": "flag",
            "regulatory_ref": "CBUAE operational risk controls",
            "match": {"payload_key": "amount_aed", "gte": 100000},
            "reason": "High-value transaction threshold exceeded",
        },
    ],
}
