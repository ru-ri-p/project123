"""Stable policy I/O contract — swap JSON evaluator for OPA/Rego without breaking SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

RiskTier = Literal["green", "yellow", "orange", "red"]
PolicyDecision = Literal["allow", "deny", "flag"]


@dataclass(frozen=True)
class FeatureVector:
    """Deterministic features extracted before rule evaluation."""

    action: str
    citation_count: int
    has_pii: bool
    pii_labels: tuple[str, ...]
    cross_border: bool
    lawful_basis_present: bool
    prohibited_phrases: tuple[str, ...]
    amount_aed: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "citation_count": self.citation_count,
            "has_pii": self.has_pii,
            "pii_labels": list(self.pii_labels),
            "cross_border": self.cross_border,
            "lawful_basis_present": self.lawful_basis_present,
            "prohibited_phrases": list(self.prohibited_phrases),
            "amount_aed": self.amount_aed,
        }


@dataclass(frozen=True)
class LayerResult:
    """One detection layer — tier bump + reason (never a naked yes/no)."""

    layer_id: str
    tier: RiskTier
    confidence: float
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer_id": self.layer_id,
            "tier": self.tier,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class PolicyInput:
    org_id: str
    action: str
    payload: dict[str, Any]
    fail_mode: str
    policy_version: str
    features: FeatureVector


@dataclass(frozen=True)
class PolicyOutput:
    """Evaluator result — same shape whether JSON or OPA backend."""

    tier: RiskTier
    decision: PolicyDecision
    allowed: bool
    reasons: tuple[str, ...]
    rule_id: str | None
    regulatory_refs: tuple[str, ...]
    risk_score: int
    layer_results: tuple[LayerResult, ...]
    mitigations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "decision": self.decision,
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "rule_id": self.rule_id,
            "regulatory_refs": list(self.regulatory_refs),
            "risk_score": self.risk_score,
            "layer_results": [layer.to_dict() for layer in self.layer_results],
            "mitigations": list(self.mitigations),
        }
