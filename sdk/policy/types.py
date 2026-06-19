"""SDK-local policy types (mirrors server contract — no app imports)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

RiskTier = Literal["green", "yellow", "orange", "red"]
PolicyDecision = Literal["allow", "deny", "flag"]


@dataclass(frozen=True)
class FeatureVector:
    action: str
    citation_count: int
    has_pii: bool
    pii_labels: tuple[str, ...]
    cross_border: bool
    lawful_basis_present: bool
    prohibited_phrases: tuple[str, ...]
    amount_aed: float | None


@dataclass(frozen=True)
class LayerResult:
    layer_id: str
    tier: RiskTier
    confidence: float
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class LocalEvaluation:
    tier: RiskTier
    decision: PolicyDecision
    allowed: bool
    reasons: tuple[str, ...]
    rule_id: str | None
    risk_score: int
    mitigations: tuple[str, ...] = field(default_factory=tuple)
    local_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "decision": self.decision,
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "rule_id": self.rule_id,
            "risk_score": self.risk_score,
            "mitigations": list(self.mitigations),
            "local_only": self.local_only,
        }
