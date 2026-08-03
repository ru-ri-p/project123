"""The gate result — what `AttestClient.gate()` hands back."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

COMPLIANT = "compliant"
FLAGGED = "flagged"
BLOCKED = "blocked"
UNEVALUATED = "unevaluated"
ERROR = "error"


@dataclass(frozen=True)
class GateResult:
    """The verdict on one AI output.

    Attest reports; your code decides. Nothing here changes what your
    application does — read `blocked` / `flagged` and act as you see fit.
    """

    status: str
    allowed: bool
    trace_id: str
    output_hash: str = ""
    signature: str = ""
    tier: str | None = None
    reasons: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    jurisdictions: list[str] = field(default_factory=list)
    policy_version: str | None = None
    output_seq: int | None = None
    decision_seq: int | None = None
    approval_id: str | None = None
    recorded: bool = True
    error: str | None = None

    # --- convenience -------------------------------------------------------

    @property
    def compliant(self) -> bool:
        """True only when it was evaluated and nothing was raised."""
        return self.status == COMPLIANT

    @property
    def flagged(self) -> bool:
        return self.status == FLAGGED

    @property
    def blocked(self) -> bool:
        """Your OWN policy denied this output. Jurisdiction packs never block."""
        return self.status == BLOCKED

    @property
    def evaluated(self) -> bool:
        return self.status in (COMPLIANT, FLAGGED, BLOCKED)

    def summary(self) -> str:
        """One line for your logs."""
        if self.status == ERROR:
            return f"attest: not recorded ({self.error})"
        if self.status == UNEVALUATED:
            return f"attest: recorded, not evaluated (trace {self.trace_id})"
        cited = ", ".join(
            f"{f.get('jurisdiction', '?')}:{f.get('rule_id', '?')}" for f in self.findings
        )
        tail = f" [{cited}]" if cited else ""
        return f"attest: {self.status} (tier {self.tier}, trace {self.trace_id}){tail}"

    @classmethod
    def from_response(cls, body: dict[str, Any]) -> GateResult:
        return cls(
            status=body.get("status", UNEVALUATED),
            allowed=bool(body.get("allowed", True)),
            trace_id=body.get("trace_id", ""),
            output_hash=body.get("output_hash", ""),
            signature=body.get("signature", ""),
            tier=body.get("tier"),
            reasons=list(body.get("reasons") or []),
            findings=list(body.get("findings") or []),
            jurisdictions=list(body.get("jurisdictions") or []),
            policy_version=body.get("policy_version"),
            output_seq=body.get("output_seq"),
            decision_seq=body.get("decision_seq"),
            approval_id=body.get("approval_id"),
            recorded=True,
        )

    @classmethod
    def unreachable(cls, exc: Exception, trace_id: str = "") -> GateResult:
        """Attest could not be reached. The caller's application keeps working;
        `recorded` is False so the gap is visible rather than silent."""
        return cls(
            status=ERROR,
            allowed=True,
            trace_id=trace_id,
            reasons=[f"attest unreachable: {exc}"],
            recorded=False,
            error=str(exc),
        )
