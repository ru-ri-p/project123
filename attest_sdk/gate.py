"""The gate result — what `AttestClient.gate()` hands back."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

COMPLIANT = "compliant"
FLAGGED = "flagged"
BLOCKED = "blocked"
UNEVALUATED = "unevaluated"
ERROR = "error"
MISCONFIGURED = "misconfigured"


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
    # recorded — Attest has it, signed and chained.
    # buffered — Attest was unreachable; it is queued locally, signed by this
    #            device, and will be grafted in on recovery.
    # offline  — the verdict was computed locally against cached rules, so it is
    #            provisional until the server re-evaluates it.
    recorded: bool = True
    buffered: bool = False
    offline: bool = False
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
        if self.status == MISCONFIGURED:
            return f"attest: setup incomplete — {self.reasons[0] if self.reasons else self.error}"
        if self.status == ERROR:
            return f"attest: not recorded ({self.error})"
        where = "buffered offline" if self.buffered else "recorded"
        if self.status == UNEVALUATED:
            return f"attest: {where}, not evaluated (trace {self.trace_id})"
        cited = ", ".join(
            f"{f.get('jurisdiction', '?')}:{f.get('rule_id', '?')}" for f in self.findings
        )
        tail = f" [{cited}]" if cited else ""
        provisional = " (provisional, offline)" if self.offline else ""
        return f"attest: {self.status}{provisional} · {where} (tier {self.tier}){tail}"

    @classmethod
    def from_offline(cls, verdict: dict[str, Any], trace_id: str) -> GateResult:
        """A verdict reached locally while Attest was unreachable, durably queued."""
        return cls(
            status=verdict["status"],
            allowed=bool(verdict.get("allowed", True)),
            trace_id=trace_id,
            tier=verdict.get("tier"),
            reasons=list(verdict.get("reasons") or []),
            findings=list(verdict.get("findings") or []),
            jurisdictions=list(verdict.get("jurisdictions") or []),
            policy_version=verdict.get("policy_version"),
            recorded=False,
            buffered=True,
            offline=True,
        )

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
    def misconfigured(cls, detail: dict[str, Any], trace_id: str = "") -> GateResult:
        """Setup is incomplete. Deliberately NOT buffered: the event could never
        be replayed, and the real problem would hide behind a fake outage."""
        return cls(
            status=MISCONFIGURED,
            allowed=True,
            trace_id=trace_id,
            reasons=[str(detail.get("message", "configuration required"))],
            recorded=False,
            buffered=False,
            error=str(detail.get("code", "misconfigured")),
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
