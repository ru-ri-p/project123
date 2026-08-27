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
    # Deterministic remediation plan when the verdict is flagged or blocked:
    # {revised_output, edits, requirements, unresolved, plan_hash}. Attest never
    # applies it — call apply_suggestion() and re-gate the result yourself, with
    # remediates=<this decision_seq>, so the fix lands in the sealed history.
    # None on compliant verdicts, and always None offline (the planner is
    # server-side in v1).
    suggested_fix: dict[str, Any] | None = None
    # Set when this result judged a revision submitted with remediates=.
    remediation_of: int | None = None
    # Present only when THIS CLIENT auto-applied a cure under the org's
    # auto_remediate configuration: {"applied": bool, "cure": "rewrite"|
    # "deterministic", "remediated_seq": <flagged decision>, "original_tier",
    # "original_status"}. The original flag stays sealed in the chain — this
    # annotation just tells your code the round trip already happened.
    auto_remediation: dict[str, Any] | None = None

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

    @property
    def rewrite(self) -> dict[str, Any] | None:
        """A model-drafted, gate-verified compliant rewrite, when one exists.

        Already checked by Attest's deterministic engine before being offered
        ("evaluation": "compliant"). If requires_human_confirmation is true the
        draft changed what the output IS (e.g. advice -> commentary) — have a
        person confirm that before applying. Apply with apply_rewrite() and
        re-gate with remediates=, like any fix; being model-drafted earns it
        nothing.
        """
        return (self.suggested_fix or {}).get("rewrite")

    def apply_rewrite(self) -> dict[str, Any]:
        """The verified rewrite's payload, for YOUR code to adopt explicitly."""
        rw = self.rewrite
        if not rw or not rw.get("output"):
            msg = "no verified rewrite on this verdict — check .rewrite first"
            raise ValueError(msg)
        return dict(rw["output"])

    @property
    def has_fix(self) -> bool:
        """A revised output is ready to apply and re-gate."""
        return bool(self.suggested_fix and self.suggested_fix.get("revised_output"))

    def apply_suggestion(self) -> dict[str, Any]:
        """The revised output, for YOUR code to adopt — explicitly, visibly.

        Attest never applies a fix for you; this returns a payload you then
        send back through gate(..., trace=<same trace>, remediates=
        <this result's decision_seq>). Raises if there is no revision — check
        has_fix first, and read suggested_fix["unresolved"] for what still
        needs a human.
        """
        if not self.has_fix:
            msg = (
                "no revised output to apply — this verdict has no mechanical "
                "fix; see suggested_fix['unresolved'] if present"
            )
            raise ValueError(msg)
        assert self.suggested_fix is not None  # narrowed by has_fix
        return dict(self.suggested_fix["revised_output"])

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
            suggested_fix=body.get("suggested_fix"),
            remediation_of=body.get("remediation_of"),
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
