"""The single definition of the verdict.

Lives in its own module so BOTH the gate (which tells the caller) and the
precheck pipeline (which seals the decision event and decides whether a
remediation plan is warranted) use the same words — without a circular import.
If two call sites computed "flagged" differently, the chain and the API could
disagree about what happened, which is the one failure an audit layer may
never have.
"""

from __future__ import annotations

from typing import Any

STATUS_COMPLIANT = "compliant"
STATUS_FLAGGED = "flagged"
STATUS_BLOCKED = "blocked"
STATUS_UNEVALUATED = "unevaluated"

FLAGGING_TIERS = frozenset({"orange", "red"})


def derive_status(*, allowed: bool, tier: str, findings: list[dict[str, Any]]) -> str:
    """blocked — the institution's OWN policy denied it (only their policy can).
    flagged  — permitted, but raised risk or drew a cited jurisdiction finding.
    compliant— permitted, low risk, nothing cited.
    """
    if not allowed:
        return STATUS_BLOCKED
    if tier in FLAGGING_TIERS or findings:
        return STATUS_FLAGGED
    return STATUS_COMPLIANT
