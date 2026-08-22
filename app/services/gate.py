"""The output gate — one call that evaluates, records, and returns a verdict.

Why this exists
===============
Integrating Attest used to mean: create a trace, call precheck with a sequence
number, inspect the result, then call record_event with the NEXT sequence number.
Four concepts and a foot-gun (reuse a seq and you get an out-of-order error) for
what a customer thinks of as one thing: "check and log this AI output".

`run_gate` collapses that into a single server-side operation:

  * the trace is created if not supplied (one output = one trace by default,
    or pass a trace to group several steps into one story);
  * sequence numbers are assigned HERE, so the customer never sees them;
  * the output is evaluated against the institution's own policy plus every
    jurisdiction pack that applies to it;
  * the decision is recorded as a signed policy_decision event, and the output
    itself as a second signed event chained to it;
  * a verdict comes back for the caller to act on.

Attest returns a verdict; it does not alter the caller's behaviour. Whether a
flagged output is withheld is the institution's decision, made in their code.

Provenance never fails for a configuration reason
=================================================
If the institution has not published a policy yet, the output is still recorded
(that is the core promise) and the verdict comes back as `unevaluated` with the
reason spelled out. Recording is the floor; evaluation is a layer on top. The
alternative — refusing to record because compliance is unconfigured — would lose
the very evidence the product exists to keep.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Org, PolicyDecisionSummary
from app.repositories import events as event_repo
from app.services.events import record_event
from app.services.precheck import NoActivePolicyError, run_precheck

# The verdict has ONE definition, in app/services/verdict.py — shared with the
# precheck pipeline so the sealed decision event and the API answer can never
# disagree. Re-exported here because this module is where callers look for it.
from app.services.verdict import (  # noqa: F401  (re-exports)
    FLAGGING_TIERS,
    STATUS_BLOCKED,
    STATUS_COMPLIANT,
    STATUS_FLAGGED,
    STATUS_UNEVALUATED,
    derive_status,
)


def _next_seq(db: Session, org_id: str, trace_id: uuid.UUID) -> int:
    last = event_repo.last_event_for_trace(db, org_id, trace_id)
    return 1 if last is None else last.seq + 1


class RemediationRefError(ValueError):
    """The remediates= reference does not name a flagged decision the caller owns."""


def _validate_remediates(
    db: Session, org_id: str, trace_id: uuid.UUID | None, remediates: int
) -> PolicyDecisionSummary:
    """A remediation must cure a real, non-compliant decision in the SAME trace.

    Same trace because the chain is the story: flagged and fixed must sit in one
    narrative an auditor reads top to bottom. Same org is enforced by the query —
    a caller can never 'remediate' another tenant's record into their own chain.
    """
    if trace_id is None:
        msg = (
            "remediates requires trace_id: the fix must be recorded in the same "
            "trace as the flagged decision it cures"
        )
        raise RemediationRefError(msg)
    summary = (
        db.query(PolicyDecisionSummary)
        .filter(
            PolicyDecisionSummary.org_id == org_id,
            PolicyDecisionSummary.trace_id == trace_id,
            PolicyDecisionSummary.seq == remediates,
        )
        .one_or_none()
    )
    if summary is None:
        msg = f"remediates={remediates} does not name a decision in this trace"
        raise RemediationRefError(msg)
    if summary.status not in (STATUS_FLAGGED, STATUS_BLOCKED):
        msg = (
            f"decision seq {remediates} is '{summary.status}', not flagged or "
            "blocked — there is nothing to remediate"
        )
        raise RemediationRefError(msg)
    return summary


def run_gate(
    db: Session,
    *,
    org: Org,
    action: str,
    output: dict[str, Any],
    trace_id: uuid.UUID | None = None,
    policy_version: str | None = None,
    remediates: int | None = None,
) -> dict[str, Any]:
    """Evaluate and record one AI output. Returns the verdict for the caller."""
    remediated_summary: PolicyDecisionSummary | None = None
    if remediates is not None:
        # Validated BEFORE anything is recorded: a bad reference must fail the
        # call, not leave a half-told story in the chain.
        remediated_summary = _validate_remediates(db, org.id, trace_id, remediates)

    trace_id = trace_id or uuid.uuid4()
    event_repo.get_or_create_trace(db, org.id, trace_id, policy_version)

    decision: dict[str, Any] | None = None
    unevaluated_reason: str | None = None
    try:
        decision = run_precheck(
            db,
            org=org,
            trace_id=trace_id,
            seq=_next_seq(db, org.id, trace_id),
            action=action,
            payload=output,
            policy_version=policy_version,
            remediation_of=remediates,
        )
    except NoActivePolicyError:
        # Record anyway — see module docstring. The verdict says plainly that no
        # evaluation happened, so this cannot be mistaken for a clean result.
        unevaluated_reason = (
            "No active policy for this organisation, so the output was recorded "
            "but not evaluated. Publish a policy from the Compliance screen to "
            "start checking outputs."
        )

    # The output itself, chained after the decision that judged it.
    event = record_event(
        db,
        org_id=org.id,
        trace_id=trace_id,
        seq=_next_seq(db, org.id, trace_id),
        event_type=action,
        payload=output,
        policy_version=(decision or {}).get("policy_version") or policy_version,
    )

    if decision is None:
        return {
            "trace_id": str(trace_id),
            "status": STATUS_UNEVALUATED,
            "allowed": True,
            "tier": None,
            "reasons": [unevaluated_reason],
            "findings": [],
            "jurisdictions": [],
            "policy_version": None,
            "decision_seq": None,
            "output_seq": event.seq,
            "output_hash": event.hash,
            "signature": event.signature,
            "approval_id": None,
            "suggested_fix": None,
            "remediation_of": remediates,
        }

    findings = decision.get("regulatory_findings", [])
    status = derive_status(
        allowed=decision["allowed"], tier=decision["tier"], findings=findings
    )

    # Stamp the verdict onto the decision index so the dashboards read the same
    # answer the caller got, rather than recomputing it and risking divergence.
    summary = (
        db.query(PolicyDecisionSummary)
        .filter(
            PolicyDecisionSummary.org_id == org.id,
            PolicyDecisionSummary.trace_id == trace_id,
            PolicyDecisionSummary.seq == decision["policy_decision_seq"],
        )
        .one_or_none()
    )
    if summary is not None:
        summary.status = status
        summary.output_seq = event.seq
        summary.output_hash = event.hash
        db.flush()

    # Close the loop: only a COMPLIANT re-gate cures the flagged decision. A
    # "fix" that still flags leaves the original open — an unremediated flag
    # must stay conspicuous, never be closed by the attempt alone.
    if remediated_summary is not None and status == STATUS_COMPLIANT:
        remediated_summary.remediated_by_seq = decision.get("policy_decision_seq")
        db.flush()

    return {
        "trace_id": str(trace_id),
        "status": status,
        "allowed": decision["allowed"],
        "tier": decision["tier"],
        "reasons": decision.get("reasons", []),
        "findings": findings,
        "jurisdictions": decision.get("jurisdictions", []),
        "policy_version": decision.get("policy_version"),
        "decision_seq": decision.get("policy_decision_seq"),
        "output_seq": event.seq,
        "output_hash": event.hash,
        "signature": event.signature,
        "approval_id": decision.get("approval_id"),
        # The full plan — content-bearing — exists only in this response and in
        # the caller's hands; the chain carries its hash. See remediation.py.
        "suggested_fix": decision.get("remediation_plan"),
        "remediation_of": remediates,
    }
