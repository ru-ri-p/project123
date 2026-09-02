"""The officer work queue — everything waiting on a human, in one read.

Three kinds of open work, three different jobs:
- PENDING APPROVALS: an orange/red decision routed to a person; the job is
  allow-or-deny the ACTION. Each is joined to the decision that raised it so
  the officer sees what they are deciding, not just an id.
- OPEN FLAGS: non-compliant outputs whose fix has not landed (no compliant
  re-gate closed them). The job is to fix the OUTPUT — which happens in the
  customer's application (apply the suggestion / rewrite and re-gate); the
  console shows the open loop so silence stays conspicuous.
- REWRITE CONFIRMATIONS: the subset of open flags carrying a gate-verified
  rewrite that changed what the output IS (reclassified) — a person must
  confirm the nature change before their application adopts it.

Everything here is index data (decision summaries and approval rows) — never
event payload content, so it works identically for customer-key orgs whose
content is dark to Attest.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Approval, PolicyDecisionSummary

OPEN_ITEMS_LIMIT = 50


def _decision_context(
    db: Session, org_id: str, trace_id: uuid.UUID
) -> PolicyDecisionSummary | None:
    """The latest decision in a trace — the thing the approval is about."""
    return (
        db.query(PolicyDecisionSummary)
        .filter(
            PolicyDecisionSummary.org_id == org_id,
            PolicyDecisionSummary.trace_id == trace_id,
        )
        .order_by(PolicyDecisionSummary.seq.desc())
        .first()
    )


def _flag_row(d: PolicyDecisionSummary) -> dict[str, Any]:
    return {
        "trace_id": str(d.trace_id),
        "seq": d.seq,
        "action": d.action,
        "tier": d.tier,
        "status": d.status,
        "created_at": d.created_at.isoformat(),
        "remediation": d.remediation,
        "findings_count": len(d.findings or []),
    }


def build_workqueue(db: Session, org_id: str) -> dict[str, Any]:
    approvals = (
        db.query(Approval)
        .filter(Approval.org_id == org_id, Approval.status == "pending")
        .order_by(Approval.created_at.asc())  # oldest first: FIFO fairness
        .limit(OPEN_ITEMS_LIMIT)
        .all()
    )
    approval_items: list[dict[str, Any]] = []
    for a in approvals:
        ctx = _decision_context(db, org_id, a.trace_id)
        approval_items.append(
            {
                "approval_id": str(a.id),
                "trace_id": str(a.trace_id),
                "created_at": a.created_at.isoformat(),
                "action": ctx.action if ctx else None,
                "tier": ctx.tier if ctx else None,
                "decision_status": ctx.status if ctx else None,
            }
        )

    flags = (
        db.query(PolicyDecisionSummary)
        .filter(
            PolicyDecisionSummary.org_id == org_id,
            PolicyDecisionSummary.status == "flagged",
            PolicyDecisionSummary.remediated_by_seq.is_(None),
            # A decision that itself judges a revision is an attempt, not new
            # work; the ORIGINAL flag stays in the queue until cured.
            PolicyDecisionSummary.remediation_of.is_(None),
        )
        .order_by(PolicyDecisionSummary.created_at.desc())
        .limit(OPEN_ITEMS_LIMIT)
        .all()
    )
    flag_items = [_flag_row(d) for d in flags]
    rewrite_items = [
        f
        for f in flag_items
        if (f["remediation"] or {}).get("has_rewrite")
        and (f["remediation"] or {}).get("rewrite_reclassified")
    ]

    return {
        "pending_approvals": approval_items,
        "open_flags": flag_items,
        "rewrite_confirmations": rewrite_items,
        "counts": {
            "approvals": len(approval_items),
            "open_flags": len(flag_items),
            "rewrite_confirmations": len(rewrite_items),
            "total": len(approval_items) + len(flag_items),
        },
    }
