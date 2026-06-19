"""Approval resolution — scaffold for Phase 3 enforcement."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.repositories import approvals as approval_repo
from app.services.envelope import now_utc_iso
from app.services.events import record_event


class ApprovalNotFoundError(LookupError):
    """Approval id not found for this org."""


class ApprovalAlreadyResolvedError(ValueError):
    """Approval is no longer pending."""


APPROVAL_STATUSES = frozenset({"approved", "denied"})


def resolve_approval(
    db: Session,
    *,
    org_id: str,
    approval_id: uuid.UUID,
    status: str,
    approver_id: str,
    comment: str | None,
) -> dict[str, str | int]:
    if status not in APPROVAL_STATUSES:
        msg = f"invalid status: {status}"
        raise ValueError(msg)

    approval = approval_repo.get_approval(db, org_id, approval_id)
    if approval is None:
        raise ApprovalNotFoundError(f"approval not found: {approval_id}")
    if approval.status != "pending":
        raise ApprovalAlreadyResolvedError(f"approval already {approval.status}")

    resolved_at = datetime.fromisoformat(now_utc_iso()).replace(tzinfo=UTC)
    approval_repo.resolve_approval(
        db,
        approval,
        status=status,
        approver_id=approver_id,
        comment=comment,
        resolved_at=resolved_at,
    )

    from app.repositories import events as event_repo

    events = event_repo.events_for_trace(db, org_id, approval.trace_id)
    next_seq = events[-1].seq + 1 if events else 1

    event_result = record_event(
        db,
        org_id=org_id,
        trace_id=approval.trace_id,
        seq=next_seq,
        event_type="approval_action",
        payload={
            "approval_id": str(approval_id),
            "status": status,
            "approver_id": approver_id,
            "comment": comment or "",
        },
        policy_version=None,
    )

    from app.services.workflow import resume_allowed_for_approval_status, workflow_gate

    gate = workflow_gate(db, org_id=org_id, trace_id=approval.trace_id)
    resume_allowed = resume_allowed_for_approval_status(status)

    return {
        "approval_id": str(approval_id),
        "trace_id": str(approval.trace_id),
        "status": status,
        "event_seq": event_result.seq,
        "event_hash": event_result.hash,
        "resume_allowed": resume_allowed,
        "workflow_status": gate["workflow_status"],
    }
