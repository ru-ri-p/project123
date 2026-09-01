"""Org-scoped approval database access."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import Approval


def list_approvals(
    db: Session,
    org_id: str,
    *,
    status: str | None = None,
    trace_id: uuid.UUID | None = None,
    limit: int = 50,
) -> list[Approval]:
    query = db.query(Approval).filter(Approval.org_id == org_id)
    if status is not None:
        query = query.filter(Approval.status == status)
    if trace_id is not None:
        query = query.filter(Approval.trace_id == trace_id)
    return query.order_by(Approval.created_at.desc()).limit(limit).all()


def list_approvals_for_trace(
    db: Session,
    org_id: str,
    trace_id: uuid.UUID,
    *,
    limit: int = 20,
) -> list[Approval]:
    return list_approvals(db, org_id, trace_id=trace_id, limit=limit)


def get_approval(db: Session, org_id: str, approval_id: uuid.UUID) -> Approval | None:
    return (
        db.query(Approval)
        .filter(Approval.org_id == org_id, Approval.id == approval_id)
        .one_or_none()
    )


def create_approval(
    db: Session,
    *,
    org_id: str,
    trace_id: uuid.UUID,
    event_id: uuid.UUID | None = None,
) -> Approval:
    approval = Approval(
        org_id=org_id,
        trace_id=trace_id,
        event_id=event_id,
        status="pending",
    )
    db.add(approval)
    db.flush()
    return approval


def resolve_approval(
    db: Session,
    approval: Approval,
    *,
    status: str,
    approver_id: str,
    approver_kind: str = "asserted",
    comment: str | None,
    resolved_at: datetime,
) -> Approval:
    approval.status = status
    approval.approver_id = approver_id
    approval.approver_kind = approver_kind
    approval.comment = comment
    approval.resolved_at = resolved_at
    db.flush()
    return approval
