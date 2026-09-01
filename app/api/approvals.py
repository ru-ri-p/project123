"""Approval API routes (dashboard scaffold — Phase 3 wires precheck)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import Actor, get_actor, get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.repositories import approvals as approval_repo
from app.schemas import ApprovalOut, ApprovalResolveIn, ApprovalResolveOut
from app.services.approvals import (
    ApprovalAlreadyResolvedError,
    ApprovalNotFoundError,
    resolve_approval,
)

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])


def _to_out(approval: object) -> ApprovalOut:
    from app.db.models import Approval

    assert isinstance(approval, Approval)
    return ApprovalOut(
        id=str(approval.id),
        trace_id=str(approval.trace_id),
        event_id=str(approval.event_id) if approval.event_id else None,
        status=approval.status,
        approver_id=approval.approver_id,
        approver_kind=approval.approver_kind,
        comment=approval.comment,
        created_at=approval.created_at.isoformat(),
        resolved_at=approval.resolved_at.isoformat() if approval.resolved_at else None,
    )


@router.get("", response_model=list[ApprovalOut])
def list_approvals(
    status: str | None = Query(default=None),
    trace_id: str | None = Query(default=None),
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> list[ApprovalOut]:
    trace_uuid: uuid.UUID | None = None
    if trace_id is not None:
        try:
            trace_uuid = uuid.UUID(trace_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid trace_id") from exc
    rows = approval_repo.list_approvals(db, org.id, status=status, trace_id=trace_uuid)
    return [_to_out(row) for row in rows]


@router.get("/{approval_id}", response_model=ApprovalOut)
def get_approval(
    approval_id: str,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> ApprovalOut:
    try:
        approval_uuid = uuid.UUID(approval_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid approval_id") from exc

    approval = approval_repo.get_approval(db, org.id, approval_uuid)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")
    return _to_out(approval)


@router.post("/{approval_id}/resolve", response_model=ApprovalResolveOut)
def resolve(
    approval_id: str,
    body: ApprovalResolveIn,
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> ApprovalResolveOut:
    """Resolve as a signed-in person (identity PROVEN, recorded from the
    session — anything the body claims is ignored) or over the org machine
    key (legacy/SDK path: approver_id required, recorded as asserted)."""
    try:
        approval_uuid = uuid.UUID(approval_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid approval_id") from exc

    approver_user_id = approver_display = None
    if actor.user is not None:
        if actor.user.role not in ("admin", "officer"):
            raise HTTPException(
                status_code=403, detail="viewer role cannot resolve approvals"
            )
        approver_id, approver_kind = actor.user.email, "authenticated"
        approver_user_id = str(actor.user.id)
        approver_display = actor.user.display_name
    else:
        if not body.approver_id:
            raise HTTPException(
                status_code=422,
                detail="approver_id required when resolving with an API key",
            )
        approver_id, approver_kind = body.approver_id, "asserted"

    try:
        result = resolve_approval(
            db,
            org_id=actor.org.id,
            approval_id=approval_uuid,
            status=body.status,
            approver_id=approver_id,
            approver_kind=approver_kind,
            approver_user_id=approver_user_id,
            approver_display=approver_display,
            comment=body.comment,
        )
        db.commit()
    except ApprovalNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ApprovalAlreadyResolvedError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="signing key unavailable") from exc

    return ApprovalResolveOut(**result)
