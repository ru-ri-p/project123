"""Approval API routes (dashboard scaffold — Phase 3 wires precheck)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
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
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> ApprovalResolveOut:
    try:
        approval_uuid = uuid.UUID(approval_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid approval_id") from exc

    try:
        result = resolve_approval(
            db,
            org_id=org.id,
            approval_id=approval_uuid,
            status=body.status,
            approver_id=body.approver_id,
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
