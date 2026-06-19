"""PDPL erasure routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.schemas import ErasureIn, ErasureOut
from app.services.access import TraceAccessDeniedError, TraceNotFoundError
from app.services.erasure import (
    ErasureTargetError,
    PayloadAlreadyErasedError,
    erase_event_payload,
)

router = APIRouter(prefix="/v1")


@router.post("/erasure", response_model=ErasureOut)
def post_erasure(
    body: ErasureIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> ErasureOut:
    try:
        trace_uuid = uuid.UUID(body.trace_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid trace_id") from exc

    try:
        result = erase_event_payload(
            db,
            org_id=org.id,
            trace_id=trace_uuid,
            target_seq=body.target_seq,
            approver_id=body.approver_id,
            reason=body.reason,
        )
        db.commit()
    except TraceAccessDeniedError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TraceNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ErasureTargetError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PayloadAlreadyErasedError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except OSError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="signing key unavailable") from exc

    return ErasureOut(**result)
