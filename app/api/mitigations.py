"""Auto-mitigation routes (Phase 3 Week 10)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.schemas import MitigateIn, MitigateOut
from app.services.access import TraceAccessDeniedError, TraceNotFoundError
from app.services.events import EventSequenceError
from app.services.mitigation import record_mitigation

router = APIRouter(prefix="/v1", tags=["mitigations"])


@router.post("/mitigate", response_model=MitigateOut)
def mitigate(
    body: MitigateIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> MitigateOut:
    try:
        trace_uuid = uuid.UUID(body.trace_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid trace_id") from exc

    try:
        result = record_mitigation(
            db,
            org_id=org.id,
            trace_id=trace_uuid,
            seq=body.seq,
            mitigation_ids=body.mitigation_ids,
            source_payload=body.source_payload,
            policy_decision_seq=body.policy_decision_seq,
            policy_version=body.policy_version,
        )
        db.commit()
    except TraceAccessDeniedError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TraceNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EventSequenceError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="signing key unavailable") from exc

    return MitigateOut(**result)
