"""HTTP route handlers for event ingestion."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.schemas import EventIn, EventOut
from app.services.access import TraceAccessDeniedError
from app.services.events import EventSequenceError, InvalidEventTypeError, record_event
from app.services.onboarding import require_onboarded

router = APIRouter(prefix="/v1")


@router.post("/event", response_model=EventOut)
def post_event(
    body: EventIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> EventOut:
    require_onboarded(db, org)
    try:
        trace_uuid = uuid.UUID(body.trace_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid trace_id") from exc

    try:
        result = record_event(
            db,
            org_id=org.id,
            trace_id=trace_uuid,
            seq=body.seq,
            event_type=body.type,
            payload=body.payload,
            policy_version=body.policy_version,
        )
        db.commit()
    except EventSequenceError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except TraceAccessDeniedError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except InvalidEventTypeError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="signing key unavailable") from exc

    return result
