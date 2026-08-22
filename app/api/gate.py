"""The gate — one call to check and log an AI output.

Replaces the precheck-then-record dance (and its sequence-number foot-gun) with
a single request. Attest returns a verdict; the caller decides what to do with
it. Nothing here changes the caller's behaviour.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.schemas import GateIn, GateOut
from app.services.access import TraceAccessDeniedError
from app.services.events import EventSequenceError, InvalidEventTypeError
from app.services.gate import RemediationRefError, run_gate
from app.services.onboarding import require_onboarded

router = APIRouter(prefix="/v1", tags=["gate"])


@router.post("/gate", response_model=GateOut)
def gate(
    body: GateIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> GateOut:
    require_onboarded(db, org)

    trace_id: uuid.UUID | None = None
    if body.trace_id:
        try:
            trace_id = uuid.UUID(body.trace_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid trace_id") from exc

    try:
        result = run_gate(
            db,
            org=org,
            action=body.action,
            output=body.output,
            trace_id=trace_id,
            policy_version=body.policy_version,
            remediates=body.remediates,
        )
        db.commit()
    except RemediationRefError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except TraceAccessDeniedError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except InvalidEventTypeError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except EventSequenceError as exc:
        # Sequences are assigned server-side, so this means concurrent writes to
        # the same trace raced. Say so plainly rather than leaking an internal.
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="concurrent writes to this trace collided; retry the call",
        ) from exc

    return GateOut(**result)
