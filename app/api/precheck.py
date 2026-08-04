"""Policy precheck — enforcement entry point (Phase 3)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.schemas import PrecheckIn, PrecheckOut
from app.services.access import TraceAccessDeniedError
from app.services.events import EventSequenceError
from app.services.onboarding import require_onboarded
from app.services.precheck import NoActivePolicyError, run_precheck

# Told to the customer verbatim when they have no policy. A bare "no active
# policy" is a dead end; this says what to do about it.
NO_POLICY_HELP = (
    "No active policy for this organisation. Attest enforces YOUR policy — publish "
    "one before prechecking actions: open the Compliance screen in your console and "
    "use 'Create starter policy', or PUT /v1/policies/internal."
)

router = APIRouter(prefix="/v1", tags=["precheck"])


@router.post("/precheck", response_model=PrecheckOut)
def precheck(
    body: PrecheckIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> PrecheckOut:
    require_onboarded(db, org)
    try:
        trace_uuid = uuid.UUID(body.trace_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid trace_id") from exc

    try:
        result = run_precheck(
            db,
            org=org,
            trace_id=trace_uuid,
            seq=body.seq,
            action=body.action,
            payload=body.payload,
            policy_version=body.policy_version,
        )
        db.commit()
    except NoActivePolicyError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=NO_POLICY_HELP) from exc
    except TraceAccessDeniedError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except EventSequenceError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except OSError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="signing key unavailable") from exc

    return PrecheckOut(**result)
