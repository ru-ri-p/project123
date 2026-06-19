"""Trace replay and evidence export routes."""

from __future__ import annotations

import uuid
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.schemas import (
    EventReplayItem,
    EvidenceBundleOut,
    TraceReplayOut,
    TraceSummary,
    WorkflowGateOut,
)
from app.services.access import TraceAccessDeniedError, TraceNotFoundError
from app.services.evidence import build_evidence_bundle, bundle_to_zip
from app.services.replay import replay_trace
from app.services.trace_list import list_traces
from app.services.workflow import workflow_gate

router = APIRouter(prefix="/v1")


@router.get("/traces", response_model=list[TraceSummary])
def get_traces(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> list[TraceSummary]:
    rows = list_traces(db, org.id, limit=limit, offset=offset)
    return [TraceSummary(**row) for row in rows]


@router.get("/trace/{trace_id}/gate", response_model=WorkflowGateOut)
def trace_gate(
    trace_id: str,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> WorkflowGateOut:
    try:
        trace_uuid = uuid.UUID(trace_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid trace_id") from exc

    try:
        result = workflow_gate(db, org_id=org.id, trace_id=trace_uuid)
    except TraceAccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TraceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return WorkflowGateOut(**result)


@router.get("/trace/{trace_id}/replay", response_model=TraceReplayOut)
def replay(
    trace_id: str,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> TraceReplayOut:
    try:
        trace_uuid = uuid.UUID(trace_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid trace_id") from exc

    try:
        result = replay_trace(db, org_id=org.id, trace_id=trace_uuid)
    except TraceAccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TraceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return TraceReplayOut(
        trace_id=result.trace_id,
        all_verified=result.all_verified,
        events=[EventReplayItem(**asdict(item)) for item in result.events],
    )


@router.get("/evidence/{trace_id}/export", response_model=None)
def export_evidence(
    trace_id: str,
    format: str = Query(default="json", pattern="^(json|zip)$"),
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> Response | EvidenceBundleOut:
    try:
        trace_uuid = uuid.UUID(trace_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid trace_id") from exc

    try:
        bundle = build_evidence_bundle(db, org_id=org.id, trace_id=trace_uuid)
    except TraceAccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TraceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if format == "zip":
        payload = bundle_to_zip(bundle)
        filename = f"attest-evidence-{trace_id}.zip"
        return Response(
            content=payload,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return EvidenceBundleOut.model_validate(bundle)
