"""Attest-ops admin API (x-admin-key) — what the admin dashboard drives.

Everything here requires the ADMIN_API_KEY (503 if unconfigured, 401 on
mismatch). Responses never include secrets: no api_key_hash, no
grantee_private_pem, no wrapped keys. A newly minted org API key appears exactly
once, in the response to the call that created it — only its hash is stored.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.auth import hash_api_key
from app.db.models import AccessGrantKey, AccessRequest, Event, Org, Trace
from app.db.session import get_db
from app.schemas import (
    AdminOrgCreateIn,
    AdminOrgKeyOut,
    AdminOrgOut,
    AdminRequestDetailOut,
    AdminRequestOut,
    AdminScopeItem,
    AdminTraceEventOut,
    EventReplayItem,
    TraceReplayOut,
)
from app.services import access_review
from app.services import orgs as org_service
from app.services.access import TraceNotFoundError
from app.services.replay import replay_trace
from app.services.verification import TraceReplayResult

router = APIRouter(prefix="/v1/admin", dependencies=[Depends(require_admin)])


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid id") from exc


@router.get("/ping")
def ping() -> dict[str, bool]:
    """Auth probe for the dashboard connect button."""
    return {"ok": True}


# --- Orgs ---------------------------------------------------------------------


def _org_out(org: Org) -> AdminOrgOut:
    return AdminOrgOut(
        id=org.id,
        name=org.name,
        region=org.region,
        confidentiality_mode=org.confidentiality_mode,
        fail_mode=org.fail_mode,
        created_at=org.created_at.isoformat(),
    )


@router.get("/orgs", response_model=list[AdminOrgOut])
def list_orgs(db: Session = Depends(get_db)) -> list[AdminOrgOut]:
    orgs = db.query(Org).order_by(Org.created_at.desc()).all()
    return [_org_out(o) for o in orgs]


@router.post("/orgs", response_model=AdminOrgKeyOut)
def create_org(body: AdminOrgCreateIn, db: Session = Depends(get_db)) -> AdminOrgKeyOut:
    try:
        org, plaintext_key = org_service.create_org_with_api_key(
            db, org_id=body.org_id, name=body.name, region=body.region, api_key=body.api_key
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    return AdminOrgKeyOut(org_id=org.id, api_key=plaintext_key)


@router.post("/orgs/{org_id}/rotate-key", response_model=AdminOrgKeyOut)
def rotate_org_key(org_id: str, db: Session = Depends(get_db)) -> AdminOrgKeyOut:
    """Mint a fresh API key for an org; the old key stops working immediately."""
    org = db.query(Org).filter(Org.id == org_id).one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="org not found")
    plaintext_key = org_service.generate_api_key(prefix="attest")
    org.api_key_hash = hash_api_key(plaintext_key)
    db.commit()
    return AdminOrgKeyOut(org_id=org_id, api_key=plaintext_key)


# --- Access requests ----------------------------------------------------------


def _req_out(db: Session, req: AccessRequest) -> AdminRequestOut:
    return AdminRequestOut(
        request_id=str(req.id),
        org_id=req.org_id,
        status=req.status,
        reason=req.reason,
        required_approvals=req.required_approvals,
        approvals=access_review.approvals_count(db, req.id),
        grantee_public_pem=req.grantee_public_pem,
        expires_at=req.expires_at.isoformat(),
        requested_by=req.requested_by,
        trace_id=str(req.trace_id) if req.trace_id else None,
    )


@router.get("/access-requests", response_model=list[AdminRequestOut])
def list_all_requests(
    org_id: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
) -> list[AdminRequestOut]:
    query = db.query(AccessRequest)
    if org_id is not None:
        query = query.filter(AccessRequest.org_id == org_id)
    if status is not None:
        query = query.filter(AccessRequest.status == status)
    reqs = query.order_by(AccessRequest.created_at.desc()).limit(200).all()
    return [_req_out(db, r) for r in reqs]


@router.get("/access-requests/{request_id}", response_model=AdminRequestDetailOut)
def request_detail(request_id: str, db: Session = Depends(get_db)) -> AdminRequestDetailOut:
    req = db.get(AccessRequest, _parse_uuid(request_id))
    if req is None:
        raise HTTPException(status_code=404, detail="access request not found")
    items = db.query(AccessGrantKey).filter(AccessGrantKey.request_id == req.id).all()
    scope = [
        AdminScopeItem(payload_hash=i.payload_hash, released=i.wrapped_key_b64 is not None)
        for i in items
    ]
    base = _req_out(db, req)
    return AdminRequestDetailOut(**base.model_dump(), scope=scope)


# --- Trace lookup + verification (any org — admin views metadata, not content) -


@router.get("/traces/{trace_id}/events", response_model=list[AdminTraceEventOut])
def trace_events(trace_id: str, db: Session = Depends(get_db)) -> list[AdminTraceEventOut]:
    """Event metadata for any trace (hashes and types — never payload content)."""
    tid = _parse_uuid(trace_id)
    events = (
        db.query(Event).filter(Event.trace_id == tid).order_by(Event.seq).all()
    )
    if not events:
        raise HTTPException(status_code=404, detail="trace not found")
    return [
        AdminTraceEventOut(
            seq=e.seq,
            type=e.type,
            payload_hash=e.payload_hash,
            hash=e.hash,
            prev_hash=e.prev_hash,
            created_at=e.created_at.isoformat(),
        )
        for e in events
    ]


@router.get("/traces/{trace_id}/replay", response_model=TraceReplayOut)
def trace_replay(trace_id: str, db: Session = Depends(get_db)) -> TraceReplayOut:
    """Re-verify a trace's hashes, signatures and chain links (admin view)."""
    tid = _parse_uuid(trace_id)
    trace = db.get(Trace, tid)
    if trace is None:
        raise HTTPException(status_code=404, detail="trace not found")
    try:
        result: TraceReplayResult = replay_trace(db, org_id=trace.org_id, trace_id=tid)
    except TraceNotFoundError as exc:
        raise HTTPException(status_code=404, detail="trace not found") from exc
    return TraceReplayOut(
        trace_id=str(tid),
        all_verified=result.all_verified,
        events=[
            EventReplayItem(
                seq=e.seq,
                type=e.type,
                verified=e.verified,
                hash_ok=e.hash_ok,
                signature_ok=e.signature_ok,
                chain_ok=e.chain_ok,
            )
            for e in result.events
        ],
    )
