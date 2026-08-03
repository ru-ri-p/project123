"""HTTP routes for the consent-gated access platform (Slice 5a).

Org endpoints (x-api-key): set customer-key confidentiality, provision a signing
key, list/inspect access requests, approve (posting client-released keys), resolve.
Admin endpoints (x-admin-key): file access requests, read a record via a grant.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org, require_admin
from app.db.models import AccessRequest, Org
from app.db.session import get_db
from app.schemas import (
    AccessApproveIn,
    AccessRequestCreateIn,
    AccessRequestDetailOut,
    AccessRequestOut,
    AccessResolveIn,
    AccessScopeItem,
    ConfidentialityIn,
    DailyCount,
    GrantRecordOut,
    OrgOverviewOut,
    SigningKeyOut,
    TraceEventMetaOut,
)
from app.services import access_review
from app.services import org_signing as org_signing_service
from app.services import orgs as org_service

router = APIRouter(prefix="/v1")


def _out(db: Session, req: AccessRequest) -> AccessRequestOut:
    return AccessRequestOut(
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


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid id") from exc


# --- Org: overview (dashboard home) -------------------------------------------


@router.get("/org/overview", response_model=OrgOverviewOut)
def org_overview(
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> OrgOverviewOut:
    """Everything the customer console's Overview screen shows, in one call."""
    import hashlib
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func

    from app.db.models import Event
    from app.services.org_signing import active_signing_key

    now = datetime.now(UTC)
    window_start = (now - timedelta(days=13)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    day_col = func.date_trunc("day", Event.created_at)
    rows = (
        db.query(day_col.label("day"), func.count(Event.id))
        .filter(Event.org_id == org.id, Event.created_at >= window_start)
        .group_by(day_col)
        .all()
    )
    counts = {day.strftime("%Y-%m-%d"): c for day, c in rows}
    days = [(window_start + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(14)]

    total = db.query(func.count(Event.id)).filter(Event.org_id == org.id).scalar() or 0
    last_at = (
        db.query(func.max(Event.created_at)).filter(Event.org_id == org.id).scalar()
    )
    pending = (
        db.query(func.count(AccessRequest.id))
        .filter(AccessRequest.org_id == org.id, AccessRequest.status == "pending")
        .scalar()
        or 0
    )
    fingerprint = (
        hashlib.sha256(org.wrapping_public_pem.encode("utf-8")).hexdigest()
        if org.wrapping_public_pem
        else None
    )
    signing = active_signing_key(db, org.id)

    from app.repositories import policies as policy_repo
    from app.services import regulation_packs as pack_service

    active_policy = policy_repo.get_active_policy(db, org.id)
    adopted = sorted(
        {
            pack.jurisdiction
            for pack, sub in pack_service.org_subscriptions(db, org.id)
            if sub.enabled
        }
    )

    return OrgOverviewOut(
        org_id=org.id,
        name=org.name,
        confidentiality_mode=org.confidentiality_mode,
        wrapping_key_fingerprint=fingerprint,
        signing_key_id=str(signing.key_id) if signing else None,
        total_events=total,
        last_event_at=last_at.isoformat() if last_at else None,
        pending_requests=pending,
        daily=[DailyCount(day=d, count=counts.get(d, 0)) for d in days],
        active_policy_version=active_policy.version if active_policy else None,
        jurisdictions_adopted=adopted,
    )


@router.get("/trace/{trace_id}/events", response_model=list[TraceEventMetaOut])
def org_trace_events(
    trace_id: str,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> list[TraceEventMetaOut]:
    """Event metadata for one of the org's own traces (hashes/types, not content)."""
    from app.repositories import events as event_repo

    events = event_repo.events_for_trace(db, org.id, _parse_uuid(trace_id))
    if not events:
        raise HTTPException(status_code=404, detail="trace not found")
    return [
        TraceEventMetaOut(
            seq=e.seq,
            type=e.type,
            payload_hash=e.payload_hash,
            hash=e.hash,
            created_at=e.created_at.isoformat(),
        )
        for e in events
    ]


# --- Org: confidentiality + signing key ---------------------------------------


@router.post("/org/confidentiality")
def set_confidentiality(
    body: ConfidentialityIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    org_service.enable_customer_key_mode(db, org.id, body.wrapping_public_pem.encode("utf-8"))
    db.commit()
    return {"org_id": org.id, "confidentiality_mode": "customer_key"}


@router.post("/org/signing-key", response_model=SigningKeyOut)
def provision_signing_key(
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> SigningKeyOut:
    key = org_signing_service.provision_managed_signing_key(db, org.id)
    db.commit()
    return SigningKeyOut(key_id=str(key.key_id), public_pem=key.public_pem)


# --- Admin (Attest ops): file requests, read via grant ------------------------


@router.post(
    "/admin/access-requests",
    response_model=AccessRequestOut,
    dependencies=[Depends(require_admin)],
)
def file_access_request(
    body: AccessRequestCreateIn, db: Session = Depends(get_db)
) -> AccessRequestOut:
    req = access_review.create_access_request(
        db,
        org_id=body.org_id,
        requested_by="attest_admin",
        payload_hashes=body.payload_hashes,
        reason=body.reason,
        required_approvals=body.required_approvals,
        ttl_seconds=body.ttl_seconds,
    )
    db.commit()
    return _out(db, req)


@router.get(
    "/admin/access-requests/{request_id}/records/{payload_hash}",
    response_model=GrantRecordOut,
    dependencies=[Depends(require_admin)],
)
def read_record_via_grant(
    request_id: str, payload_hash: str, db: Session = Depends(get_db)
) -> GrantRecordOut:
    content = access_review.read_via_grant(
        db, request_id=_parse_uuid(request_id), payload_hash=payload_hash
    )
    if content is None:
        raise HTTPException(
            status_code=403,
            detail="not available (not approved, out of scope, or expired)",
        )
    # The read appended an access_read event to the consent trail — commit it
    # with the read. If recording failed, read_via_grant raised and no content
    # reaches the caller (no unrecorded vendor access).
    db.commit()
    return GrantRecordOut(payload_hash=payload_hash, content=content)


# --- Org: list / inspect / approve / resolve ----------------------------------


@router.get("/access-requests", response_model=list[AccessRequestOut])
def list_requests(
    status: str | None = None,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> list[AccessRequestOut]:
    return [_out(db, r) for r in access_review.list_access_requests(db, org.id, status)]


def _owned_request(db: Session, request_id: str, org: Org) -> AccessRequest:
    req = access_review.get_access_request(db, _parse_uuid(request_id))
    if req is None or req.org_id != org.id:
        raise HTTPException(status_code=404, detail="access request not found")
    return req


@router.get("/access-requests/{request_id}", response_model=AccessRequestDetailOut)
def request_detail(
    request_id: str,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> AccessRequestDetailOut:
    req = _owned_request(db, request_id, org)
    scope = [
        AccessScopeItem(
            payload_hash=str(item["payload_hash"]),
            wrapped_key_for_org=item["wrapped_key_for_org"],
        )
        for item in access_review.request_scope(db, req.id)
    ]
    base = _out(db, req)
    return AccessRequestDetailOut(**base.model_dump(), scope=scope)


@router.post("/access-requests/{request_id}/approve", response_model=AccessRequestOut)
def approve_request(
    request_id: str,
    body: AccessApproveIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> AccessRequestOut:
    req = _owned_request(db, request_id, org)
    req = access_review.record_client_approval(
        db, request_id=req.id, approver_id=body.approver_id, released_keys=body.released_keys
    )
    db.commit()
    return _out(db, req)


@router.post("/access-requests/{request_id}/resolve", response_model=AccessRequestOut)
def resolve_request(
    request_id: str,
    body: AccessResolveIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> AccessRequestOut:
    req = _owned_request(db, request_id, org)
    req = access_review.resolve_access_request(db, request_id=req.id, status=body.status)
    db.commit()
    return _out(db, req)
