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
    GrantRecordOut,
    SigningKeyOut,
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
    )


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid id") from exc


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
