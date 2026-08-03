"""Endpoints the SDK uses to stay useful when Attest is unreachable.

  POST /v1/sdk/devices  — register this SDK instance's signing key (automatic)
  GET  /v1/sdk/bundle   — the rules to evaluate against locally during an outage
  POST /v1/sdk/replay   — hand back events buffered while we were down
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.repositories import policies as policy_repo
from app.schemas import (
    DeviceRegisterIn,
    DeviceRegisterOut,
    OfflineBundleOut,
    ReplayIn,
    ReplayOut,
)
from app.services import regulation_packs as pack_service
from app.services.offline import (
    OfflineSegmentError,
    graft_offline_segment,
    register_device,
)

router = APIRouter(prefix="/v1/sdk", tags=["sdk"])


@router.post("/devices", response_model=DeviceRegisterOut)
def register_sdk_device(
    body: DeviceRegisterIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> DeviceRegisterOut:
    try:
        device = register_device(
            db,
            org_id=org.id,
            device_id=body.device_id,
            public_pem=body.public_pem,
            label=body.label,
        )
    except OfflineSegmentError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    return DeviceRegisterOut(device_id=device.device_id, registered=True)


@router.get("/bundle", response_model=OfflineBundleOut)
def offline_bundle(
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> OfflineBundleOut:
    """Everything needed to reach the same verdict locally during an outage.

    Ships the institution's own policy AND the jurisdiction packs it has adopted
    — without the packs a local verdict would silently omit findings the server
    would have raised, so the same output would get different answers depending
    on whether Attest happened to be up.
    """
    policy = policy_repo.get_active_policy(db, org.id)
    packs = [
        {
            "code": pack.code,
            "jurisdiction": pack.jurisdiction,
            "instrument": pack.instrument,
            "version": pack.version,
            "verification_status": pack.verification_status,
            "source_url": pack.source_url,
            "rules": (pack.rules or {}).get("rules", []),
        }
        for pack, sub in pack_service.org_subscriptions(db, org.id)
        if sub.enabled
    ]
    return OfflineBundleOut(
        policy_version=policy.version if policy else None,
        policy_rules=(policy.rules if policy else None) or {},
        packs=packs,
        fail_mode=org.fail_mode,
    )


@router.post("/replay", response_model=ReplayOut)
def replay_offline_segment(
    body: ReplayIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> ReplayOut:
    """Graft events buffered during an outage. Verified as a whole or refused."""
    try:
        results = graft_offline_segment(
            db, org=org, device_id=body.device_id, items=[i.model_dump() for i in body.items]
        )
        db.commit()
    except OfflineSegmentError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ReplayOut(accepted=len(results), results=results)
