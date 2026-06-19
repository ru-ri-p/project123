"""Organisation settings routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.schemas import OrgOut, OrgSettingsUpdate
from app.services.orgs import InvalidOrgSettingsError, update_org_settings

router = APIRouter(prefix="/v1/org", tags=["org"])


@router.get("/me", response_model=OrgOut)
def get_current_org(org: Org = Depends(get_authenticated_org)) -> OrgOut:
    return OrgOut.model_validate(org)


@router.patch("/settings", response_model=OrgOut)
def patch_org_settings(
    body: OrgSettingsUpdate,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> OrgOut:
    try:
        updated = update_org_settings(
            db,
            org.id,
            region=body.region,
            fail_mode=body.fail_mode,
            retention_days_payload=body.retention_days_payload,
        )
        db.commit()
    except InvalidOrgSettingsError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return OrgOut.model_validate(updated)
