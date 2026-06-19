"""Active policy document for operators and SDK bundle sync."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.repositories import policies as policy_repo
from app.schemas import PolicyOut
from app.services.precheck import NoActivePolicyError

router = APIRouter(prefix="/v1/policies", tags=["policies"])


@router.get("/active", response_model=PolicyOut)
def get_active_policy(
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> PolicyOut:
    policy = policy_repo.get_active_policy(db, org.id)
    if policy is None:
        raise HTTPException(status_code=404, detail=str(NoActivePolicyError("no active policy")))

    rules = policy.rules if isinstance(policy.rules, dict) else {}
    return PolicyOut(
        id=str(policy.id),
        org_id=policy.org_id,
        name=policy.name,
        version=policy.version,
        active=policy.active,
        schema_version=rules.get("schema_version"),
        engine=rules.get("engine"),
        rules=rules,
    )
