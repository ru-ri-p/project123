"""Policy surface for customers.

Two distinct things live here, and keeping them distinct is the point:

  * the institution's OWN policy — authored by the institution, decisive; and
  * regulation packs — jurisdiction rulebooks Attest publishes, advisory only,
    which the institution subscribes to.

Attest never writes the institution's policy for it.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.domain.jurisdictions import list_jurisdictions
from app.repositories import policies as policy_repo
from app.schemas import (
    InternalPolicyIn,
    JurisdictionOut,
    PackSubscriptionIn,
    PolicyOut,
    RegulationPackOut,
)
from app.services import regulation_packs as pack_service
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


@router.put("/internal", response_model=PolicyOut)
def put_internal_policy(
    body: InternalPolicyIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> PolicyOut:
    """The institution authors and versions its OWN policy.

    Activating a version changes what is enforced on every subsequent action, so
    the change is recorded against a version string the institution chooses and
    which is stamped onto every decision event thereafter.
    """
    policy = policy_repo.upsert_policy(
        db,
        org_id=org.id,
        name=body.name,
        version=body.version,
        rules=body.rules,
        active=body.activate,
    )
    db.commit()
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


# --- Jurisdictions & regulation packs -----------------------------------------


@router.get("/jurisdictions", response_model=list[JurisdictionOut])
def get_jurisdictions() -> list[JurisdictionOut]:
    """Every jurisdiction Attest can model, with its official source links."""
    return [
        JurisdictionOut(
            code=j.code,
            name=j.name,
            regulators=list(j.regulators),
            summary=j.summary,
            official_sources=list(j.official_sources),
        )
        for j in list_jurisdictions()
    ]


def _pack_out(pack, enabled=None, enforcement=None) -> RegulationPackOut:  # type: ignore[no-untyped-def]
    doc = pack.rules if isinstance(pack.rules, dict) else {}
    rules = doc.get("rules", [])
    return RegulationPackOut(
        id=str(pack.id),
        code=pack.code,
        jurisdiction=pack.jurisdiction,
        name=pack.name,
        version=pack.version,
        instrument=pack.instrument,
        instrument_notes=pack.instrument_notes,
        source_url=pack.source_url,
        effective_date=pack.effective_date,
        verification_status=pack.verification_status,
        reviewed_by=pack.reviewed_by,
        rule_count=len(rules) if isinstance(rules, list) else 0,
        enabled=enabled,
        enforcement=enforcement,
    )


@router.get("/packs", response_model=list[RegulationPackOut])
def get_available_packs(
    jurisdiction: str | None = None,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> list[RegulationPackOut]:
    """Packs available to subscribe to."""
    return [_pack_out(p) for p in pack_service.list_packs(db, jurisdiction)]


@router.get("/packs/mine", response_model=list[RegulationPackOut])
def get_my_packs(
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> list[RegulationPackOut]:
    """Packs this institution has applied to itself."""
    return [
        _pack_out(pack, enabled=sub.enabled, enforcement=sub.enforcement)
        for pack, sub in pack_service.org_subscriptions(db, org.id)
    ]


@router.post("/packs/subscribe", response_model=RegulationPackOut)
def subscribe_pack(
    body: PackSubscriptionIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> RegulationPackOut:
    try:
        sub = pack_service.subscribe_org(
            db,
            org_id=org.id,
            pack_code=body.pack_code,
            enabled=body.enabled,
            enforcement=body.enforcement,
        )
    except pack_service.PackError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    pack = pack_service.latest_pack_by_code(db, body.pack_code)
    assert pack is not None
    return _pack_out(pack, enabled=sub.enabled, enforcement=sub.enforcement)
