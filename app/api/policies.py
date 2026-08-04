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
from app.db.models import Org, PolicyDecisionSummary
from app.db.session import get_db
from app.domain.jurisdictions import list_jurisdictions
from app.domain.sectors import grouped_sectors
from app.repositories import policies as policy_repo
from app.schemas import (
    ComplianceSummaryOut,
    InternalPolicyIn,
    JurisdictionOut,
    OrgProfileIn,
    OrgProfileOut,
    PolicyDecisionOut,
    PolicyOut,
    ProfileUpdateOut,
    RegulationPackOut,
)
from app.services import org_profile as profile_service
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


@router.get("/decisions", response_model=list[PolicyDecisionOut])
def get_decisions(
    flagged_only: bool = False,
    limit: int = 50,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> list[PolicyDecisionOut]:
    """Recent policy decisions with their cited findings."""
    query = db.query(PolicyDecisionSummary).filter(PolicyDecisionSummary.org_id == org.id)
    if flagged_only:
        query = query.filter(PolicyDecisionSummary.tier.in_(("orange", "red")))
    rows = (
        query.order_by(PolicyDecisionSummary.created_at.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return [_decision_out(r) for r in rows]


def _decision_out(row: PolicyDecisionSummary) -> PolicyDecisionOut:
    return PolicyDecisionOut(
        trace_id=str(row.trace_id),
        seq=row.seq,
        action=row.action,
        tier=row.tier,
        policy_tier=row.policy_tier,
        allowed=row.allowed,
        policy_version=row.policy_version,
        jurisdictions=list(row.jurisdictions or []),
        findings=list(row.findings or []),
        event_hash=row.event_hash,
        created_at=row.created_at.isoformat(),
        status=row.status,
        output_seq=row.output_seq,
        output_hash=row.output_hash,
    )


@router.get("/compliance-summary", response_model=ComplianceSummaryOut)
def get_compliance_summary(
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> ComplianceSummaryOut:
    from sqlalchemy import func

    rows = (
        db.query(PolicyDecisionSummary.tier, func.count(PolicyDecisionSummary.id))
        .filter(PolicyDecisionSummary.org_id == org.id)
        .group_by(PolicyDecisionSummary.tier)
        .all()
    )
    by_tier = {tier: count for tier, count in rows}
    total = sum(by_tier.values())
    flagged = by_tier.get("orange", 0) + by_tier.get("red", 0)

    by_jurisdiction: dict[str, int] = {}
    for (js,) in (
        db.query(PolicyDecisionSummary.jurisdictions)
        .filter(PolicyDecisionSummary.org_id == org.id)
        .all()
    ):
        for j in js or []:
            by_jurisdiction[j] = by_jurisdiction.get(j, 0) + 1

    unverified = sum(
        1
        for pack, sub in pack_service.org_subscriptions(db, org.id)
        if sub.enabled and pack.verification_status == "unverified"
    )
    # What APPLIES to them, from their declared profile — not merely which
    # jurisdictions have produced a finding so far. The old version read "none"
    # for a correctly-configured org that simply had not been checked yet.
    profile = profile_service.get_profile(db, org.id)
    applied_jurisdictions = sorted(profile.jurisdictions or []) if profile else []
    active = policy_repo.get_active_policy(db, org.id)
    return ComplianceSummaryOut(
        decisions_total=total,
        flagged_total=flagged,
        by_tier=by_tier,
        by_jurisdiction=by_jurisdiction,
        applied_jurisdictions=applied_jurisdictions,
        unverified_packs=unverified,
        active_policy_version=active.version if active else None,
    )


# --- Settings: the institution's profile --------------------------------------


@router.get("/sectors")
def get_sector_taxonomy() -> dict[str, object]:
    """The sector list for the settings page, grouped, with ISIC mappings."""
    return {"groups": grouped_sectors()}


@router.get("/profile", response_model=OrgProfileOut)
def get_org_profile(
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> OrgProfileOut:
    return OrgProfileOut(**profile_service.profile_summary(db, org))  # type: ignore[arg-type]


@router.put("/profile", response_model=ProfileUpdateOut)
def put_org_profile(
    body: OrgProfileIn,
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> ProfileUpdateOut:
    """Declare where you are licensed and what you do.

    Adding applies immediately. Removing raises a request for Attest to approve —
    obligations may be taken on freely, but not dropped unilaterally.
    """
    try:
        profile, request = profile_service.set_profile(
            db,
            org_id=org.id,
            jurisdictions=body.jurisdictions,
            sectors=body.sectors,
            actor=body.updated_by or "customer",
            reason=body.reason or "",
        )
    except (profile_service.ProfileError, ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()

    if request is not None:
        return ProfileUpdateOut(
            applied=False,
            pending_approval=True,
            removed=list(request.removed),
            request_id=str(request.id),
            message=(
                "Removing a jurisdiction or sector needs Attest's approval. Your "
                "current obligations remain in force until it is reviewed."
            ),
            profile=OrgProfileOut(**profile_service.profile_summary(db, org)),  # type: ignore[arg-type]
        )
    assert profile is not None
    return ProfileUpdateOut(
        applied=True,
        pending_approval=False,
        removed=[],
        message="Profile updated. Rulebooks have been applied automatically.",
        profile=OrgProfileOut(**profile_service.profile_summary(db, org)),  # type: ignore[arg-type]
    )
