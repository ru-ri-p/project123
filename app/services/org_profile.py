"""Deriving obligations from an institution's profile.

The rule that makes this worth having: **mandatory packs are computed, not
chosen.** A firm declares where it is licensed and what it does; Attest works out
which rulebooks follow. There is no endpoint that lets them drop one.

Asymmetric change control, because the risk is asymmetric:

  * ADDING a jurisdiction or sector applies immediately. Taking on more
    obligations is never the thing to defend against, and making it slow would
    only discourage honesty.
  * REMOVING one raises a request for Attest to approve. That is the move that
    sheds obligations, and it is exactly the evasion that picking rulebooks
    à la carte would have allowed.

There is no second route in. The "adopt a rulebook" picker has been removed: it
was the visible remnant of cherry-picking, and it let the applied set drift away
from who the firm actually is. A firm carrying rulebooks that do not apply to it
is as wrong as one missing rulebooks that do — both make the dashboard
meaningless. To take on another rulebook, declare the sector or jurisdiction that
implies it, which is the honest way to acquire the obligation anyway.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.db.models import (
    Org,
    OrgProfile,
    OrgRegulationPack,
    ProfileChangeRequest,
    RegulationPack,
)
from app.domain.jurisdictions import JURISDICTIONS
from app.domain.sectors import validate_sectors


class ProfileError(ValueError):
    """Invalid profile, or a reduction attempted without approval."""


def validate_jurisdictions(codes: list[str]) -> list[str]:
    cleaned = sorted({c.strip() for c in codes if c and c.strip()})
    unknown = [c for c in cleaned if c not in JURISDICTIONS or c == "internal"]
    if unknown:
        msg = f"unknown jurisdiction(s): {', '.join(unknown)}"
        raise ProfileError(msg)
    return cleaned


def get_profile(db: Session, org_id: str) -> OrgProfile | None:
    return db.get(OrgProfile, org_id)


def pack_applies(pack: RegulationPack, jurisdictions: list[str], sectors: list[str]) -> bool:
    """A pack applies when it reaches BOTH the institution's jurisdiction and sector.

    Jurisdiction and sector are separate tests because instruments genuinely vary
    on both axes: DIFC data protection binds every sector in the DIFC, while the
    joint financial-sector AI guidelines bind financial institutions across all
    three UAE jurisdictions.
    """
    doc = pack.rules if isinstance(pack.rules, dict) else {}
    pack_jurisdictions = doc.get("jurisdictions") or [pack.jurisdiction]
    pack_sectors = doc.get("sectors") or ["*"]

    juris_hit = "*" in pack_jurisdictions or bool(set(pack_jurisdictions) & set(jurisdictions))
    sector_hit = "*" in pack_sectors or bool(set(pack_sectors) & set(sectors))
    return juris_hit and sector_hit


def mandatory_packs(db: Session, org_id: str) -> list[RegulationPack]:
    """The rulebooks the profile requires. Empty until a profile is set."""
    profile = get_profile(db, org_id)
    if profile is None:
        return []
    jurisdictions = list(profile.jurisdictions or [])
    sectors = list(profile.sectors or [])
    return [
        pack
        for pack in db.query(RegulationPack).order_by(RegulationPack.code).all()
        if pack_applies(pack, jurisdictions, sectors)
    ]


def reconcile_packs(db: Session, org_id: str) -> tuple[list[str], list[str]]:
    """Make the applied rulebooks equal exactly what the profile derives.

    The profile is the single source of truth. A firm that declares DIFC and
    capital markets must not be carrying ADGM: being measured against
    regulations that do not apply to it is as wrong as missing ones that do, and
    it makes the dashboard meaningless.

    Removing here is safe precisely because reductions are already gated —
    shrinking a profile needs Attest's approval, so a pack can only fall away
    after a human agreed the change. Nothing is shed unilaterally.

    Returns (added, removed) pack codes.
    """
    from app.services.regulation_packs import org_subscriptions, subscribe_org

    required = {pack.code: pack for pack in mandatory_packs(db, org_id)}
    current = {pack.code: sub for pack, sub in org_subscriptions(db, org_id)}

    added = [code for code in required if code not in current]
    for code in added:
        subscribe_org(db, org_id=org_id, pack_code=code)

    removed = [code for code in current if code not in required]
    for code in removed:
        db.query(OrgRegulationPack).filter(
            OrgRegulationPack.org_id == org_id,
            OrgRegulationPack.pack_id == current[code].pack_id,
        ).delete()

    db.flush()
    return sorted(added), sorted(removed)


def _apply(
    db: Session, *, org_id: str, jurisdictions: list[str], sectors: list[str], actor: str
) -> OrgProfile:
    profile = get_profile(db, org_id)
    if profile is None:
        profile = OrgProfile(org_id=org_id, jurisdictions=jurisdictions, sectors=sectors)
        db.add(profile)
    else:
        profile.jurisdictions = jurisdictions
        profile.sectors = sectors
    profile.updated_at = datetime.now(UTC)
    profile.updated_by = actor
    db.flush()

    # Applied rulebooks always equal what the profile derives — including
    # dropping ones it no longer implies, and clearing legacy subscriptions made
    # back when packs could be picked one by one.
    reconcile_packs(db, org_id)
    return profile


def set_profile(
    db: Session,
    *,
    org_id: str,
    jurisdictions: list[str],
    sectors: list[str],
    actor: str,
    reason: str = "",
    allow_reduction: bool = False,
) -> tuple[OrgProfile | None, ProfileChangeRequest | None]:
    """Update a profile.

    Returns (profile, None) when applied outright, or (None, request) when the
    change would REMOVE something and therefore needs Attest's approval.
    """
    jurisdictions = validate_jurisdictions(jurisdictions)
    sectors = validate_sectors(sectors)
    if not jurisdictions or not sectors:
        msg = "at least one jurisdiction and one sector are required"
        raise ProfileError(msg)

    current = get_profile(db, org_id)
    removed: list[str] = []
    if current is not None:
        removed = sorted(
            (set(current.jurisdictions or []) - set(jurisdictions))
            | (set(current.sectors or []) - set(sectors))
        )

    if removed and not allow_reduction:
        if not reason.strip():
            msg = "a reason is required to request removal of a jurisdiction or sector"
            raise ProfileError(msg)
        request = ProfileChangeRequest(
            org_id=org_id,
            requested_by=actor,
            reason=reason.strip(),
            proposed_jurisdictions=jurisdictions,
            proposed_sectors=sectors,
            removed=removed,
            status="pending",
        )
        db.add(request)
        db.flush()
        return None, request

    return _apply(
        db, org_id=org_id, jurisdictions=jurisdictions, sectors=sectors, actor=actor
    ), None


def decide_change_request(
    db: Session, *, request_id: str, approve: bool, decided_by: str
) -> ProfileChangeRequest:
    request = db.get(ProfileChangeRequest, request_id)
    if request is None:
        msg = f"profile change request not found: {request_id}"
        raise ProfileError(msg)
    if request.status != "pending":
        return request

    request.status = "approved" if approve else "denied"
    request.decided_by = decided_by
    request.decided_at = datetime.now(UTC)
    if approve:
        _apply(
            db,
            org_id=request.org_id,
            jurisdictions=list(request.proposed_jurisdictions),
            sectors=list(request.proposed_sectors),
            actor=f"attest:{decided_by}",
        )
    db.flush()
    return request


def pending_change_requests(db: Session, org_id: str | None = None) -> list[ProfileChangeRequest]:
    query = db.query(ProfileChangeRequest).filter(ProfileChangeRequest.status == "pending")
    if org_id is not None:
        query = query.filter(ProfileChangeRequest.org_id == org_id)
    return query.order_by(ProfileChangeRequest.created_at.desc()).all()


def profile_summary(db: Session, org: Org) -> dict[str, object]:
    profile = get_profile(db, org.id)
    packs = mandatory_packs(db, org.id)
    return {
        "org_id": org.id,
        "configured": profile is not None,
        "jurisdictions": list(profile.jurisdictions) if profile else [],
        "sectors": list(profile.sectors) if profile else [],
        "updated_at": profile.updated_at.isoformat() if profile else None,
        "updated_by": profile.updated_by if profile else None,
        "mandatory_pack_codes": [p.code for p in packs],
        "pending_changes": len(pending_change_requests(db, org.id)),
    }
