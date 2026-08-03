"""Publishing regulation packs and subscribing orgs to them."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.models import OrgRegulationPack, RegulationPack
from app.domain.regulation_packs import BUILTIN_PACKS


class PackError(ValueError):
    """Unknown pack, or an invalid subscription."""


def upsert_pack(db: Session, doc: dict[str, Any]) -> RegulationPack:
    """Publish (or refresh) one pack version. Idempotent on (code, version)."""
    existing = (
        db.query(RegulationPack)
        .filter(RegulationPack.code == doc["code"], RegulationPack.version == doc["version"])
        .one_or_none()
    )
    rules_doc = {
        "schema_version": doc.get("schema_version", 2),
        "engine": doc.get("engine", "json"),
        "rules": doc.get("rules", []),
        # Targeting must be persisted, not just declared in the source module —
        # it is what decides whether a pack reaches a given institution, and
        # profile matching reads it back from here.
        "jurisdictions": doc.get("jurisdictions") or [doc["jurisdiction"]],
        "sectors": doc.get("sectors") or ["*"],
    }
    if existing is not None:
        existing.name = doc["name"]
        existing.instrument = doc["instrument"]
        existing.instrument_notes = doc.get("instrument_notes")
        existing.source_url = doc.get("source_url")
        existing.effective_date = doc.get("effective_date")
        existing.verification_status = doc.get("verification_status", "unverified")
        existing.rules = rules_doc
        db.flush()
        return existing

    pack = RegulationPack(
        code=doc["code"],
        jurisdiction=doc["jurisdiction"],
        name=doc["name"],
        version=doc["version"],
        instrument=doc["instrument"],
        instrument_notes=doc.get("instrument_notes"),
        source_url=doc.get("source_url"),
        effective_date=doc.get("effective_date"),
        verification_status=doc.get("verification_status", "unverified"),
        rules=rules_doc,
    )
    db.add(pack)
    db.flush()
    return pack


def seed_builtin_packs(db: Session) -> list[RegulationPack]:
    """Publish the bundled starter packs. Safe to re-run."""
    return [upsert_pack(db, doc) for doc in BUILTIN_PACKS]


def latest_pack_by_code(db: Session, code: str) -> RegulationPack | None:
    return (
        db.query(RegulationPack)
        .filter(RegulationPack.code == code)
        .order_by(RegulationPack.created_at.desc())
        .first()
    )


def list_packs(db: Session, jurisdiction: str | None = None) -> list[RegulationPack]:
    query = db.query(RegulationPack)
    if jurisdiction is not None:
        query = query.filter(RegulationPack.jurisdiction == jurisdiction)
    return query.order_by(RegulationPack.jurisdiction, RegulationPack.code).all()


def subscribe_org(
    db: Session,
    *,
    org_id: str,
    pack_code: str,
    enabled: bool = True,
    enforcement: str = "advisory",
) -> OrgRegulationPack:
    """Apply a jurisdiction's pack to an org.

    MVP refuses anything but advisory: blocking on rule content that has not had
    legal review could stop a customer's business on a drafting error.
    """
    if enforcement != "advisory":
        msg = "only 'advisory' enforcement is available until pack content is reviewed"
        raise PackError(msg)
    pack = latest_pack_by_code(db, pack_code)
    if pack is None:
        msg = f"unknown regulation pack: {pack_code}"
        raise PackError(msg)

    row = (
        db.query(OrgRegulationPack)
        .filter(OrgRegulationPack.org_id == org_id, OrgRegulationPack.pack_id == pack.id)
        .one_or_none()
    )
    if row is None:
        row = OrgRegulationPack(
            org_id=org_id, pack_id=pack.id, enabled=enabled, enforcement=enforcement
        )
        db.add(row)
    else:
        row.enabled = enabled
        row.enforcement = enforcement
    db.flush()
    return row


def org_subscriptions(db: Session, org_id: str) -> list[tuple[RegulationPack, OrgRegulationPack]]:
    rows = (
        db.query(RegulationPack, OrgRegulationPack)
        .join(OrgRegulationPack, OrgRegulationPack.pack_id == RegulationPack.id)
        .filter(OrgRegulationPack.org_id == org_id)
        .order_by(RegulationPack.jurisdiction, RegulationPack.code)
        .all()
    )
    return [(pack, sub) for pack, sub in rows]
