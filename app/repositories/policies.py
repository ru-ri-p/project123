"""Org-scoped policy documents."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Policy


def get_active_policy(db: Session, org_id: str) -> Policy | None:
    return (
        db.query(Policy)
        .filter(Policy.org_id == org_id, Policy.active.is_(True))
        .order_by(Policy.created_at.desc())
        .first()
    )


def get_policy_by_version(db: Session, org_id: str, version: str) -> Policy | None:
    return (
        db.query(Policy)
        .filter(Policy.org_id == org_id, Policy.version == version)
        .one_or_none()
    )


def upsert_policy(
    db: Session,
    *,
    org_id: str,
    name: str,
    version: str,
    rules: dict[str, Any],
    active: bool = True,
) -> Policy:
    existing = get_policy_by_version(db, org_id, version)
    if existing is not None:
        existing.name = name
        existing.rules = rules
        existing.active = active
        db.flush()
        return existing

    if active:
        db.query(Policy).filter(Policy.org_id == org_id, Policy.active.is_(True)).update(
            {"active": False}
        )

    policy = Policy(
        org_id=org_id,
        name=name,
        version=version,
        rules=rules,
        active=active,
    )
    db.add(policy)
    db.flush()
    return policy
