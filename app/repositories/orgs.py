"""Org-scoped database access."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.auth import hash_api_key
from app.db.models import Org


def get_org_by_id(db: Session, org_id: str) -> Org | None:
    return db.query(Org).filter(Org.id == org_id).one_or_none()


def create_org(
    db: Session,
    *,
    org_id: str,
    name: str,
    api_key_hash: str,
    region: str,
    fail_mode: str,
    retention_days_payload: int = 365,
) -> Org:
    org = Org(
        id=org_id,
        name=name,
        api_key_hash=api_key_hash,
        region=region,
        fail_mode=fail_mode,
        retention_days_payload=retention_days_payload,
    )
    db.add(org)
    db.flush()
    return org


def update_org_settings(
    db: Session,
    org_id: str,
    *,
    region: str | None = None,
    fail_mode: str | None = None,
    retention_days_payload: int | None = None,
) -> Org | None:
    org = get_org_by_id(db, org_id)
    if org is None:
        return None
    if region is not None:
        org.region = region
    if fail_mode is not None:
        org.fail_mode = fail_mode
    if retention_days_payload is not None:
        org.retention_days_payload = retention_days_payload
    db.flush()
    return org


def org_exists_by_api_key_hash(db: Session, api_key_hash: str) -> bool:
    return db.query(Org.id).filter(Org.api_key_hash == api_key_hash).first() is not None


def hash_and_check_unique(db: Session, api_key: str) -> str:
    key_hash = hash_api_key(api_key)
    if org_exists_by_api_key_hash(db, key_hash):
        msg = "api key hash collision"
        raise ValueError(msg)
    return key_hash
