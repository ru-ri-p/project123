"""Organisation provisioning and settings."""

from __future__ import annotations

import secrets

from sqlalchemy.orm import Session

from app.auth import hash_api_key
from app.db.models import Org
from app.domain.org_settings import DEFAULT_FAIL_MODE, DEFAULT_REGION, FAIL_MODES, REGIONS
from app.repositories import orgs as org_repo


class InvalidOrgSettingsError(ValueError):
    """Raised when region or fail_mode values are not allowed."""


def validate_region(region: str) -> str:
    if region not in REGIONS:
        msg = f"invalid region: {region}; allowed: {sorted(REGIONS)}"
        raise InvalidOrgSettingsError(msg)
    return region


def validate_fail_mode(fail_mode: str) -> str:
    if fail_mode not in FAIL_MODES:
        msg = f"invalid fail_mode: {fail_mode}; allowed: {sorted(FAIL_MODES)}"
        raise InvalidOrgSettingsError(msg)
    return fail_mode


def generate_api_key(prefix: str = "wthq") -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


def create_org_with_api_key(
    db: Session,
    *,
    org_id: str,
    name: str,
    region: str = DEFAULT_REGION,
    fail_mode: str = DEFAULT_FAIL_MODE,
    retention_days_payload: int = 365,
    api_key: str | None = None,
) -> tuple[Org, str]:
    if org_repo.get_org_by_id(db, org_id) is not None:
        msg = f"org already exists: {org_id}"
        raise ValueError(msg)

    region = validate_region(region)
    fail_mode = validate_fail_mode(fail_mode)
    plaintext_key = api_key or generate_api_key()
    key_hash = hash_api_key(plaintext_key)

    if org_repo.org_exists_by_api_key_hash(db, key_hash):
        msg = "api key already in use"
        raise ValueError(msg)

    org_repo.create_org(
        db,
        org_id=org_id,
        name=name,
        api_key_hash=key_hash,
        region=region,
        fail_mode=fail_mode,
        retention_days_payload=retention_days_payload,
    )
    org = org_repo.get_org_by_id(db, org_id)
    assert org is not None
    return org, plaintext_key


def enable_customer_key_mode(db: Session, org_id: str, wrapping_public_pem: bytes) -> Org:
    """Switch an org to customer-key confidentiality: new content is wrapped to
    this public key and becomes dark to Attest. The org keeps the private key."""
    org = org_repo.get_org_by_id(db, org_id)
    if org is None:
        msg = f"org not found: {org_id}"
        raise LookupError(msg)
    org.confidentiality_mode = "customer_key"
    org.wrapping_public_pem = wrapping_public_pem.decode("utf-8")
    db.flush()
    return org


def update_org_settings(
    db: Session,
    org_id: str,
    *,
    region: str | None = None,
    fail_mode: str | None = None,
    retention_days_payload: int | None = None,
) -> Org:
    if region is not None:
        validate_region(region)
    if fail_mode is not None:
        validate_fail_mode(fail_mode)

    org = org_repo.update_org_settings(
        db,
        org_id,
        region=region,
        fail_mode=fail_mode,
        retention_days_payload=retention_days_payload,
    )
    if org is None:
        msg = f"org not found: {org_id}"
        raise LookupError(msg)
    return org
