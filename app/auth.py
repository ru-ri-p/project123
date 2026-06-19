"""API key hashing and org resolution."""

from __future__ import annotations

import hashlib

from sqlalchemy.orm import Session

from app.db.models import Org


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def resolve_org(db: Session, api_key: str) -> Org | None:
    """Map x-api-key header to org — every authenticated path uses this."""
    key_hash = hash_api_key(api_key)
    return db.query(Org).filter(Org.api_key_hash == key_hash).one_or_none()
