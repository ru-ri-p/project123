"""Shared FastAPI dependencies."""

from __future__ import annotations

import secrets

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.auth import resolve_org
from app.config import get_settings
from app.db.models import Org
from app.db.session import get_db


def get_authenticated_org(
    x_api_key: str = Header(..., alias="x-api-key"),
    db: Session = Depends(get_db),
) -> Org:
    org = resolve_org(db, x_api_key)
    if org is None:
        raise HTTPException(status_code=401, detail="invalid api key")
    return org


def require_admin(x_admin_key: str = Header(..., alias="x-admin-key")) -> None:
    """Attest-ops auth for the access-review console. Constant-time key compare."""
    admin_key = get_settings().admin_api_key
    if not admin_key:
        raise HTTPException(status_code=503, detail="admin api disabled")
    if not secrets.compare_digest(x_admin_key, admin_key):
        raise HTTPException(status_code=401, detail="invalid admin key")
