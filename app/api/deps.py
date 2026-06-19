"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.auth import resolve_org
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
