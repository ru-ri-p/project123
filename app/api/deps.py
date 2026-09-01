"""Shared FastAPI dependencies."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from fastapi import Cookie, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.auth import resolve_org
from app.config import get_settings
from app.db.models import Org, User
from app.db.session import get_db


def get_authenticated_org(
    x_api_key: str = Header(..., alias="x-api-key"),
    db: Session = Depends(get_db),
) -> Org:
    org = resolve_org(db, x_api_key)
    if org is None:
        raise HTTPException(status_code=401, detail="invalid api key")
    return org


@dataclass(frozen=True)
class Actor:
    """Who is calling: always an org; a User too when a person is signed in.

    `user` set  -> a session-authenticated human (identity is PROVEN).
    `user` None -> the org's machine key (identity, if supplied, is asserted).
    """

    org: Org
    user: User | None


def get_actor(
    db: Session = Depends(get_db),
    x_api_key: str | None = Header(default=None, alias="x-api-key"),
    authorization: str | None = Header(default=None),
    attest_session: str | None = Cookie(default=None),
) -> Actor:
    """Accept EITHER a human session or the org API key, preferring the human:
    when both are present the request is attributed to the person, because a
    person in the room is always the stronger identity claim."""
    from app.services import human_auth

    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif attest_session:
        token = attest_session
    if token:
        user = human_auth.session_user(db, token)
        if user is not None:
            org = db.query(Org).filter(Org.id == user.org_id).one_or_none()
            if org is not None:
                return Actor(org=org, user=user)
        # An invalid/expired session must fail loudly, not silently fall back
        # to the machine key — the caller thinks a person is signed in.
        raise HTTPException(status_code=401, detail="session invalid or expired")

    if x_api_key:
        org = resolve_org(db, x_api_key)
        if org is not None:
            return Actor(org=org, user=None)
    raise HTTPException(status_code=401, detail="not authenticated")


def require_admin(x_admin_key: str = Header(..., alias="x-admin-key")) -> None:
    """Attest-ops auth for the access-review console. Constant-time key compare."""
    admin_key = get_settings().admin_api_key
    if not admin_key:
        raise HTTPException(status_code=503, detail="admin api disabled")
    if not secrets.compare_digest(x_admin_key, admin_key):
        raise HTTPException(status_code=401, detail="invalid admin key")
