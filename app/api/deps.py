"""Shared FastAPI dependencies."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth import resolve_org
from app.config import get_settings
from app.db.models import Org, User
from app.db.session import get_db


def get_authenticated_org(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="x-api-key"),
    authorization: str | None = Header(default=None),
    attest_session: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> Org:
    """Org auth for data endpoints: the org API key, or a signed-in person.

    A key, when present, must be valid — a bad key never silently falls back
    to the cookie (the caller thinks they authenticated one way; failing the
    other way hides real misconfiguration). A session authenticates the
    user's own org; viewers get read-only (403 on writes) — finer per-route
    role gating belongs to the routes that need it (see approvals)."""
    if x_api_key:
        org = resolve_org(db, x_api_key)
        if org is None:
            raise HTTPException(status_code=401, detail="invalid api key")
        return org

    from app.services import human_auth

    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif attest_session:
        token = attest_session
    if token:
        user = human_auth.session_user(db, token)
        if user is not None:
            if user.role == "viewer" and request.method not in ("GET", "HEAD"):
                raise HTTPException(status_code=403, detail="viewer role is read-only")
            org = db.query(Org).filter(Org.id == user.org_id).one_or_none()
            if org is not None:
                return org
        raise HTTPException(status_code=401, detail="session invalid or expired")

    raise HTTPException(status_code=401, detail="not authenticated")


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
