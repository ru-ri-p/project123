"""Human login routes — the dashboard's front door.

Failure discipline: every login failure is the same 401 ("invalid or expired
code") and every request-code call gets the same generic 200 — the API never
confirms whether an email has an account. In production without an email
provider, request-code is an explicit 503 rather than a silent black hole;
AUTH_DEV_MODE=1 (development only) returns the code inline instead.
"""

from __future__ import annotations

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.models import User
from app.db.session import get_db
from app.schemas import (
    AdminCreateUserIn,
    AuthLoginIn,
    AuthRequestCodeIn,
    AuthSessionOut,
    AuthSetPasswordIn,
    AuthUserOut,
    AuthVerifyIn,
)
from app.services import human_auth

router = APIRouter(prefix="/v1/auth", tags=["auth"])

SESSION_COOKIE = "attest_session"


def _bearer_token(
    authorization: str | None, cookie_token: str | None
) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return cookie_token or ""


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=not human_auth.dev_mode(),
        max_age=human_auth.SESSION_TTL_HOURS * 3600,
    )


def _user_out(user: User) -> AuthUserOut:
    return AuthUserOut(
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        org_id=user.org_id,
    )


@router.post("/request-code")
def request_code(
    body: AuthRequestCodeIn, db: Session = Depends(get_db)
) -> dict[str, object]:
    if not human_auth.dev_mode():
        # TODO(EMAIL): wire a provider (needs a sending domain + SPF/DKIM),
        # then deliver the code by email and return the generic body below.
        raise HTTPException(
            status_code=503,
            detail="email delivery not configured; login is unavailable",
        )
    code = human_auth.request_code(db, body.email)
    db.commit()
    out: dict[str, object] = {"ok": True}
    if code is not None:
        # DEV MODE ONLY: inline delivery so the pipeline is testable without
        # a domain or provider. dev_mode() documents why this must stay off
        # in production.
        out["dev_code"] = code
    return out


@router.post("/verify", response_model=AuthSessionOut)
def verify(
    body: AuthVerifyIn, response: Response, db: Session = Depends(get_db)
) -> AuthSessionOut:
    result = human_auth.verify_code(db, body.email, body.code)
    db.commit()
    if result is None:
        raise HTTPException(status_code=401, detail="invalid or expired code")
    user, token, expires_at = result
    _set_session_cookie(response, token)
    return AuthSessionOut(
        user=_user_out(user), token=token, expires_at=expires_at.isoformat()
    )


@router.post("/login", response_model=AuthSessionOut)
def login(
    body: AuthLoginIn, response: Response, db: Session = Depends(get_db)
) -> AuthSessionOut:
    """Email + password. One generic 401 for every failure mode — unknown
    email, no password set, wrong password, locked, disabled — so nothing is
    learnable from the error. Lockout details live in the service."""
    result = human_auth.login_password(db, body.email, body.password)
    db.commit()  # failed attempts / lockouts must persist even on 401
    if result is None:
        raise HTTPException(status_code=401, detail="invalid email or password")
    user, token, expires_at = result
    _set_session_cookie(response, token)
    return AuthSessionOut(
        user=_user_out(user), token=token, expires_at=expires_at.isoformat()
    )


@router.post("/set-password")
def set_password(
    body: AuthSetPasswordIn,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    attest_session: str | None = Cookie(default=None),
) -> dict[str, bool]:
    """Set (first time / after reset-by-code) or change (knowing the current
    one) the signed-in user's password. Every other session is revoked."""
    found = human_auth.session_with_user(
        db, _bearer_token(authorization, attest_session)
    )
    if found is None:
        raise HTTPException(status_code=401, detail="not signed in")
    user, session = found
    try:
        human_auth.set_password(
            db,
            user=user,
            session=session,
            new_password=body.new_password,
            current_password=body.current_password,
        )
    except human_auth.PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except human_auth.WrongCurrentPasswordError:
        raise HTTPException(
            status_code=403, detail="current password required and must match"
        ) from None
    db.commit()
    return {"ok": True}


@router.get("/me", response_model=AuthUserOut)
def me(
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    attest_session: str | None = Cookie(default=None),
) -> AuthUserOut:
    user = human_auth.session_user(db, _bearer_token(authorization, attest_session))
    if user is None:
        raise HTTPException(status_code=401, detail="not signed in")
    return _user_out(user)


@router.post("/logout")
def logout(
    response: Response,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    attest_session: str | None = Cookie(default=None),
) -> dict[str, bool]:
    revoked = human_auth.revoke_session(
        db, _bearer_token(authorization, attest_session)
    )
    db.commit()
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True, "revoked": revoked}


# Provisioning is an Attest-ops action for the pilot: we create the customer's
# first users at onboarding. Org-admin self-service comes once roles are
# exercised in anger.
@router.post(
    "/admin/orgs/{org_id}/users",
    response_model=AuthUserOut,
    dependencies=[Depends(require_admin)],
)
def admin_create_user(
    org_id: str, body: AdminCreateUserIn, db: Session = Depends(get_db)
) -> AuthUserOut:
    from app.db.models import Org

    if db.query(Org).filter(Org.id == org_id).one_or_none() is None:
        raise HTTPException(status_code=404, detail="unknown org")
    try:
        user = human_auth.create_user(
            db,
            org_id=org_id,
            email=body.email,
            display_name=body.display_name,
            role=body.role,
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="email already registered") from None
    return _user_out(user)
