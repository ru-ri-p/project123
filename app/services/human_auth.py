"""Passwordless human login — email + one-time code, sessions, roles.

WHY THIS SHAPE
==============
Dashboard users are PEOPLE (compliance officers approving actions), distinct
from the org API key their software uses. We deliberately store no passwords:
a 6-digit one-time code is emailed (or, in development, returned inline), so
there is no password database to breach, rotate, or be embarrassed by.

What makes a 6-digit code safe enough for its lifetime:
- stored only as SHA-256 — a DB read yields no usable code;
- expires in CODE_TTL_MINUTES; dead on first successful use;
- at most MAX_ATTEMPTS guesses, counted BEFORE comparison — then it burns;
- issuing a new code voids the old ones, and issuance is capped per user
  per window, so an attacker cannot farm fresh chances.

Sessions are 256-bit random bearer tokens, stored hashed, expiring, and
revocable server-side (logout works even if the cookie survives).

DELIVERY
========
Email delivery is TODO(EMAIL): it needs a sending domain (SPF/DKIM) the
project does not have yet. Until then the pipeline runs end-to-end only with
AUTH_DEV_MODE=1, where request_code returns the code to the caller — for
tests and local development ONLY. The route layer refuses to pretend
otherwise in production: without dev mode and without a provider, login is
explicitly 503, never silently broken.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.db.models import AuthSession, LoginCode, User

CODE_TTL_MINUTES = int(os.environ.get("AUTH_CODE_TTL_MINUTES", "10"))
MAX_ATTEMPTS = int(os.environ.get("AUTH_CODE_MAX_ATTEMPTS", "5"))
SESSION_TTL_HOURS = int(os.environ.get("AUTH_SESSION_TTL_HOURS", "12"))
# How many codes one user may be issued inside one TTL window. Caps an
# attacker's total guess budget at MAX_ATTEMPTS * MAX_OUTSTANDING per window.
MAX_ISSUED_PER_WINDOW = int(os.environ.get("AUTH_CODES_PER_WINDOW", "3"))

ROLES = ("admin", "officer", "viewer")


def dev_mode() -> bool:
    """Development switch: codes are returned inline instead of emailed.

    Never enable in production — it turns "can receive email at the address"
    into "can call the API", which is no authentication at all.
    """
    return os.environ.get("AUTH_DEV_MODE") == "1"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def find_user(db: Session, email: str) -> User | None:
    return (
        db.query(User)
        .filter(User.email == email.strip().lower(), User.disabled.is_(False))
        .one_or_none()
    )


def request_code(db: Session, email: str) -> str | None:
    """Issue a one-time code for this email, or None (unknown user / capped).

    The caller must answer identically either way — the response never says
    whether an email address has an account (no user enumeration).
    """
    user = find_user(db, email)
    if user is None:
        return None

    window_start = _now() - timedelta(minutes=CODE_TTL_MINUTES)
    issued_recently = (
        db.query(LoginCode)
        .filter(LoginCode.user_id == user.id, LoginCode.created_at >= window_start)
        .count()
    )
    if issued_recently >= MAX_ISSUED_PER_WINDOW:
        return None  # silently: the generic response leaks nothing

    # A new code voids every outstanding one — only the latest is guessable.
    db.query(LoginCode).filter(
        LoginCode.user_id == user.id, LoginCode.used_at.is_(None)
    ).update({LoginCode.used_at: _now()})

    code = f"{secrets.randbelow(1_000_000):06d}"
    db.add(
        LoginCode(
            user_id=user.id,
            code_hash=_sha256(code),
            expires_at=_now() + timedelta(minutes=CODE_TTL_MINUTES),
        )
    )
    db.flush()
    return code


def verify_code(db: Session, email: str, code: str) -> tuple[User, str, datetime] | None:
    """Trade a valid (email, code) for a session. None on ANY failure —
    the caller reports one generic 'invalid or expired code'."""
    user = find_user(db, email)
    if user is None:
        return None

    candidate = (
        db.query(LoginCode)
        .filter(
            LoginCode.user_id == user.id,
            LoginCode.used_at.is_(None),
            LoginCode.expires_at > _now(),
        )
        .order_by(LoginCode.created_at.desc())
        .first()
    )
    if candidate is None:
        return None

    # Spend the attempt BEFORE comparing, and persist it even though the
    # request will "fail" — a wrong guess must never be free.
    candidate.attempts += 1
    db.flush()
    if candidate.attempts > MAX_ATTEMPTS:
        return None
    if not secrets.compare_digest(candidate.code_hash, _sha256(code)):
        return None

    candidate.used_at = _now()
    token = secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(hours=SESSION_TTL_HOURS)
    db.add(AuthSession(user_id=user.id, token_hash=_sha256(token), expires_at=expires_at))
    db.flush()
    return user, token, expires_at


def session_user(db: Session, token: str) -> User | None:
    """The live user behind a bearer token, or None."""
    if not token:
        return None
    row = (
        db.query(AuthSession)
        .filter(
            AuthSession.token_hash == _sha256(token),
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > _now(),
        )
        .one_or_none()
    )
    if row is None:
        return None
    user = db.query(User).filter(User.id == row.user_id, User.disabled.is_(False)).one_or_none()
    return user


def revoke_session(db: Session, token: str) -> bool:
    row = (
        db.query(AuthSession)
        .filter(AuthSession.token_hash == _sha256(token), AuthSession.revoked_at.is_(None))
        .one_or_none()
    )
    if row is None:
        return False
    row.revoked_at = _now()
    db.flush()
    return True


def create_user(
    db: Session, *, org_id: str, email: str, display_name: str, role: str
) -> User:
    if role not in ROLES:
        msg = f"role must be one of {ROLES}"
        raise ValueError(msg)
    user = User(
        org_id=org_id,
        email=email.strip().lower(),
        display_name=display_name.strip(),
        role=role,
    )
    db.add(user)
    db.flush()
    return user
