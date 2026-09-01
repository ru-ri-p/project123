"""Human login — email + password, with one-time codes for invitation/reset.

WHY THIS SHAPE
==============
Dashboard users are PEOPLE (compliance officers approving actions), distinct
from the org API key their software uses. Day-to-day login is email +
password — the model every client expects. The one-time-code flow stays as
the BOOTSTRAP and RESET path: a code proves custody of the inbox, which is
exactly the proof a password reset needs, so invitations and resets are the
same mechanism instead of two.

PASSWORD RULES (and the reasoning)
==================================
- Argon2id hashes only (memory-hard; GPUs don't shortcut it). The password
  itself never touches a log, an event, or a column.
- Length is the policy: 12+ characters, anything printable, no composition
  theatre (NIST 800-63B). TODO(BREACH-LIST): screen against known-breached
  passwords once an offline corpus is bundled.
- Online guessing is braked twice: per-account lockout (LOCKOUT_THRESHOLD
  failures -> LOCKOUT_MINUTES cool-off, all server-side and durable) on top
  of the API-wide rate limiter.
- Unknown email and wrong password are the SAME generic failure, and unknown
  emails still burn an Argon2 verification (against a dummy hash) so timing
  does not betray which addresses exist.
- Changing a password requires the current one — unless the session was
  earned via emailed code (the reset path, where inbox custody IS the proof).
  Every other session dies on change: a stolen cookie does not survive the
  victim rotating their password.

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

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy.orm import Session

from app.db.models import AuthSession, LoginCode, User

CODE_TTL_MINUTES = int(os.environ.get("AUTH_CODE_TTL_MINUTES", "10"))
MAX_ATTEMPTS = int(os.environ.get("AUTH_CODE_MAX_ATTEMPTS", "5"))
SESSION_TTL_HOURS = int(os.environ.get("AUTH_SESSION_TTL_HOURS", "12"))
# How many codes one user may be issued inside one TTL window. Caps an
# attacker's total guess budget at MAX_ATTEMPTS * MAX_OUTSTANDING per window.
MAX_ISSUED_PER_WINDOW = int(os.environ.get("AUTH_CODES_PER_WINDOW", "3"))
# Per-account online-guessing brake for password login.
LOCKOUT_THRESHOLD = int(os.environ.get("AUTH_LOCKOUT_THRESHOLD", "5"))
LOCKOUT_MINUTES = int(os.environ.get("AUTH_LOCKOUT_MINUTES", "15"))
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128  # hashing-cost cap; nobody types more anyway

ROLES = ("admin", "officer", "viewer")

_ph = PasswordHasher()  # argon2id with library-maintained parameters
# Burned for unknown emails so "no such user" and "wrong password" take the
# same time. Module-level: hashed once, not per request.
_DUMMY_HASH = _ph.hash("timing-equalizer-not-a-real-credential")


class PasswordPolicyError(ValueError):
    """The proposed password fails policy; message is safe to show."""


class WrongCurrentPasswordError(Exception):
    """Password change refused: the current password did not verify."""


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
    return user, *_create_session(db, user, method="code")


def _create_session(db: Session, user: User, *, method: str) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(hours=SESSION_TTL_HOURS)
    db.add(
        AuthSession(
            user_id=user.id,
            token_hash=_sha256(token),
            method=method,
            expires_at=expires_at,
        )
    )
    db.flush()
    return token, expires_at


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


# --- passwords --------------------------------------------------------------


def session_with_user(db: Session, token: str) -> tuple[User, AuthSession] | None:
    """Like session_user, but also returns the session row — callers that
    care HOW the session was earned (password change vs reset) need it."""
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
    user = (
        db.query(User).filter(User.id == row.user_id, User.disabled.is_(False)).one_or_none()
    )
    if user is None:
        return None
    return user, row


def validate_password(password: str, *, email: str) -> None:
    """Length-first policy (NIST 800-63B): no composition theatre."""
    if len(password) < PASSWORD_MIN_LENGTH:
        msg = f"password must be at least {PASSWORD_MIN_LENGTH} characters"
        raise PasswordPolicyError(msg)
    if len(password) > PASSWORD_MAX_LENGTH:
        msg = f"password must be at most {PASSWORD_MAX_LENGTH} characters"
        raise PasswordPolicyError(msg)
    if password.strip().lower() == email.strip().lower():
        msg = "password must not be your email address"
        raise PasswordPolicyError(msg)


def _burn_dummy_verification() -> None:
    """Spend the same Argon2 work a real check would, so response timing does
    not reveal whether the email exists or has a password."""
    try:
        _ph.verify(_DUMMY_HASH, "wrong-on-purpose")
    except VerifyMismatchError:
        pass


def login_password(db: Session, email: str, password: str) -> tuple[User, str, datetime] | None:
    """Trade (email, password) for a session. None on ANY failure — unknown
    email, no password set, wrong password, locked, disabled — and the caller
    reports one generic 401 for all of them."""
    user = find_user(db, email)
    if user is None or user.password_hash is None:
        _burn_dummy_verification()
        return None
    if user.locked_until is not None and user.locked_until > _now():
        _burn_dummy_verification()  # locked looks exactly like wrong
        return None

    try:
        _ph.verify(user.password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        user.failed_logins += 1
        if user.failed_logins >= LOCKOUT_THRESHOLD:
            # Cool-off, then the counter starts fresh. Codes still work while
            # locked: inbox custody beats a guesser, and the legitimate owner
            # is never locked out of their own account entirely.
            user.locked_until = _now() + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_logins = 0
        db.flush()
        return None

    if _ph.check_needs_rehash(user.password_hash):
        user.password_hash = _ph.hash(password)  # transparent parameter upgrades
    user.failed_logins = 0
    user.locked_until = None
    return user, *_create_session(db, user, method="password")


def set_password(
    db: Session,
    *,
    user: User,
    session: AuthSession,
    new_password: str,
    current_password: str | None,
) -> None:
    """Set or change the password for the session's own user.

    Custody rules: a session earned by PASSWORD must prove it still knows the
    current password (a stolen cookie must not be enough to take the account
    over). A session earned by CODE just proved inbox custody — that IS the
    reset credential, so no current password is required (there may be none).
    Every OTHER session dies on change; the one making the change survives.
    """
    validate_password(new_password, email=user.email)
    if user.password_hash is not None and session.method == "password":
        if not current_password:
            raise WrongCurrentPasswordError
        try:
            _ph.verify(user.password_hash, current_password)
        except (VerifyMismatchError, InvalidHashError):
            raise WrongCurrentPasswordError from None

    user.password_hash = _ph.hash(new_password)
    user.failed_logins = 0
    user.locked_until = None
    db.query(AuthSession).filter(
        AuthSession.user_id == user.id,
        AuthSession.id != session.id,
        AuthSession.revoked_at.is_(None),
    ).update({AuthSession.revoked_at: _now()})
    db.flush()
