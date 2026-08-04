"""The onboarding gate: no recording until obligations are declared.

Why gate at all
===============
Evidence recorded before anyone said which rules apply is evidence with no
yardstick. Declaring the profile first means every record from the very first one
was checked against a known set of obligations — and a firm cannot decide, after
seeing what its AI produced, which regulations it would like to have been subject
to.

Why it is not retroactive
=========================
Existing organisations are grandfathered (`requires_profile` False). Breaking a
live customer's integration because we shipped a gate would be the wrong trade:
they are prompted persistently in the console instead. Only organisations created
after the gate shipped are blocked.

Why this is NOT an outage
=========================
The SDK buffers when Attest is unreachable. A missing profile must therefore be
distinguishable from a network failure, or the buffer would fill with events that
can never be replayed. The response carries `code: "profile_required"` and the
SDK treats it as a configuration error: it does not buffer, does not retry, and
tells the developer what to do.
"""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.models import Org
from app.services.org_profile import get_profile

PROFILE_REQUIRED_CODE = "profile_required"
PROFILE_REQUIRED_MESSAGE = (
    "This organisation has not completed onboarding. Attest checks every AI "
    "output against the regulations that apply to you, so you must first declare "
    "where you are licensed and what sectors you operate in. Open the Attest "
    "console and complete Settings, then retry. Nothing is recorded until then."
)


def profile_is_complete(db: Session, org: Org) -> bool:
    profile = get_profile(db, org.id)
    return bool(profile and profile.jurisdictions and profile.sectors)


def require_onboarded(db: Session, org: Org) -> None:
    """Raise 409 if this org must onboard first. No-op for grandfathered orgs."""
    if not org.requires_profile:
        return
    if profile_is_complete(db, org):
        return
    raise HTTPException(
        status_code=409,
        detail={
            "code": PROFILE_REQUIRED_CODE,
            "message": PROFILE_REQUIRED_MESSAGE,
            "settings_path": "/console#settings",
        },
    )
