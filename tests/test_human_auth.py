"""Human login, attacked.

The promise: passwordless email+code login where a code is short-lived,
single-use, attempt-capped, and never confirms whether an email has an
account; sessions are revocable; dev mode is the only way codes travel
inline, and production without email delivery fails loudly, not silently.
Each test tries to break one of those.
"""

from __future__ import annotations

import os
import uuid

import pytest

ADMIN_KEY = "test-admin-key"
A = {"x-admin-key": ADMIN_KEY}


@pytest.fixture(scope="module", autouse=True)
def _env():
    os.environ["ADMIN_API_KEY"] = ADMIN_KEY
    os.environ["AUTH_DEV_MODE"] = "1"
    from app.config import get_settings

    get_settings.cache_clear()
    yield
    del os.environ["ADMIN_API_KEY"]
    del os.environ["AUTH_DEV_MODE"]
    get_settings.cache_clear()


@pytest.fixture()
def client(db_available: bool):
    if not db_available:
        pytest.skip("PostgreSQL not available")
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


def _make_user(client, role: str = "officer") -> tuple[str, str]:
    """Create an org + user; returns (org_id, email)."""
    org_id = f"org_ha_{uuid.uuid4().hex[:8]}"
    client.post("/v1/admin/orgs", headers=A, json={"org_id": org_id, "name": "HA"})
    email = f"officer_{uuid.uuid4().hex[:8]}@example.test"
    r = client.post(f"/v1/auth/admin/orgs/{org_id}/users", headers=A,
                    json={"email": email, "display_name": "Test Officer",
                          "role": role})
    assert r.status_code == 200, r.text
    return org_id, email


def _login(client, email: str) -> dict:
    code = client.post("/v1/auth/request-code",
                       json={"email": email}).json()["dev_code"]
    r = client.post("/v1/auth/verify", json={"email": email, "code": code})
    assert r.status_code == 200, r.text
    return r.json()


def test_full_login_round_trip(client) -> None:
    org_id, email = _make_user(client)
    session = _login(client, email)

    assert session["user"]["email"] == email
    assert session["user"]["org_id"] == org_id
    assert session["user"]["role"] == "officer"

    me = client.get("/v1/auth/me",
                    headers={"Authorization": f"Bearer {session['token']}"})
    assert me.status_code == 200
    assert me.json()["email"] == email


def test_unknown_email_gets_the_same_friendly_nothing(client) -> None:
    """No user enumeration: an address with no account must not be
    distinguishable by status code or error."""
    r = client.post("/v1/auth/request-code",
                    json={"email": "nobody@example.test"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert "dev_code" not in r.json() or r.json().get("dev_code") is None


def test_wrong_guesses_burn_the_code_even_for_its_owner(client) -> None:
    _, email = _make_user(client)
    code = client.post("/v1/auth/request-code",
                       json={"email": email}).json()["dev_code"]
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        r = client.post("/v1/auth/verify", json={"email": email, "code": wrong})
        assert r.status_code == 401
    # Sixth attempt with the RIGHT code: too late, the code is burnt.
    r = client.post("/v1/auth/verify", json={"email": email, "code": code})
    assert r.status_code == 401, "attempt cap holds even against the real code"


def test_a_code_dies_on_first_use(client) -> None:
    _, email = _make_user(client)
    code = client.post("/v1/auth/request-code",
                       json={"email": email}).json()["dev_code"]
    assert client.post("/v1/auth/verify",
                       json={"email": email, "code": code}).status_code == 200
    r = client.post("/v1/auth/verify", json={"email": email, "code": code})
    assert r.status_code == 401, "replaying a used code yields nothing"


def test_a_new_code_voids_the_old_one(client) -> None:
    _, email = _make_user(client)
    old = client.post("/v1/auth/request-code",
                      json={"email": email}).json()["dev_code"]
    new = client.post("/v1/auth/request-code",
                      json={"email": email}).json()["dev_code"]
    assert client.post("/v1/auth/verify",
                       json={"email": email, "code": old}).status_code == 401
    assert client.post("/v1/auth/verify",
                       json={"email": email, "code": new}).status_code == 200


def test_issuance_is_capped_per_window(client) -> None:
    """An attacker cannot farm fresh codes to reset the guess budget."""
    _, email = _make_user(client)
    granted = 0
    for _ in range(5):
        body = client.post("/v1/auth/request-code",
                           json={"email": email}).json()
        if "dev_code" in body:
            granted += 1
    assert granted == 3, "3 per window, then the same generic silence"


def test_logout_revokes_server_side(client) -> None:
    _, email = _make_user(client)
    token = _login(client, email)["token"]
    H = {"Authorization": f"Bearer {token}"}
    assert client.get("/v1/auth/me", headers=H).status_code == 200
    assert client.post("/v1/auth/logout", headers=H).json()["revoked"] is True
    assert client.get("/v1/auth/me", headers=H).status_code == 401, (
        "a revoked session is dead even if the bearer token survives"
    )


def test_expired_code_is_worthless(client) -> None:
    from datetime import UTC, datetime, timedelta

    from app.db.models import LoginCode, User
    from app.db.session import SessionLocal

    _, email = _make_user(client)
    code = client.post("/v1/auth/request-code",
                       json={"email": email}).json()["dev_code"]
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        db.query(LoginCode).filter(LoginCode.user_id == user.id).update(
            {LoginCode.expires_at: datetime.now(UTC) - timedelta(minutes=1)}
        )
        db.commit()
    finally:
        db.close()
    r = client.post("/v1/auth/verify", json={"email": email, "code": code})
    assert r.status_code == 401


def test_production_without_email_fails_loudly(client, monkeypatch) -> None:
    """No dev mode + no provider must be an explicit 503 — a login page that
    silently never delivers would be debugged for days."""
    monkeypatch.delenv("AUTH_DEV_MODE", raising=False)
    r = client.post("/v1/auth/request-code",
                    json={"email": "anyone@example.test"})
    assert r.status_code == 503


def test_provisioning_is_admin_only_and_validated(client) -> None:
    org_id, email = _make_user(client)

    # No admin key -> no user creation.
    r = client.post(f"/v1/auth/admin/orgs/{org_id}/users",
                    json={"email": "x@example.test", "display_name": "X"})
    assert r.status_code in (401, 422)

    # Duplicate email -> 409, not a second identity.
    r = client.post(f"/v1/auth/admin/orgs/{org_id}/users", headers=A,
                    json={"email": email, "display_name": "Dup"})
    assert r.status_code == 409

    # Made-up role -> rejected by the schema.
    r = client.post(f"/v1/auth/admin/orgs/{org_id}/users", headers=A,
                    json={"email": "y@example.test", "display_name": "Y",
                          "role": "superuser"})
    assert r.status_code == 422

    # Unknown org -> 404.
    r = client.post("/v1/auth/admin/orgs/org_never_existed/users", headers=A,
                    json={"email": "z@example.test", "display_name": "Z"})
    assert r.status_code == 404


def test_disabled_user_is_fully_dead(client) -> None:
    from app.db.models import User
    from app.db.session import SessionLocal

    _, email = _make_user(client)
    token = _login(client, email)["token"]

    db = SessionLocal()
    try:
        db.query(User).filter(User.email == email).update({User.disabled: True})
        db.commit()
    finally:
        db.close()

    r = client.post("/v1/auth/request-code", json={"email": email})
    assert "dev_code" not in r.json(), "no new codes for a disabled account"
    assert client.get(
        "/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 401, "existing sessions die with the account"
