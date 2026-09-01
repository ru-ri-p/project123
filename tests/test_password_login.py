"""Password login, attacked.

The promise: Argon2id-hashed passwords set only by someone who proved inbox
custody (code) or knows the current password; one generic failure for every
wrong login; a durable per-account lockout that codes can still bypass
(inbox custody beats a guesser); and a password change that kills every
other session. Each test tries to break one of those.
"""

from __future__ import annotations

import os
import uuid

import pytest

ADMIN_KEY = "test-admin-key"
A = {"x-admin-key": ADMIN_KEY}
GOOD_PW = "correct horse battery staple"


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


def _make_user(client) -> str:
    org_id = f"org_pw_{uuid.uuid4().hex[:8]}"
    client.post("/v1/admin/orgs", headers=A, json={"org_id": org_id, "name": "PW"})
    email = f"officer_{uuid.uuid4().hex[:8]}@example.test"
    r = client.post(f"/v1/auth/admin/orgs/{org_id}/users", headers=A,
                    json={"email": email, "display_name": "PW Officer"})
    assert r.status_code == 200, r.text
    return email


def _code_session(client, email: str) -> str:
    code = client.post("/v1/auth/request-code",
                       json={"email": email}).json()["dev_code"]
    r = client.post("/v1/auth/verify", json={"email": email, "code": code})
    assert r.status_code == 200
    return r.json()["token"]


def _onboard(client, email: str, password: str = GOOD_PW) -> None:
    """The invitation flow: code proves the inbox, then a password is chosen."""
    token = _code_session(client, email)
    r = client.post("/v1/auth/set-password",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"new_password": password})
    assert r.status_code == 200, r.text


def test_onboard_then_password_login_round_trip(client) -> None:
    email = _make_user(client)
    _onboard(client, email)

    r = client.post("/v1/auth/login", json={"email": email, "password": GOOD_PW})
    assert r.status_code == 200
    token = r.json()["token"]
    me = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["email"] == email


def test_every_failure_is_the_same_generic_401(client) -> None:
    email = _make_user(client)
    _onboard(client, email)

    wrong = client.post("/v1/auth/login",
                        json={"email": email, "password": "not-the-password"})
    nobody = client.post("/v1/auth/login",
                         json={"email": "ghost@example.test", "password": GOOD_PW})
    unset = client.post("/v1/auth/login",
                        json={"email": _make_user(client), "password": GOOD_PW})

    assert wrong.status_code == nobody.status_code == unset.status_code == 401
    assert wrong.json() == nobody.json() == unset.json(), (
        "unknown email, no password set, wrong password: indistinguishable"
    )


def test_lockout_after_repeated_failures_blocks_even_the_right_password(client) -> None:
    email = _make_user(client)
    _onboard(client, email)
    for _ in range(5):
        client.post("/v1/auth/login", json={"email": email, "password": "wrong-pw-x"})
    r = client.post("/v1/auth/login", json={"email": email, "password": GOOD_PW})
    assert r.status_code == 401, "locked: correct password buys nothing for 15 min"

    # But the inbox still works: a code session can reset and re-enter.
    token = _code_session(client, email)
    assert client.post("/v1/auth/set-password",
                       headers={"Authorization": f"Bearer {token}"},
                       json={"new_password": "a brand new sensible pw"},
                       ).status_code == 200
    r = client.post("/v1/auth/login",
                    json={"email": email, "password": "a brand new sensible pw"})
    assert r.status_code == 200, "reset clears the lockout for the real owner"


def test_password_change_requires_the_current_password(client) -> None:
    """A stolen session cookie must not be enough to take the account over."""
    email = _make_user(client)
    _onboard(client, email)
    token = client.post("/v1/auth/login",
                        json={"email": email, "password": GOOD_PW}).json()["token"]
    H = {"Authorization": f"Bearer {token}"}

    r = client.post("/v1/auth/set-password", headers=H,
                    json={"new_password": "attacker chosen password"})
    assert r.status_code == 403, "password-earned session, no current password: refused"

    r = client.post("/v1/auth/set-password", headers=H,
                    json={"new_password": "attacker chosen password",
                          "current_password": "wrong-guess-here"})
    assert r.status_code == 403

    r = client.post("/v1/auth/set-password", headers=H,
                    json={"new_password": "my next sensible password",
                          "current_password": GOOD_PW})
    assert r.status_code == 200, "knowing the current password: allowed"


def test_changing_the_password_kills_every_other_session(client) -> None:
    email = _make_user(client)
    _onboard(client, email)
    victim = client.post("/v1/auth/login",
                         json={"email": email, "password": GOOD_PW}).json()["token"]
    changer = client.post("/v1/auth/login",
                          json={"email": email, "password": GOOD_PW}).json()["token"]

    r = client.post("/v1/auth/set-password",
                    headers={"Authorization": f"Bearer {changer}"},
                    json={"new_password": "rotated after suspicion",
                          "current_password": GOOD_PW})
    assert r.status_code == 200

    assert client.get("/v1/auth/me",
                      headers={"Authorization": f"Bearer {victim}"},
                      ).status_code == 401, "the possibly-stolen session is dead"
    assert client.get("/v1/auth/me",
                      headers={"Authorization": f"Bearer {changer}"},
                      ).status_code == 200, "the session that rotated survives"


def test_password_policy_is_enforced_on_set(client) -> None:
    email = _make_user(client)
    token = _code_session(client, email)
    H = {"Authorization": f"Bearer {token}"}

    assert client.post("/v1/auth/set-password", headers=H,
                       json={"new_password": "short"}).status_code == 422
    assert client.post("/v1/auth/set-password", headers=H,
                       json={"new_password": email.ljust(12, "x") if len(email) < 12
                             else email}).status_code == 422, (
        "your email address is not a password"
    )
    # And login never enforces policy — whatever was set must keep working.


def test_wrong_login_attempts_persist_across_requests(client) -> None:
    """The lockout counter lives in the database, not process memory — a
    guesser cannot reset it by waiting for a restart or hitting another
    worker."""
    from app.db.models import User
    from app.db.session import SessionLocal

    email = _make_user(client)
    _onboard(client, email)
    for _ in range(3):
        client.post("/v1/auth/login", json={"email": email, "password": "nope-1"})

    db = SessionLocal()
    try:
        row = db.query(User).filter(User.email == email).one()
        assert row.failed_logins == 3
        assert row.password_hash != GOOD_PW and GOOD_PW not in (row.password_hash or "")
        assert row.password_hash.startswith("$argon2id$"), "argon2id, hash only"
    finally:
        db.close()
