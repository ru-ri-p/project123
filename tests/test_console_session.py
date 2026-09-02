"""The console's session door, attacked at the API level.

The promise: a signed-in person can use every console data endpoint with no
API key (the cookie is enough); their role is respected (viewer = read-only);
sign-out really ends it; and the login page itself is served. The browser is
simulated by the test client's cookie jar.
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


def _org_and_user(client, role: str = "officer") -> tuple[str, str]:
    org_id = f"org_cs_{uuid.uuid4().hex[:8]}"
    client.post("/v1/admin/orgs", headers=A, json={"org_id": org_id, "name": "CS"})
    email = f"{role}_{uuid.uuid4().hex[:8]}@example.test"
    client.post(f"/v1/auth/admin/orgs/{org_id}/users", headers=A,
                json={"email": email, "display_name": "Console Person",
                      "role": role})
    return org_id, email


def _sign_in(client, email: str) -> None:
    """Cookie-based sign-in, exactly as the login page does it."""
    code = client.post("/v1/auth/request-code",
                       json={"email": email}).json()["dev_code"]
    r = client.post("/v1/auth/verify", json={"email": email, "code": code})
    assert r.status_code == 200
    assert "attest_session" in r.cookies, "the session rides as a cookie"


def test_login_page_is_served(client) -> None:
    r = client.get("/login")
    assert r.status_code == 200
    assert "Sign in" in r.text and "/v1/auth/login" in r.text


def test_signed_in_officer_reads_org_data_with_cookie_only(client) -> None:
    org_id, email = _org_and_user(client)
    _sign_in(client, email)

    ov = client.get("/v1/org/overview")  # NO x-api-key header
    assert ov.status_code == 200
    assert ov.json()["org_id"] == org_id, "the session resolves to their org"

    me = client.get("/v1/auth/me")
    assert me.json()["email"] == email


def test_viewer_is_read_only_through_the_session_door(client) -> None:
    org_id, email = _org_and_user(client, role="viewer")
    _sign_in(client, email)

    assert client.get("/v1/org/overview").status_code == 200, "reading: fine"
    r = client.put("/v1/policies/profile",
                   json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    assert r.status_code == 403, "writing through a viewer session: refused"


def test_officer_can_write_through_the_session(client) -> None:
    org_id, email = _org_and_user(client, role="officer")
    _sign_in(client, email)
    r = client.put("/v1/policies/profile",
                   json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    assert r.status_code == 200, r.text


def test_signout_closes_the_console(client) -> None:
    _, email = _org_and_user(client)
    _sign_in(client, email)
    assert client.get("/v1/org/overview").status_code == 200
    client.post("/v1/auth/logout")
    assert client.get("/v1/org/overview").status_code == 401, (
        "after sign-out the cookie is a dead token, server-side"
    )


def test_a_bad_api_key_never_falls_back_to_the_cookie(client) -> None:
    """Someone pasted a wrong key while signed in: the key must fail loudly,
    not silently succeed as the cookie identity — that would mask real
    misconfiguration in their integration."""
    _, email = _org_and_user(client)
    _sign_in(client, email)
    r = client.get("/v1/org/overview", headers={"x-api-key": "wrong-key"})
    assert r.status_code == 401
