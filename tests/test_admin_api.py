"""Admin API (x-admin-key): auth, org management, request oversight, trace tools.

Also guards the no-secret-leakage rule: admin responses must never contain the
grantee private key or any api_key_hash.
"""

from __future__ import annotations

import os
import uuid

import pytest

ADMIN_KEY = "test-admin-key"


@pytest.fixture(scope="module", autouse=True)
def _admin_env():
    os.environ["ADMIN_API_KEY"] = ADMIN_KEY
    from app.config import get_settings

    get_settings.cache_clear()
    yield
    del os.environ["ADMIN_API_KEY"]
    get_settings.cache_clear()


@pytest.fixture()
def client(db_available: bool):
    if not db_available:
        pytest.skip("PostgreSQL not available")
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


A = {"x-admin-key": ADMIN_KEY}


def test_admin_auth_required(client) -> None:
    assert client.get("/v1/admin/ping").status_code == 422  # header missing
    assert client.get("/v1/admin/ping", headers={"x-admin-key": "nope"}).status_code == 401
    assert client.get("/v1/admin/ping", headers=A).json() == {"ok": True}


def test_org_create_rotate_and_list(client) -> None:
    org_id = f"org_adm_{uuid.uuid4().hex[:10]}"
    r = client.post("/v1/admin/orgs", headers=A, json={"org_id": org_id, "name": "Adm Test"})
    assert r.status_code == 200, r.text
    first_key = r.json()["api_key"]
    assert first_key and r.json()["org_id"] == org_id

    # Duplicate id -> 409, not a 500.
    r = client.post("/v1/admin/orgs", headers=A, json={"org_id": org_id, "name": "Dup"})
    assert r.status_code == 409

    r = client.post(f"/v1/admin/orgs/{org_id}/rotate-key", headers=A)
    assert r.status_code == 200
    second_key = r.json()["api_key"]
    assert second_key != first_key

    # Old key dead, new key lives.
    assert client.get("/v1/org/me", headers={"x-api-key": first_key}).status_code == 401
    me = client.get("/v1/org/me", headers={"x-api-key": second_key})
    assert me.status_code == 200 and me.json()["id"] == org_id

    listed = client.get("/v1/admin/orgs", headers=A).json()
    assert any(o["id"] == org_id for o in listed)
    assert all("api_key_hash" not in o for o in listed)

    assert client.post("/v1/admin/orgs/nope_no_such/rotate-key", headers=A).status_code == 404


def test_request_oversight_and_trace_tools(client) -> None:
    org_id = f"org_adm_{uuid.uuid4().hex[:10]}"
    key = client.post(
        "/v1/admin/orgs", headers=A, json={"org_id": org_id, "name": "Oversight"}
    ).json()["api_key"]

    trace = str(uuid.uuid4())
    for seq in (1, 2):
        r = client.post("/v1/event", headers={"x-api-key": key}, json={
            "trace_id": trace, "seq": seq, "type": "model_completion",
            "payload": {"n": seq}})
        assert r.status_code == 200, r.text

    events = client.get(f"/v1/admin/traces/{trace}/events", headers=A).json()
    assert [e["seq"] for e in events] == [1, 2]
    h1 = events[0]["payload_hash"]

    replay = client.get(f"/v1/admin/traces/{trace}/replay", headers=A).json()
    assert replay["all_verified"] is True

    r = client.post("/v1/admin/access-requests", headers=A, json={
        "org_id": org_id, "payload_hashes": [h1], "reason": "admin ui test"})
    assert r.status_code == 200, r.text
    req_id = r.json()["request_id"]

    listed = client.get(f"/v1/admin/access-requests?org_id={org_id}", headers=A).json()
    assert [x["request_id"] for x in listed] == [req_id]
    assert listed[0]["requested_by"] == "attest_admin"

    detail = client.get(f"/v1/admin/access-requests/{req_id}", headers=A).json()
    assert detail["scope"] == [{"payload_hash": h1, "released": False}]
    assert detail["trace_id"] is not None
    assert "grantee_private_pem" not in detail

    # The consent trail is itself a verifiable trace via the admin tools.
    trail = client.get(f"/v1/admin/traces/{detail['trace_id']}/events", headers=A).json()
    assert [e["type"] for e in trail] == ["access_request"]
    trail_replay = client.get(
        f"/v1/admin/traces/{detail['trace_id']}/replay", headers=A
    ).json()
    assert trail_replay["all_verified"] is True

    assert client.get(f"/v1/admin/traces/{uuid.uuid4()}/events", headers=A).status_code == 404
    assert client.get("/v1/admin/traces/not-a-uuid/events", headers=A).status_code == 422


def test_admin_dashboard_served_and_self_contained(client) -> None:
    res = client.get("/admin")
    assert res.status_code == 200
    assert "Ops Control Room" in res.text
    for marker in ("<script src=", "https://cdn", "googleapis.com"):
        assert marker not in res.text
    # The regulatory type system is embedded, not fetched.
    assert "Fraunces" in res.text and "data:font/woff2;base64," in res.text
