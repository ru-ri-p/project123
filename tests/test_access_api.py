"""Slice 5a: the consent flow over HTTP.

Drives the whole ceremony through the API: org goes customer-key, records dark
events, Attest (admin) files a request, the org (acting as its own client)
releases only the in-scope key and approves, and Attest reads exactly that
record via the grant — nothing else.
"""

from __future__ import annotations

import base64
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


def _make_org(api_key: str) -> str:
    from app.auth import hash_api_key
    from app.db.models import Org
    from app.db.session import SessionLocal

    org_id = f"org_{uuid.uuid4().hex[:10]}"
    db = SessionLocal()
    try:
        db.add(Org(id=org_id, name="T", api_key_hash=hash_api_key(api_key),
                   requires_profile=False))
        db.commit()
    finally:
        db.close()
    return org_id


def _payload_hash(trace_id: str, seq: int) -> str:
    from app.db.models import Event
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        ev = (
            db.query(Event)
            .filter(Event.trace_id == uuid.UUID(trace_id), Event.seq == seq)
            .one()
        )
        return ev.payload_hash
    finally:
        db.close()


def test_admin_endpoint_requires_key(client) -> None:
    r = client.post(
        "/v1/admin/access-requests",
        headers={"x-admin-key": "wrong"},
        json={"org_id": "x", "payload_hashes": ["h"], "reason": "r"},
    )
    assert r.status_code == 401


def test_full_consent_flow_over_http(client) -> None:
    from app.crypto.org_encryption import generate_wrapping_keypair, regrant_key

    api_key = f"key_{uuid.uuid4().hex}"
    org_id = _make_org(api_key)
    org_headers = {"x-api-key": api_key}
    admin_headers = {"x-admin-key": ADMIN_KEY}

    # 1. Org generates a wrapping keypair (keeps private) and goes customer-key.
    org_private, org_public = generate_wrapping_keypair()
    r = client.post(
        "/v1/org/confidentiality",
        headers=org_headers,
        json={"wrapping_public_pem": org_public.decode()},
    )
    assert r.status_code == 200, r.text

    # 2. Org records two events; content is now dark to Attest.
    trace_id = str(uuid.uuid4())
    for seq in (1, 2):
        rr = client.post(
            "/v1/event",
            headers=org_headers,
            json={"trace_id": trace_id, "seq": seq, "type": "model_completion",
                  "payload": {"secret": f"value-{seq}"}},
        )
        assert rr.status_code == 200, rr.text
    in_scope = _payload_hash(trace_id, 1)
    out_of_scope = _payload_hash(trace_id, 2)

    # 3. Attest (admin) files a request for only the first record.
    r = client.post(
        "/v1/admin/access-requests",
        headers=admin_headers,
        json={"org_id": org_id, "payload_hashes": [in_scope], "reason": "dispute"},
    )
    assert r.status_code == 200, r.text
    request_id = r.json()["request_id"]
    grantee_public = r.json()["grantee_public_pem"].encode()

    # Before approval: Attest cannot read.
    r = client.get(
        f"/v1/admin/access-requests/{request_id}/records/{in_scope}", headers=admin_headers
    )
    assert r.status_code == 403

    # 4. Org fetches the request, and (as its own client) re-wraps just the
    #    in-scope key to the grantee, then approves.
    detail = client.get(f"/v1/access-requests/{request_id}", headers=org_headers).json()
    released: dict[str, str] = {}
    for item in detail["scope"]:
        wrapped_for_org = base64.b64decode(item["wrapped_key_for_org"])
        regranted = regrant_key(org_private, wrapped_for_org, grantee_public)
        released[item["payload_hash"]] = base64.b64encode(regranted).decode()

    r = client.post(
        f"/v1/access-requests/{request_id}/approve",
        headers=org_headers,
        json={"approver_id": "officer_1", "released_keys": released},
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved"

    # 5. Attest can now read exactly the approved record...
    r = client.get(
        f"/v1/admin/access-requests/{request_id}/records/{in_scope}", headers=admin_headers
    )
    assert r.status_code == 200
    assert r.json()["content"] == {"secret": "value-1"}

    # ...but not one that was out of scope.
    r = client.get(
        f"/v1/admin/access-requests/{request_id}/records/{out_of_scope}", headers=admin_headers
    )
    assert r.status_code == 403
