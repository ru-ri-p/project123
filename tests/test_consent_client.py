"""Slice 5b: the org-side ConsentClient drives the ceremony end to end.

Proves the client generates a keypair, goes customer-key, and — holding only the
private key locally — approves a scoped request by re-wrapping just the in-scope
record's key. Attest then reads exactly that record and nothing else.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest

ADMIN_KEY = "test-admin-key"


@pytest.fixture(scope="module", autouse=True)
def _admin_env() -> Any:
    os.environ["ADMIN_API_KEY"] = ADMIN_KEY
    from app.config import get_settings

    get_settings.cache_clear()
    yield
    del os.environ["ADMIN_API_KEY"]
    get_settings.cache_clear()


class _RequestsShim:
    """Route attest_sdk.consent's requests.* calls at the in-process FastAPI app.

    Mirrors the tiny slice of the `requests` API the client uses (get/post with
    headers/json/params, a response exposing raise_for_status()/json()), dropping
    the `timeout` kwarg the TestClient doesn't take.
    """

    def __init__(self, test_client: Any) -> None:
        self._c = test_client

    def get(self, url: str, **kw: Any) -> Any:
        kw.pop("timeout", None)
        return self._c.get(url, **kw)

    def post(self, url: str, **kw: Any) -> Any:
        kw.pop("timeout", None)
        return self._c.post(url, **kw)


@pytest.fixture()
def consent_client(db_available: bool, monkeypatch: pytest.MonkeyPatch) -> Any:
    if not db_available:
        pytest.skip("PostgreSQL not available")
    from fastapi.testclient import TestClient

    from app.main import app
    from attest_sdk import consent as consent_module

    test_client = TestClient(app)
    monkeypatch.setattr(consent_module, "requests", _RequestsShim(test_client))
    return test_client


def _make_org(api_key: str) -> str:
    from app.auth import hash_api_key
    from app.db.models import Org
    from app.db.session import SessionLocal

    org_id = f"org_{uuid.uuid4().hex[:10]}"
    db = SessionLocal()
    try:
        db.add(Org(id=org_id, name="T", api_key_hash=hash_api_key(api_key)))
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


def test_orgcrypto_roundtrip_and_regrant() -> None:
    from attest_sdk.orgcrypto import (
        generate_wrapping_keypair,
        regrant_key,
        unwrap_key,
        wrap_key,
    )

    org_priv, org_pub = generate_wrapping_keypair()
    grantee_priv, grantee_pub = generate_wrapping_keypair()

    dek = os.urandom(32)
    wrapped_for_org = wrap_key(org_pub, dek)
    assert unwrap_key(org_priv, wrapped_for_org) == dek

    # Regrant to the grantee: only the grantee can now recover the DEK.
    regranted = regrant_key(org_priv, wrapped_for_org, grantee_pub)
    assert unwrap_key(grantee_priv, regranted) == dek


def test_consent_client_full_flow(consent_client: Any) -> None:
    from attest_sdk import ConsentClient
    from attest_sdk.orgcrypto import generate_wrapping_keypair

    api_key = f"key_{uuid.uuid4().hex}"
    org_id = _make_org(api_key)
    org = ConsentClient(api_key=api_key, base_url="http://testserver")

    # 1. Org generates a keypair and goes customer-key with the public half.
    org_private, org_public = generate_wrapping_keypair()
    out = org.enable_customer_key(org_public)
    assert out["confidentiality_mode"] == "customer_key"

    # 2. Org records two dark events.
    trace_id = str(uuid.uuid4())
    for seq in (1, 2):
        r = consent_client.post(
            "/v1/event",
            headers={"x-api-key": api_key},
            json={
                "trace_id": trace_id,
                "seq": seq,
                "type": "model_completion",
                "payload": {"secret": f"value-{seq}"},
            },
        )
        assert r.status_code == 200, r.text
    in_scope = _payload_hash(trace_id, 1)
    out_of_scope = _payload_hash(trace_id, 2)

    # 3. Attest (admin) files a request for only the first record.
    admin_headers = {"x-admin-key": ADMIN_KEY}
    r = consent_client.post(
        "/v1/admin/access-requests",
        headers=admin_headers,
        json={"org_id": org_id, "payload_hashes": [in_scope], "reason": "dispute"},
    )
    assert r.status_code == 200, r.text
    request_id = r.json()["request_id"]

    # 4. Org sees the request and approves it with its private key (locally).
    pending = org.list_requests(status="pending")
    assert any(req["request_id"] == request_id for req in pending)

    approved = org.approve(request_id, approver_id="officer_1", org_private_pem=org_private)
    assert approved["status"] == "approved"

    # 5. Attest reads exactly the approved record...
    r = consent_client.get(
        f"/v1/admin/access-requests/{request_id}/records/{in_scope}", headers=admin_headers
    )
    assert r.status_code == 200
    assert r.json()["content"] == {"secret": "value-1"}

    # ...but not the out-of-scope one.
    r = consent_client.get(
        f"/v1/admin/access-requests/{request_id}/records/{out_of_scope}", headers=admin_headers
    )
    assert r.status_code == 403


def test_consent_client_deny_releases_nothing(consent_client: Any) -> None:
    from attest_sdk import ConsentClient
    from attest_sdk.orgcrypto import generate_wrapping_keypair

    api_key = f"key_{uuid.uuid4().hex}"
    org_id = _make_org(api_key)
    org = ConsentClient(api_key=api_key, base_url="http://testserver")

    _, org_public = generate_wrapping_keypair()
    org.enable_customer_key(org_public)

    trace_id = str(uuid.uuid4())
    consent_client.post(
        "/v1/event",
        headers={"x-api-key": api_key},
        json={"trace_id": trace_id, "seq": 1, "type": "model_completion",
              "payload": {"secret": "nope"}},
    )
    target = _payload_hash(trace_id, 1)

    r = consent_client.post(
        "/v1/admin/access-requests",
        headers={"x-admin-key": ADMIN_KEY},
        json={"org_id": org_id, "payload_hashes": [target], "reason": "dispute"},
    )
    request_id = r.json()["request_id"]

    denied = org.deny(request_id)
    assert denied["status"] == "denied"

    # Even the admin read path stays closed after a denial.
    r = consent_client.get(
        f"/v1/admin/access-requests/{request_id}/records/{target}",
        headers={"x-admin-key": ADMIN_KEY},
    )
    assert r.status_code == 403
