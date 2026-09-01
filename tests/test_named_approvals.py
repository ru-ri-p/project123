"""Named-person approvals, attacked.

The promise: when a signed-in person resolves an approval, the sealed chain
records their VERIFIED identity ("authenticated"), never a name the request
body claims; the machine-key path still works but is honestly labeled
"asserted"; viewers cannot approve; and nobody reaches across orgs. Each
test tries to break one of those.
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


RED_POLICY = {
    "schema_version": 2, "engine": "json",
    "rules": [{"id": "wire", "priority": 1000, "tier": "red",
               "decision": "deny", "match": {"action": ["wire_transfer"]},
               "reason": "High-risk financial action"}],
}


def _org_with_approval(client) -> tuple[str, dict, str]:
    """Org + a pending approval; returns (org_id, api headers, approval_id)."""
    org_id = f"org_na_{uuid.uuid4().hex[:8]}"
    key = client.post("/v1/admin/orgs", headers=A,
                      json={"org_id": org_id, "name": "NA"}).json()["api_key"]
    H = {"x-api-key": key}
    client.put("/v1/policies/profile", headers=H,
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    client.put("/v1/policies/internal", headers=H,
               json={"name": "Internal", "version": "v1", "rules": RED_POLICY,
                     "activate": True})
    r = client.post("/v1/gate", headers=H, json={
        "action": "wire_transfer", "output": {"output": "sending 25k"}}).json()
    assert r["status"] == "blocked" and r["approval_id"]
    return org_id, H, r["approval_id"]


def _officer_token(client, org_id: str, role: str = "officer") -> tuple[str, str]:
    email = f"{role}_{uuid.uuid4().hex[:8]}@example.test"
    client.post(f"/v1/auth/admin/orgs/{org_id}/users", headers=A,
                json={"email": email, "display_name": "Named Person",
                      "role": role})
    code = client.post("/v1/auth/request-code",
                       json={"email": email}).json()["dev_code"]
    token = client.post("/v1/auth/verify",
                        json={"email": email, "code": code}).json()["token"]
    return email, token


def test_signed_in_officer_resolves_with_proven_identity(client) -> None:
    org_id, H, approval_id = _org_with_approval(client)
    email, token = _officer_token(client, org_id)

    r = client.post(f"/v1/approvals/{approval_id}/resolve",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"status": "approved", "comment": "reviewed the wire"})
    assert r.status_code == 200, r.text

    row = client.get(f"/v1/approvals/{approval_id}", headers=H).json()
    assert row["approver_id"] == email, "recorded who ACTUALLY approved"
    assert row["approver_kind"] == "authenticated"


def test_a_claimed_name_in_the_body_is_ignored_for_a_signed_in_person(client) -> None:
    """A person cannot approve as somebody else by typing a different name."""
    org_id, H, approval_id = _org_with_approval(client)
    email, token = _officer_token(client, org_id)

    r = client.post(f"/v1/approvals/{approval_id}/resolve",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"status": "approved",
                          "approver_id": "chief_risk_officer_definitely"})
    assert r.status_code == 200
    row = client.get(f"/v1/approvals/{approval_id}", headers=H).json()
    assert row["approver_id"] == email, "the session identity wins, always"


def test_the_chain_event_carries_identity_without_raw_pii(client) -> None:
    """The authenticated/asserted distinction AND a durable identity are
    sealed in the signed event — but as the user's UUID and display name,
    never a raw email: record_event redacts PII from every stored payload
    (data minimisation), and approvals are no exception."""
    org_id, H, approval_id = _org_with_approval(client)
    email, token = _officer_token(client, org_id)
    client.post(f"/v1/approvals/{approval_id}/resolve",
                headers={"Authorization": f"Bearer {token}"},
                json={"status": "denied"})

    trace_id = client.get(f"/v1/approvals/{approval_id}", headers=H).json()["trace_id"]
    rep = client.get(f"/v1/trace/{trace_id}/replay", headers=H).json()
    assert rep["all_verified"] is True, "and the chain still verifies"

    from app.db.models import Event, User
    from app.db.session import SessionLocal
    from app.services.payload_store import read_payload_content

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        ev = (
            db.query(Event)
            .filter(Event.trace_id == uuid.UUID(trace_id),
                    Event.type == "approval_action")
            .one()
        )
        payload = read_payload_content(db, ev.org_id, ev.payload_hash)
        assert payload is not None
        assert payload["approver_kind"] == "authenticated"
        assert payload["approver_user_id"] == str(user.id), (
            "durable person identity, resolvable to the user row"
        )
        assert payload["approver_display"] == "Named Person"
        assert email not in str(payload), "no raw email in the sealed chain"
    finally:
        db.close()


def test_viewer_role_cannot_approve(client) -> None:
    org_id, H, approval_id = _org_with_approval(client)
    _, token = _officer_token(client, org_id, role="viewer")
    r = client.post(f"/v1/approvals/{approval_id}/resolve",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"status": "approved"})
    assert r.status_code == 403
    row = client.get(f"/v1/approvals/{approval_id}", headers=H).json()
    assert row["status"] == "pending", "and the approval is untouched"


def test_machine_key_path_still_works_but_is_labeled_asserted(client) -> None:
    _, H, approval_id = _org_with_approval(client)
    r = client.post(f"/v1/approvals/{approval_id}/resolve", headers=H,
                    json={"status": "approved", "approver_id": "risk_officer_1"})
    assert r.status_code == 200
    row = client.get(f"/v1/approvals/{approval_id}", headers=H).json()
    assert row["approver_id"] == "risk_officer_1"
    assert row["approver_kind"] == "asserted", "a claimed name says so, forever"


def test_machine_key_without_a_name_is_refused(client) -> None:
    _, H, approval_id = _org_with_approval(client)
    r = client.post(f"/v1/approvals/{approval_id}/resolve", headers=H,
                    json={"status": "approved"})
    assert r.status_code == 422, "an anonymous machine approval is worthless"


def test_an_officer_of_another_org_cannot_reach_this_approval(client) -> None:
    _, _, approval_id = _org_with_approval(client)
    other_org, _, _ = _org_with_approval(client)
    _, token = _officer_token(client, other_org)
    r = client.post(f"/v1/approvals/{approval_id}/resolve",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"status": "approved"})
    assert r.status_code == 404, "cross-org approvals do not exist for you"


def test_expired_or_garbage_session_never_falls_back_to_anonymous(client) -> None:
    _, _, approval_id = _org_with_approval(client)
    r = client.post(f"/v1/approvals/{approval_id}/resolve",
                    headers={"Authorization": "Bearer not-a-real-token"},
                    json={"status": "approved", "approver_id": "ghost"})
    assert r.status_code == 401, "a dead session fails loudly, never downgrades"
