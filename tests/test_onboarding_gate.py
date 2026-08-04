"""No recording until obligations are declared — and no collateral damage.

Evidence recorded before anyone said which rules apply is evidence with no
yardstick, so new orgs are gated. Two things must NOT break:

  * existing orgs (grandfathered) keep working — shipping a gate must never stop
    a live customer's integration;
  * the SDK must tell a missing profile apart from an outage, or the offline
    buffer fills with events that can never be replayed.
"""

from __future__ import annotations

import os
import uuid

import pytest

ADMIN_KEY = "test-admin-key"
A = {"x-admin-key": ADMIN_KEY}


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

    c = TestClient(app)
    c.post("/v1/admin/regulation-packs/seed", headers=A)
    return c


def _new_org(client) -> tuple[str, str]:
    org_id = f"org_gate_{uuid.uuid4().hex[:10]}"
    key = client.post("/v1/admin/orgs", headers=A,
                      json={"org_id": org_id, "name": "Gate Test"}).json()["api_key"]
    return org_id, key


def _grandfather(org_id: str) -> None:
    """Simulate an org that predates the gate, as the migration leaves them."""
    from app.db.models import Org
    from app.db.session import SessionLocal

    db = SessionLocal()
    db.query(Org).filter(Org.id == org_id).update({"requires_profile": False})
    db.commit()
    db.close()


def test_new_org_cannot_record_anything_without_a_profile(client) -> None:
    _, key = _new_org(client)
    H = {"x-api-key": key}
    trace = str(uuid.uuid4())

    for path, body in (
        ("/v1/gate", {"action": "model_completion", "output": {"x": 1}}),
        ("/v1/event", {"trace_id": trace, "seq": 1, "type": "model_completion",
                       "payload": {"x": 1}}),
        ("/v1/precheck", {"trace_id": trace, "seq": 1, "action": "model_completion",
                          "payload": {"x": 1}}),
    ):
        r = client.post(path, headers=H, json=body)
        assert r.status_code == 409, f"{path} -> {r.status_code}"
        detail = r.json()["detail"]
        assert detail["code"] == "profile_required"
        # The message must tell them what to do, not merely state a fact.
        assert "Settings" in detail["message"]

    # Nothing was written.
    assert client.get("/v1/traces", headers=H).json() == []


def test_recording_works_the_moment_the_profile_is_set(client) -> None:
    _, key = _new_org(client)
    H = {"x-api-key": key}
    client.put("/v1/policies/profile", headers=H,
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})

    r = client.post("/v1/gate", headers=H,
                    json={"action": "model_completion", "output": {"x": 1}})
    assert r.status_code == 200, r.text
    assert r.json()["status"] in ("compliant", "flagged", "unevaluated")


def test_existing_orgs_are_grandfathered(client) -> None:
    """Shipping a gate must not stop a live customer mid-integration."""
    org_id, key = _new_org(client)
    _grandfather(org_id)
    H = {"x-api-key": key}

    r = client.post("/v1/gate", headers=H,
                    json={"action": "model_completion", "output": {"x": 1}})
    assert r.status_code == 200, "a grandfathered org must keep recording"
    # And it is still prompted, so the gap is visible rather than ignored.
    assert client.get("/v1/policies/profile", headers=H).json()["configured"] is False


def test_setting_a_profile_is_never_itself_gated(client) -> None:
    """Otherwise onboarding would be impossible — the gate would lock them out."""
    _, key = _new_org(client)
    H = {"x-api-key": key}
    assert client.get("/v1/policies/sectors", headers=H).status_code == 200
    assert client.get("/v1/policies/profile", headers=H).status_code == 200
    assert client.put("/v1/policies/profile", headers=H, json={
        "jurisdictions": ["difc"], "sectors": ["banking"]}).status_code == 200


def test_sdk_treats_missing_profile_as_config_error_not_an_outage(client) -> None:
    """The load-bearing one: buffering a 'no profile' rejection would fill the
    queue with events that can never be replayed, and disguise a setup problem
    as a network fault."""
    import requests

    from attest_sdk.gate import GateResult

    _, key = _new_org(client)
    response = client.post("/v1/gate", headers={"x-api-key": key},
                           json={"action": "model_completion", "output": {"x": 1}})
    assert response.status_code == 409

    exc = requests.HTTPError(response=response)  # type: ignore[arg-type]
    from attest_sdk.attest import _configuration_error

    detail = _configuration_error(exc)
    assert detail is not None and detail["code"] == "profile_required"

    result = GateResult.misconfigured(detail)
    assert result.status == "misconfigured"
    assert result.buffered is False, "a config error must never be buffered"
    assert result.recorded is False
    assert result.allowed is True, "the caller's application still serves"
    assert "Settings" in result.summary() or "setup incomplete" in result.summary()


def test_a_real_outage_is_still_buffered(client) -> None:
    """The distinction must cut both ways — network faults still buffer."""
    import requests

    from attest_sdk.attest import _configuration_error

    assert _configuration_error(requests.ConnectionError("refused")) is None
