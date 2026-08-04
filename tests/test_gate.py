"""The output gate — one call to check and log an AI output.

What must hold:
  * one call records BOTH the decision and the output, chained and signed;
  * sequence numbers are assigned server-side (the old foot-gun is gone);
  * the verdict is derived in one place and matches what the dashboards show;
  * a jurisdiction finding flags but never blocks; only the institution's own
    policy blocks;
  * provenance never fails for a configuration reason — no policy still records.
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


def _org(client, *, policy: bool = True, difc: bool = False) -> str:
    org_id = f"org_gate_{uuid.uuid4().hex[:10]}"
    key = client.post(
        "/v1/admin/orgs", headers={"x-admin-key": ADMIN_KEY},
        json={"org_id": org_id, "name": "Gate Test"},
    ).json()["api_key"]
    # Onboarding is now a precondition for recording, so every org that records
    # must declare its profile first.
    client.put("/v1/policies/profile", headers={"x-api-key": key},
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    if policy:
        client.put("/v1/policies/internal", headers={"x-api-key": key}, json={
            "name": "Internal", "version": "v1", "activate": True,
            "rules": {"schema_version": 2, "engine": "json", "rules": [
                {"id": "block_wires", "priority": 1000, "tier": "red", "decision": "deny",
                 "match": {"action": ["wire_transfer"]},
                 "reason": "Wire transfers need a human."}]}})
    if difc:
        client.post("/v1/admin/regulation-packs/seed", headers={"x-admin-key": ADMIN_KEY})
        client.post(
            f"/v1/admin/orgs/{org_id}/regulation-packs",
            headers={"x-admin-key": ADMIN_KEY},
            json={"pack_code": "difc_dp_reg10"},
        )
    return key


def test_one_call_records_decision_and_output(client) -> None:
    key = _org(client)
    r = client.post("/v1/gate", headers={"x-api-key": key},
                    json={"action": "model_completion", "output": {"text": "hello"}})
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["status"] == "compliant"
    assert body["allowed"] is True
    # The caller never supplied a trace or any sequence numbers.
    assert body["decision_seq"] == 1
    assert body["output_seq"] == 2
    assert body["output_hash"] and body["signature"]

    # Both events exist, chained, in the auto-created trace.
    events = client.get(f"/v1/trace/{body['trace_id']}/events",
                        headers={"x-api-key": key}).json()
    assert [e["type"] for e in events] == ["policy_decision", "model_completion"]

    replay = client.get(f"/v1/trace/{body['trace_id']}/replay",
                        headers={"x-api-key": key}).json()
    assert replay["all_verified"] is True


def test_own_policy_blocks_but_jurisdiction_only_flags(client) -> None:
    key = _org(client, difc=True)

    # Their own rule denies -> blocked.
    blocked = client.post("/v1/gate", headers={"x-api-key": key},
                          json={"action": "wire_transfer", "output": {"amount": 500}}).json()
    assert blocked["status"] == "blocked"
    assert blocked["allowed"] is False

    # A DIFC rule at red -> flagged, still allowed. Only their policy blocks.
    flagged = client.post("/v1/gate", headers={"x-api-key": key}, json={
        "action": "model_completion",
        "output": {"text": "declined", "_classifier_tier": "discriminatory_lending"}}).json()
    assert flagged["status"] == "flagged"
    assert flagged["allowed"] is True
    assert flagged["tier"] == "red"
    assert flagged["jurisdictions"] == ["difc"]
    assert flagged["findings"][0]["advisory_only"] is True


def test_gate_records_even_without_a_policy(client) -> None:
    """Provenance is the floor; evaluation is a layer on top."""
    key = _org(client, policy=False)
    body = client.post("/v1/gate", headers={"x-api-key": key},
                       json={"action": "model_completion", "output": {"text": "x"}}).json()

    assert body["status"] == "unevaluated"
    assert body["allowed"] is True
    assert "not evaluated" in body["reasons"][0]
    # The output was still recorded and is verifiable.
    assert body["output_seq"] == 1 and body["output_hash"]
    replay = client.get(f"/v1/trace/{body['trace_id']}/replay",
                        headers={"x-api-key": key}).json()
    assert replay["all_verified"] is True


def test_multi_step_trace_groups_and_chains(client) -> None:
    key = _org(client)
    first = client.post("/v1/gate", headers={"x-api-key": key},
                        json={"action": "model_completion", "output": {"step": 1}}).json()
    trace = first["trace_id"]
    second = client.post("/v1/gate", headers={"x-api-key": key}, json={
        "action": "tool_call", "output": {"step": 2}, "trace_id": trace}).json()

    assert second["trace_id"] == trace
    assert second["output_seq"] > first["output_seq"]
    events = client.get(f"/v1/trace/{trace}/events", headers={"x-api-key": key}).json()
    assert [e["type"] for e in events] == [
        "policy_decision", "model_completion", "policy_decision", "tool_call"]
    assert client.get(f"/v1/trace/{trace}/replay",
                      headers={"x-api-key": key}).json()["all_verified"] is True


def test_verdict_matches_what_the_dashboard_shows(client) -> None:
    """The status the caller received must be the status the dashboard reports."""
    key = _org(client, difc=True)
    gated = client.post("/v1/gate", headers={"x-api-key": key}, json={
        "action": "model_completion",
        "output": {"text": "declined", "_classifier_tier": "discriminatory_lending"}}).json()

    decisions = client.get("/v1/policies/decisions", headers={"x-api-key": key}).json()
    match = [d for d in decisions if d["trace_id"] == gated["trace_id"]]
    assert len(match) == 1
    assert match[0]["status"] == gated["status"] == "flagged"
    assert match[0]["output_hash"] == gated["output_hash"]


def test_derive_status_is_the_single_definition() -> None:
    from app.services.gate import derive_status

    assert derive_status(allowed=False, tier="green", findings=[]) == "blocked"
    assert derive_status(allowed=True, tier="red", findings=[]) == "flagged"
    assert derive_status(allowed=True, tier="green", findings=[{"x": 1}]) == "flagged"
    assert derive_status(allowed=True, tier="yellow", findings=[]) == "compliant"
    assert derive_status(allowed=True, tier="green", findings=[]) == "compliant"


def test_bad_input_is_rejected_cleanly(client) -> None:
    key = _org(client)
    assert client.post("/v1/gate", headers={"x-api-key": key},
                       json={"action": "", "output": {}}).status_code == 422
    assert client.post("/v1/gate", headers={"x-api-key": key}, json={
        "action": "x", "output": {}, "trace_id": "not-a-uuid"}).status_code == 422
    assert client.post("/v1/gate", json={"action": "x", "output": {}}).status_code == 422


def test_another_orgs_trace_is_refused(client) -> None:
    key_a = _org(client)
    key_b = _org(client)
    trace = client.post("/v1/gate", headers={"x-api-key": key_a},
                        json={"action": "model_completion", "output": {}}).json()["trace_id"]
    r = client.post("/v1/gate", headers={"x-api-key": key_b}, json={
        "action": "model_completion", "output": {}, "trace_id": trace})
    assert r.status_code == 403
