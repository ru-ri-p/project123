"""Policy dry-run preview: same verdict as the gate, but records NOTHING."""

from __future__ import annotations

import os
import uuid

import pytest

ADMIN_KEY = "test-admin-key"
A = {"x-admin-key": ADMIN_KEY}


@pytest.fixture(scope="module", autouse=True)
def _env():
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


POLICY = {
    "schema_version": 2, "engine": "json",
    "rules": [
        {"id": "wire", "priority": 1000, "tier": "red", "decision": "deny",
         "match": {"action": ["wire_transfer"]}, "reason": "High-risk action"},
        {"id": "pii", "priority": 800, "tier": "orange", "decision": "flag",
         "match": {"has_pii": True}, "reason": "Personal data in output"},
    ],
}


def _org(client) -> dict:
    org_id = f"org_pv_{uuid.uuid4().hex[:8]}"
    key = client.post("/v1/admin/orgs", headers=A,
                      json={"org_id": org_id, "name": "PV"}).json()["api_key"]
    H = {"x-api-key": key}
    client.post("/v1/admin/regulation-packs/seed", headers=A)
    client.put("/v1/policies/profile", headers=H,
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    client.put("/v1/policies/internal", headers=H,
               json={"name": "Internal", "version": "v1", "rules": POLICY,
                     "activate": True})
    return H


def test_preview_flags_pii_and_records_nothing(client) -> None:
    H = _org(client)
    r = client.post("/v1/policies/preview", headers=H, json={
        "action": "model_completion",
        "output": {"output": "email sara.m@example.com"}}).json()
    assert r["status"] == "flagged"
    assert r["tier"] == "orange"
    assert r["remediation_preview"] is not None
    assert r["recorded"] is False

    # The dashboards saw nothing: no decision was indexed.
    decisions = client.get("/v1/policies/decisions", headers=H).json()
    assert decisions == [], "a dry run must leave no trace in the record"


def test_preview_matches_the_real_gate_verdict(client) -> None:
    """Preview and the recorded gate must agree — same pipeline, same answer."""
    H = _org(client)
    sample = {"action": "wire_transfer", "output": {"output": "send it"}}
    pv = client.post("/v1/policies/preview", headers=H, json=sample).json()
    real = client.post("/v1/gate", headers=H, json=sample).json()
    assert pv["status"] == real["status"] == "blocked"
    assert pv["tier"] == real["tier"]


def test_preview_a_candidate_ruleset_without_activating_it(client) -> None:
    """Test an edit before it goes live: the candidate flags, the ACTIVE
    policy (which has no such rule) still would not."""
    H = _org(client)
    candidate = {
        "schema_version": 2, "engine": "json",
        "rules": [{"id": "no_guarantees", "priority": 500, "tier": "orange",
                   "decision": "flag", "match": {"prohibited_phrases": True},
                   "reason": "Guaranteed-return language"}],
    }
    body = {"action": "model_completion",
            "output": {"output": "guaranteed 20% returns", "prohibited_phrases": True}}
    cand = client.post("/v1/policies/preview", headers=H,
                       json={**body, "candidate_rules": candidate}).json()
    assert cand["status"] == "flagged", "the candidate rule catches it"

    # And the active policy is untouched — still what we published.
    active = client.get("/v1/policies/active", headers=H).json()
    assert active["version"] == "v1"
    assert not any(r["id"] == "no_guarantees" for r in active["rules"]["rules"])


def test_preview_reports_a_broken_candidate_instead_of_crashing(client) -> None:
    H = _org(client)
    r = client.post("/v1/policies/preview", headers=H, json={
        "action": "model_completion", "output": {"output": "x"},
        "candidate_rules": {"schema_version": 2, "engine": "json",
                            "rules": [{"garbage": True}]}})
    # Either a clean validation error or a reported status:"error" — never 500.
    assert r.status_code in (200, 422)
    if r.status_code == 200:
        assert r.json()["status"] in ("error", "compliant", "flagged", "blocked")


def test_preview_needs_auth(client) -> None:
    r = client.post("/v1/policies/preview",
                    json={"action": "x", "output": {"output": "y"}})
    assert r.status_code == 401
