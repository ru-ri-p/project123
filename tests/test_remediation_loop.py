"""The full remediation loop through the gate, attacked.

The story under test: flagged → fix suggested → revised output re-gated with a
remediates reference → original marked remediated — with the chain still
verifying, the plan's content absent from the index, and every way of lying
about a fix rejected.
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

STARTER = {
    "schema_version": 2,
    "engine": "json",
    "rules": [
        {"id": "high_risk_financial_action", "priority": 10, "tier": "red",
         "decision": "deny", "match": {"action": ["wire_transfer", "execute_trade"]},
         "reason": "High-risk financial action"},
        {"id": "personal_data_in_output", "priority": 50, "tier": "orange",
         "decision": "flag", "match": {"has_pii": True},
         "reason": "Personal data in output"},
    ],
}


def _org(client):
    org_id = f"org_loop_{uuid.uuid4().hex[:8]}"
    key = client.post(
        "/v1/admin/orgs", headers=A, json={"org_id": org_id, "name": "Loop"}
    ).json()["api_key"]
    H = {"x-api-key": key}
    client.post("/v1/admin/regulation-packs/seed", headers=A)
    client.put("/v1/policies/profile", headers=H,
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    client.put("/v1/policies/internal", headers=H,
               json={"name": "Internal", "version": "v1", "rules": STARTER,
                     "activate": True})
    return H


def _gate(client, H, body):
    r = client.post("/v1/gate", headers=H, json=body)
    assert r.status_code == 200, r.text
    return r.json()


PII_OUTPUT = {"output": "Send the statement to sara.m@example.com today."}


def test_the_full_story_flagged_fixed_proven(client) -> None:
    H = _org(client)
    trace = str(uuid.uuid4())

    # 1. Flagged, with a fix offered.
    first = _gate(client, H, {"action": "model_completion", "output": PII_OUTPUT,
                              "trace_id": trace})
    assert first["status"] == "flagged"
    fix = first["suggested_fix"]
    assert fix is not None and fix["revised_output"] is not None
    assert "sara.m@example.com" not in fix["revised_output"]["output"]
    assert fix["plan_hash"], "the hash that ties this plan to the sealed decision"

    # 2. The customer applies the fix and re-gates it, naming what it cures.
    second = _gate(client, H, {
        "action": "model_completion",
        "output": fix["revised_output"],
        "trace_id": trace,
        "remediates": first["decision_seq"],
    })
    assert second["status"] == "compliant"
    assert second["remediation_of"] == first["decision_seq"]
    assert second["suggested_fix"] is None, "nothing left to fix"

    # 3. The chain still verifies end to end — the story is sealed, not stapled.
    rep = client.get(f"/v1/trace/{trace}/replay", headers=H).json()
    assert rep["all_verified"] is True

    # 4. The index shows the loop closed.
    from app.db.models import PolicyDecisionSummary
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        rows = {
            s.seq: s
            for s in db.query(PolicyDecisionSummary).filter(
                PolicyDecisionSummary.trace_id == uuid.UUID(trace)
            )
        }
    finally:
        db.close()
    flagged_row = rows[first["decision_seq"]]
    curing_row = rows[second["decision_seq"]]
    assert flagged_row.remediated_by_seq == second["decision_seq"]
    assert curing_row.remediation_of == first["decision_seq"]
    # Shape only in the index — never the plan's content.
    assert flagged_row.remediation is not None
    assert set(flagged_row.remediation) == {
        "plan_hash", "edit_kinds", "requirement_kinds", "unresolved_count",
        "has_revision", "has_rewrite", "rewrite_drafted_by",
        "rewrite_reclassified",
    }
    assert flagged_row.remediation["plan_hash"] == fix["plan_hash"]


def test_a_failed_fix_leaves_the_flag_open(client) -> None:
    """Submitting a 'fix' that still flags must not close anything — otherwise
    the attempt itself would count as the cure."""
    H = _org(client)
    trace = str(uuid.uuid4())
    first = _gate(client, H, {"action": "model_completion", "output": PII_OUTPUT,
                              "trace_id": trace})

    still_bad = {"output": "Send the statement to sara.m@example.com anyway."}
    second = _gate(client, H, {"action": "model_completion", "output": still_bad,
                               "trace_id": trace, "remediates": first["decision_seq"]})
    assert second["status"] == "flagged"

    from app.db.models import PolicyDecisionSummary
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        row = (
            db.query(PolicyDecisionSummary)
            .filter(PolicyDecisionSummary.trace_id == uuid.UUID(trace),
                    PolicyDecisionSummary.seq == first["decision_seq"])
            .one()
        )
        assert row.remediated_by_seq is None, "the flag stays open"
    finally:
        db.close()


def test_remediates_requires_a_trace(client) -> None:
    H = _org(client)
    r = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": {"output": "x"}, "remediates": 1,
    })
    assert r.status_code == 422
    assert "trace_id" in r.json()["detail"]


def test_remediates_must_name_a_real_flagged_decision(client) -> None:
    H = _org(client)
    trace = str(uuid.uuid4())
    clean = _gate(client, H, {"action": "model_completion",
                              "output": {"output": "gold rose"}, "trace_id": trace})
    assert clean["status"] == "compliant"

    # A compliant decision is not remediable.
    r = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": {"output": "y"},
        "trace_id": trace, "remediates": clean["decision_seq"],
    })
    assert r.status_code == 422
    assert "nothing to remediate" in r.json()["detail"]

    # A seq that does not exist is refused too.
    r = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": {"output": "y"},
        "trace_id": trace, "remediates": 999,
    })
    assert r.status_code == 422


def test_one_tenant_cannot_remediate_anothers_record(client) -> None:
    """The reference is scoped by org: a caller must never be able to attach
    their 'fix' to another tenant's flagged decision."""
    H1 = _org(client)
    H2 = _org(client)
    trace = str(uuid.uuid4())
    first = _gate(client, H1, {"action": "model_completion", "output": PII_OUTPUT,
                               "trace_id": trace})

    r = client.post("/v1/gate", headers=H2, json={
        "action": "model_completion", "output": {"output": "clean"},
        "trace_id": trace, "remediates": first["decision_seq"],
    })
    # The other tenant sees nothing to reference — and no hint that the trace
    # exists at all (403 from trace ownership or 422 from the missing ref;
    # either way, never success).
    assert r.status_code in (403, 422)


def test_a_blocked_action_offers_no_fake_rewrite(client) -> None:
    H = _org(client)
    r = _gate(client, H, {"action": "execute_trade", "output": {"output": "executing"}})
    assert r["status"] == "blocked"
    fix = r["suggested_fix"]
    assert fix is not None
    assert fix["revised_output"] is None, "a denied action is not a wording problem"
    assert any("approval workflow" in u["note"] for u in fix["unresolved"])
