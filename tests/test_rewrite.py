"""The semantic rewrite layer, attacked.

The promise: a model may DRAFT a compliant rewrite, but the deterministic gate
judges every draft before it is offered, provenance is sealed, reclassification
is flagged for a human, and the feature's absence changes nothing. Each test
tries to make the layer break one of those.
"""

from __future__ import annotations

import json
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
    "schema_version": 2, "engine": "json",
    "rules": [
        {"id": "high_risk_financial_action", "priority": 1000, "tier": "red",
         "decision": "deny", "match": {"action": ["wire_transfer", "execute_trade"]},
         "reason": "High-risk financial action"},
        {"id": "personal_data_in_output", "priority": 800, "tier": "orange",
         "decision": "flag", "match": {"has_pii": True},
         "reason": "Personal data in output"},
    ],
}

# An output with a judgement-level violation: individualised advice. The
# deterministic planner can only put this in `unresolved` — the rewrite layer's
# trigger condition.
ADVICE_OUTPUT = {
    "output": "You should increase your gold position before the Fed minutes.",
    "classifier": "individualised_advice",
}

COMPLIANT_DRAFT = {
    "revised": {"output": "Morning brief: gold momentum is elevated ahead of "
                          "the Fed minutes. General commentary, not advice."},
    "reclassified": True,
    "notes": "Rewrote individualised advice as general commentary.",
}

STILL_BAD_DRAFT = {
    "revised": {"output": "You should buy now — email me at x.y@example.com.",
                "classifier": "individualised_advice"},
    "reclassified": False,
    "notes": "barely changed",
}


def _org(client):
    org_id = f"org_rw_{uuid.uuid4().hex[:8]}"
    key = client.post("/v1/admin/orgs", headers=A,
                      json={"org_id": org_id, "name": "RW"}).json()["api_key"]
    H = {"x-api-key": key}
    client.post("/v1/admin/regulation-packs/seed", headers=A)
    client.put("/v1/policies/profile", headers=H,
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    client.put("/v1/policies/internal", headers=H,
               json={"name": "Internal", "version": "v1", "rules": STARTER,
                     "activate": True})
    return H


def _stub_drafter(monkeypatch, responses: list[dict | Exception]):
    """Make the drafter return canned model responses, in order."""
    from app.services import rewrite

    calls: list[dict] = []

    def completer(system: str, user: str) -> str:
        calls.append({"system": system, "user": user})
        item = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(item, Exception):
            raise item
        return json.dumps(item)

    real = rewrite.draft_rewrite

    def patched(**kw):
        kw["completer"] = completer
        return real(**kw)

    monkeypatch.setattr(rewrite, "draft_rewrite", patched)
    return calls


def test_a_gate_passing_draft_is_offered_with_provenance(client, monkeypatch) -> None:
    calls = _stub_drafter(monkeypatch, [COMPLIANT_DRAFT])
    H = _org(client)
    r = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": ADVICE_OUTPUT}).json()

    assert r["status"] == "flagged"
    rw = r["suggested_fix"].get("rewrite")
    assert rw is not None, "a verified rewrite rides with the flag"
    assert rw["evaluation"] == "compliant", "checked, not hoped"
    assert rw["drafted_by"] == "stub", "model provenance is never elided"
    assert rw["prompt_sha256"], "and the exact prompt is pinned"
    assert rw["requires_human_confirmation"] is True, (
        "the draft changed what the output IS — a human must confirm that"
    )
    assert "advice" not in rw["output"].get("classifier", ""), "declaration dropped"
    assert len(calls) == 1


def test_a_draft_that_still_violates_is_never_offered(client, monkeypatch) -> None:
    """THE load-bearing test: the model cannot vouch for itself. A draft that
    fails the deterministic gate must not reach the customer, however
    confidently the model produced it."""
    calls = _stub_drafter(monkeypatch, [STILL_BAD_DRAFT, STILL_BAD_DRAFT])
    H = _org(client)
    r = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": ADVICE_OUTPUT}).json()

    assert r["status"] == "flagged"
    assert "rewrite" not in (r["suggested_fix"] or {}), (
        "no passing draft -> no rewrite offered; unresolved stands"
    )
    assert r["suggested_fix"]["unresolved"], "the honest answer survives"
    assert len(calls) == 2, "bounded retries, then stop"


def test_model_failure_changes_nothing(client, monkeypatch) -> None:
    _stub_drafter(monkeypatch, [RuntimeError("model unavailable")])
    H = _org(client)
    r = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": ADVICE_OUTPUT}).json()
    assert r["status"] == "flagged"
    assert "rewrite" not in (r["suggested_fix"] or {})


def test_no_api_key_means_the_feature_does_not_exist(client) -> None:
    """Default test environment has no key: the response must look exactly as
    it did before this layer was built."""
    from app.services import rewrite

    assert rewrite.enabled() is False
    H = _org(client)
    r = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": ADVICE_OUTPUT}).json()
    assert r["status"] == "flagged"
    assert "rewrite" not in (r["suggested_fix"] or {})


def test_the_drafter_is_not_invoked_for_blocked_or_mechanical_flags(
    client, monkeypatch
) -> None:
    """A rewrite cannot cure a denied ACTION, and mechanical fixes need no
    model — the expensive path must not run for either."""
    calls = _stub_drafter(monkeypatch, [COMPLIANT_DRAFT])
    H = _org(client)

    r = client.post("/v1/gate", headers=H, json={
        "action": "execute_trade", "output": {"output": "executing"}}).json()
    assert r["status"] == "blocked"
    assert len(calls) == 0, "no drafting for a denied action"

    r = client.post("/v1/gate", headers=H, json={
        "action": "model_completion",
        "output": {"output": "email sara.m@example.com"}}).json()
    assert r["status"] == "flagged"
    assert len(calls) == 0, "pure-PII flag has a mechanical fix; no model needed"


def test_the_rewrite_is_sealed_under_the_plan_hash(client, monkeypatch) -> None:
    """Nobody can later swap the suggested text and claim it was ours: the
    plan hash in the signed decision covers the rewrite."""
    _stub_drafter(monkeypatch, [COMPLIANT_DRAFT])
    H = _org(client)
    r = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": ADVICE_OUTPUT}).json()

    from app.crypto.canonical import sha256_hex

    fix = r["suggested_fix"]
    body = {k: fix[k] for k in
            ("revised_output", "edits", "requirements", "unresolved", "rewrite")}
    assert sha256_hex(body) == fix["plan_hash"], "hash covers the rewrite"

    # And the summary the chain/dashboards see records who drafted it.
    from app.db.models import PolicyDecisionSummary
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        row = (
            db.query(PolicyDecisionSummary)
            .filter(PolicyDecisionSummary.trace_id == uuid.UUID(r["trace_id"]))
            .one()
        )
        assert row.remediation["has_rewrite"] is True
        assert row.remediation["rewrite_drafted_by"] == "stub"
        assert row.remediation["rewrite_reclassified"] is True
        assert row.remediation["plan_hash"] == fix["plan_hash"]
    finally:
        db.close()


def test_applying_the_rewrite_closes_the_loop_like_any_fix(client, monkeypatch) -> None:
    """The rewrite earns nothing by being model-drafted: it closes the flag
    only the way every fix does — by re-gating compliant with remediates=."""
    _stub_drafter(monkeypatch, [COMPLIANT_DRAFT])
    H = _org(client)
    trace = str(uuid.uuid4())
    first = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": ADVICE_OUTPUT,
        "trace_id": trace}).json()
    rw = first["suggested_fix"]["rewrite"]

    second = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": rw["output"],
        "trace_id": trace, "remediates": first["decision_seq"]}).json()
    assert second["status"] == "compliant"

    rep = client.get(f"/v1/trace/{trace}/replay", headers=H).json()
    assert rep["all_verified"] is True
