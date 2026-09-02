"""The officer work queue, attacked.

The promise: one read shows everything waiting on a person — approvals with
the decision they gate, flags whose fix has not landed, verified rewrites
needing confirmation — and finished work leaves the queue: a resolved
approval disappears, a compliant re-gate clears the flag, and remediation
ATTEMPTS never masquerade as new work.
"""

from __future__ import annotations

import json
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

COMPLIANT_DRAFT = {
    "revised": {"output": "Morning brief: gold momentum elevated. General "
                          "commentary, not advice."},
    "reclassified": True,
    "notes": "advice -> commentary",
}


def _org(client) -> dict:
    org_id = f"org_wq_{uuid.uuid4().hex[:8]}"
    key = client.post("/v1/admin/orgs", headers=A,
                      json={"org_id": org_id, "name": "WQ"}).json()["api_key"]
    H = {"x-api-key": key}
    client.post("/v1/admin/regulation-packs/seed", headers=A)
    client.put("/v1/policies/profile", headers=H,
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    client.put("/v1/policies/internal", headers=H,
               json={"name": "Internal", "version": "v1", "rules": POLICY,
                     "activate": True})
    return H


def _stub_drafter(monkeypatch):
    from app.services import rewrite

    real = rewrite.draft_rewrite

    def patched(**kw):
        kw["completer"] = lambda s, u: json.dumps(COMPLIANT_DRAFT)
        return real(**kw)

    monkeypatch.setattr(rewrite, "draft_rewrite", patched)


def test_the_queue_shows_all_three_kinds_of_open_work(client, monkeypatch) -> None:
    _stub_drafter(monkeypatch)
    H = _org(client)

    blocked = client.post("/v1/gate", headers=H, json={
        "action": "wire_transfer", "output": {"output": "sending"}}).json()
    flagged = client.post("/v1/gate", headers=H, json={
        "action": "model_completion",
        "output": {"output": "email sara.m@example.com"}}).json()
    advised = client.post("/v1/gate", headers=H, json={
        "action": "model_completion",
        "output": {"output": "You should buy gold now.",
                   "classifier": "individualised_advice"}}).json()
    assert blocked["status"] == "blocked" and flagged["status"] == "flagged"
    assert advised["suggested_fix"].get("rewrite"), "sanity: rewrite offered"

    q = client.get("/v1/workqueue", headers=H).json()

    # Approvals carry the decision they gate — the officer sees WHAT. Every
    # orange/red decision routes to a person, so all three appear here.
    pairs = {(a["action"], a["tier"], a["decision_status"])
             for a in q["pending_approvals"]}
    assert ("wire_transfer", "red", "blocked") in pairs
    assert ("model_completion", "orange", "flagged") in pairs

    flag_traces = {f["trace_id"] for f in q["open_flags"]}
    assert flagged["trace_id"] in flag_traces
    assert advised["trace_id"] in flag_traces
    assert blocked["trace_id"] not in flag_traces, (
        "a blocked action is approval work, not an open FLAG"
    )

    rw = {f["trace_id"] for f in q["rewrite_confirmations"]}
    assert advised["trace_id"] in rw, "the reclassified rewrite asks for a human"
    assert flagged["trace_id"] not in rw, "a mechanical PII fix does not"

    c = q["counts"]
    assert c["approvals"] == 3 and c["open_flags"] == 2
    assert c["rewrite_confirmations"] == 1
    assert c["total"] == 5


def test_finished_work_leaves_the_queue(client) -> None:
    H = _org(client)
    flagged = client.post("/v1/gate", headers=H, json={
        "action": "model_completion",
        "output": {"output": "email sara.m@example.com"}}).json()

    fix = flagged["suggested_fix"]["revised_output"]
    cured = client.post("/v1/gate", headers=H, json={
        "action": "model_completion", "output": fix,
        "trace_id": flagged["trace_id"],
        "remediates": flagged["decision_seq"]}).json()
    assert cured["status"] == "compliant"

    q = client.get("/v1/workqueue", headers=H).json()
    assert flagged["trace_id"] not in {f["trace_id"] for f in q["open_flags"]}, (
        "a compliant re-gate closes the flag AND clears the queue"
    )

    approval_ids = [a["approval_id"] for a in q["pending_approvals"]]
    assert len(approval_ids) == 1, "the orange flag's approval still stands"
    client.post(f"/v1/approvals/{approval_ids[0]}/resolve", headers=H,
                json={"status": "approved", "approver_id": "officer_1"})
    q2 = client.get("/v1/workqueue", headers=H).json()
    assert q2["counts"]["total"] == 0, "resolved and cured: an empty queue"


def test_a_failed_cure_attempt_is_not_new_work(client) -> None:
    """A revision that STILL flags keeps the original flag in the queue but
    must not add itself as a second item — attempts are not obligations."""
    H = _org(client)
    flagged = client.post("/v1/gate", headers=H, json={
        "action": "model_completion",
        "output": {"output": "email sara.m@example.com"}}).json()
    still_bad = client.post("/v1/gate", headers=H, json={
        "action": "model_completion",
        "output": {"output": "email maria.h@example.com"},   # a different email!
        "trace_id": flagged["trace_id"],
        "remediates": flagged["decision_seq"]}).json()
    assert still_bad["status"] == "flagged"

    q = client.get("/v1/workqueue", headers=H).json()
    seqs = [(f["trace_id"], f["seq"]) for f in q["open_flags"]]
    assert (flagged["trace_id"], flagged["decision_seq"]) in seqs
    assert (still_bad["trace_id"], still_bad["decision_seq"]) not in seqs


def test_the_queue_is_org_scoped(client) -> None:
    H_a = _org(client)
    H_b = _org(client)
    client.post("/v1/gate", headers=H_a, json={
        "action": "wire_transfer", "output": {"output": "x"}})
    q_b = client.get("/v1/workqueue", headers=H_b).json()
    assert q_b["counts"]["total"] == 0, "org B sees none of org A's work"


def test_the_queue_opens_for_a_session_too(client) -> None:
    os.environ["AUTH_DEV_MODE"] = "1"
    try:
        H = _org(client)
        org_id = client.get("/v1/org/overview", headers=H).json()["org_id"]
        email = f"wq_{uuid.uuid4().hex[:6]}@example.test"
        client.post(f"/v1/auth/admin/orgs/{org_id}/users", headers=A,
                    json={"email": email, "display_name": "Q Officer",
                          "role": "officer"})
        code = client.post("/v1/auth/request-code",
                           json={"email": email}).json()["dev_code"]
        client.post("/v1/auth/verify", json={"email": email, "code": code})
        q = client.get("/v1/workqueue")  # cookie only, no API key
        assert q.status_code == 200
        assert q.json()["counts"]["total"] == 0
    finally:
        del os.environ["AUTH_DEV_MODE"]
