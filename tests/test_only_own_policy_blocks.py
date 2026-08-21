"""THE promise: only the customer's own policy can block an output.

Found broken live by a trigger-matrix sweep: a cross-border output was blocked
for an org whose own policy said nothing about cross-border. Two separate
mechanisms were substituting Attest's judgement for the customer's:

  1. the evaluator's default decision turned a layer-raised red tier into a
     deny even when NO customer rule had matched;
  2. tier_allows_action re-derived blocking from the tier, overriding the
     evaluator's allowed=True.

The same sweep also found two trigger gaps: UAE phone numbers written with
spaces were not PII, and the classifier rules matched only an undocumented
`_classifier_tier` payload field.
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
    org_id = f"org_blk_{uuid.uuid4().hex[:8]}"
    key = client.post(
        "/v1/admin/orgs", headers=A, json={"org_id": org_id, "name": "Blk"}
    ).json()["api_key"]
    H = {"x-api-key": key}
    client.post("/v1/admin/regulation-packs/seed", headers=A)
    client.put("/v1/policies/profile", headers=H,
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    client.put("/v1/policies/internal", headers=H,
               json={"name": "Internal", "version": "v1", "rules": STARTER,
                     "activate": True})
    return H


def _gate(client, H, action, output):
    r = client.post("/v1/gate", headers=H, json={"action": action, "output": output})
    assert r.status_code == 200, r.text
    return r.json()


def test_a_builtin_layer_can_flag_but_never_block(client) -> None:
    """Cross-border without lawful basis trips a RED built-in layer. The org's
    own policy says nothing about cross-border, so the verdict must be a flag —
    the exact case that was blocking in production."""
    H = _org(client)
    r = _gate(client, H, "model_completion",
              {"output": "sending data", "cross_border": True})
    assert r["status"] == "flagged"
    assert r["allowed"] is True, "no rule of the customer's matched; nothing may block"


def test_an_advisory_pack_finding_never_blocks(client) -> None:
    """PII trips orange pack rules and the customer's own flag rule. Flags all
    the way down — blocked only ever means the customer's own deny."""
    H = _org(client)
    r = _gate(client, H, "model_completion",
              {"output": "email the statement to sara.m@example.com"})
    assert r["status"] == "flagged" and r["allowed"] is True
    assert any(f.get("pack_code", "").startswith("difc") for f in r["findings"]), (
        "the flag carries its jurisdiction citation"
    )


def test_the_customers_own_deny_still_blocks(client) -> None:
    """Fixing over-blocking must not have broken legitimate blocking."""
    H = _org(client)
    r = _gate(client, H, "execute_trade", {"output": "executing"})
    assert r["status"] == "blocked" and r["allowed"] is False


def test_a_lawful_basis_clears_the_cross_border_layer(client) -> None:
    H = _org(client)
    r = _gate(client, H, "model_completion",
              {"output": "sending data", "cross_border": True,
               "lawful_basis": "contract"})
    assert r["status"] == "compliant"


def test_phone_numbers_with_separators_are_pii() -> None:
    """+971 50 123 4567 is how a human writes it; only the unbroken form was
    matched before, which missed the common case entirely."""
    from app.services.pii import PATTERNS

    pat = PATTERNS["phone_ae"]
    for sample in ("+971501234567", "+971 50 123 4567", "0501234567",
                   "050-123-4567", "call me on +971 50 123 4567 today"):
        assert pat.search(sample), sample
    for not_phone in ("gold rose 4567 points", "ref 12345678901"):
        assert not pat.search(not_phone), not_phone


def test_classifier_rules_fire_on_the_documented_field(client) -> None:
    """Rules matching {"feature": "classifier"} used to read only an
    undocumented `_classifier_tier` key, so no real customer payload could ever
    trigger them."""
    H = _org(client)
    r = _gate(client, H, "model_completion",
              {"output": "you should buy X", "classifier": "individualised_advice"})
    assert r["status"] == "flagged"
    packs = {f.get("pack_code") for f in r["findings"]}
    assert "difc_dp_reg10" in packs and "uae_fin_enabling_tech" in packs
