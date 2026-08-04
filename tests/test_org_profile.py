"""Settings: obligations derived from jurisdiction x sector, and not droppable.

The point of the whole feature is that a firm cannot pick its way to a clean
dashboard. So the tests that matter are the ones that try to evade:

  * mandatory packs are DERIVED, and every one is applied automatically;
  * adding a sector applies at once (more obligations is never the risk);
  * removing one does NOT take effect — it raises a request for Attest, and the
    dropped rulebooks keep applying until that is approved;
  * there is no unsubscribe endpoint to sneak out through.
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


def _org(client) -> str:
    org_id = f"org_prof_{uuid.uuid4().hex[:10]}"
    return client.post("/v1/admin/orgs", headers=A,
                       json={"org_id": org_id, "name": "Profile Test"}).json()["api_key"]


def test_sector_taxonomy_is_complete_and_grounded(client) -> None:
    """Any customer must be able to classify themselves, and the taxonomy must
    map to a recognised standard rather than being invented here."""
    from app.domain.sectors import SECTORS

    body = client.get("/v1/policies/sectors", headers={"x-api-key": _org(client)}).json()
    codes = {s["code"] for g in body["groups"] for s in g["sectors"]}
    assert codes == {s.code for s in SECTORS}
    # Every sector carries an ISIC Rev.4 mapping, and there is always a fallback.
    assert all(s["isic"] for g in body["groups"] for s in g["sectors"])
    assert "other" in codes
    # The regulated, AI-sensitive groups are present.
    groups = {g["group"] for g in body["groups"]}
    assert {"Financial services", "Health", "Public sector"} <= groups


def test_profile_derives_packs_across_both_axes(client) -> None:
    """A DIFC capital-markets firm gets DIFC data protection (jurisdiction-wide)
    AND the joint financial-sector AI guidelines (sector-wide, all jurisdictions)
    — but not the healthcare pack, and not the onshore-only CBUAE one."""
    key = _org(client)
    r = client.put("/v1/policies/profile", headers={"x-api-key": key},
                   json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["applied"] is True

    codes = set(body["profile"]["mandatory_pack_codes"])
    assert "difc_dp_reg10" in codes and "difc_dp_law_5_2020" in codes
    assert "uae_fin_enabling_tech" in codes, "joint guidelines reach DIFC firms too"
    assert "uae_health_ai" not in codes, "wrong sector"
    assert "cbuae_ai_consumer" not in codes, "CBUAE does not supervise DIFC firms"
    assert "adgm_dp_regs" not in codes, "wrong jurisdiction"

    # Everything derived is actually applied, not merely listed.
    mine = {p["code"] for p in client.get("/v1/policies/packs/mine",
                                          headers={"x-api-key": key}).json()}
    assert codes <= mine


def test_multiple_sectors_and_jurisdictions_accumulate(client) -> None:
    key = _org(client)
    body = client.put("/v1/policies/profile", headers={"x-api-key": key}, json={
        "jurisdictions": ["difc", "uae_onshore"],
        "sectors": ["banking", "healthcare_provider"]}).json()
    codes = set(body["profile"]["mandatory_pack_codes"])
    assert {"difc_dp_reg10", "uae_onshore_core", "uae_fin_enabling_tech",
            "cbuae_ai_consumer", "uae_health_ai"} <= codes


def test_adding_applies_immediately(client) -> None:
    key = _org(client)
    client.put("/v1/policies/profile", headers={"x-api-key": key},
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    r = client.put("/v1/policies/profile", headers={"x-api-key": key}, json={
        "jurisdictions": ["difc", "uae_onshore"],
        "sectors": ["capital_markets", "healthcare_provider"]})
    body = r.json()
    assert body["applied"] is True and body["pending_approval"] is False
    assert "uae_health_ai" in body["profile"]["mandatory_pack_codes"]


def test_removing_a_sector_does_not_take_effect_without_approval(client) -> None:
    """THE anti-evasion test. Declaring your way out of obligations must fail."""
    key = _org(client)
    client.put("/v1/policies/profile", headers={"x-api-key": key}, json={
        "jurisdictions": ["difc", "uae_onshore"],
        "sectors": ["banking", "healthcare_provider"]})

    r = client.put("/v1/policies/profile", headers={"x-api-key": key}, json={
        "jurisdictions": ["difc"], "sectors": ["banking"],
        "reason": "we exited healthcare"})
    assert r.status_code == 200
    body = r.json()
    assert body["applied"] is False and body["pending_approval"] is True
    assert set(body["removed"]) == {"uae_onshore", "healthcare_provider"}

    # Unchanged until Attest decides — the obligations still bind.
    profile = client.get("/v1/policies/profile", headers={"x-api-key": key}).json()
    assert set(profile["sectors"]) == {"banking", "healthcare_provider"}
    assert "uae_health_ai" in profile["mandatory_pack_codes"]
    mine = {p["code"] for p in client.get("/v1/policies/packs/mine",
                                          headers={"x-api-key": key}).json()}
    assert "uae_health_ai" in mine, "the rulebook must keep applying while pending"


def test_reduction_requires_a_reason_and_shows_up_for_attest(client) -> None:
    key = _org(client)
    client.put("/v1/policies/profile", headers={"x-api-key": key},
               json={"jurisdictions": ["difc"], "sectors": ["banking", "legal"]})

    # No reason -> refused outright.
    r = client.put("/v1/policies/profile", headers={"x-api-key": key},
                   json={"jurisdictions": ["difc"], "sectors": ["banking"]})
    assert r.status_code == 400

    client.put("/v1/policies/profile", headers={"x-api-key": key},
               json={"jurisdictions": ["difc"], "sectors": ["banking"],
                     "reason": "legal work moved to an affiliate"})
    pending = client.get("/v1/admin/profile-changes", headers=A).json()
    assert any(p["removed"] == ["legal"] for p in pending)


def test_attest_approval_applies_the_reduction(client) -> None:
    key = _org(client)
    client.put("/v1/policies/profile", headers={"x-api-key": key},
               json={"jurisdictions": ["difc"], "sectors": ["banking", "legal"]})
    req_id = client.put("/v1/policies/profile", headers={"x-api-key": key},
                        json={"jurisdictions": ["difc"], "sectors": ["banking"],
                              "reason": "moved"}).json()["request_id"]

    r = client.post(f"/v1/admin/profile-changes/{req_id}/decide?approve=true", headers=A)
    assert r.status_code == 200 and r.json()["status"] == "approved"
    profile = client.get("/v1/policies/profile", headers={"x-api-key": key}).json()
    assert profile["sectors"] == ["banking"]


def test_attest_can_refuse_a_reduction(client) -> None:
    key = _org(client)
    client.put("/v1/policies/profile", headers={"x-api-key": key},
               json={"jurisdictions": ["difc"], "sectors": ["banking", "legal"]})
    req_id = client.put("/v1/policies/profile", headers={"x-api-key": key},
                        json={"jurisdictions": ["difc"], "sectors": ["banking"],
                              "reason": "nope"}).json()["request_id"]

    r = client.post(f"/v1/admin/profile-changes/{req_id}/decide?approve=false", headers=A)
    assert r.json()["status"] == "denied"
    profile = client.get("/v1/policies/profile", headers={"x-api-key": key}).json()
    assert set(profile["sectors"]) == {"banking", "legal"}, "denied means unchanged"


def test_there_is_no_route_to_adopt_a_pack_directly(client) -> None:
    """The picker was the visible remnant of cherry-picking; it is gone, and so
    is the endpoint behind it. Rulebooks come only from the profile."""
    key = _org(client)
    client.put("/v1/policies/profile", headers={"x-api-key": key},
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    r = client.post("/v1/policies/packs/subscribe", headers={"x-api-key": key},
                    json={"pack_code": "adgm_dp_regs"})
    assert r.status_code == 405 or r.status_code == 404, r.status_code


def test_applied_rulebooks_always_equal_what_the_profile_derives(client) -> None:
    """The bug this fixes: a DIFC firm was carrying ADGM, because legacy
    subscriptions were never reconciled against the profile."""
    from app.db.models import OrgRegulationPack
    from app.db.session import SessionLocal
    from app.services.regulation_packs import latest_pack_by_code

    key = _org(client)
    org_id = client.get("/v1/org/me", headers={"x-api-key": key}).json()["id"]
    client.put("/v1/policies/profile", headers={"x-api-key": key},
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})

    # Simulate a legacy subscription from the cherry-pick era.
    db = SessionLocal()
    adgm = latest_pack_by_code(db, "adgm_dp_regs")
    db.add(OrgRegulationPack(org_id=org_id, pack_id=adgm.id))
    db.commit()
    db.close()
    mine = {p["code"] for p in client.get("/v1/policies/packs/mine",
                                          headers={"x-api-key": key}).json()}
    assert "adgm_dp_regs" in mine, "precondition: the stray subscription exists"

    # Saving the profile again snaps the applied set back to the truth.
    client.put("/v1/policies/profile", headers={"x-api-key": key},
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    mine = {p["code"] for p in client.get("/v1/policies/packs/mine",
                                          headers={"x-api-key": key}).json()}
    assert "adgm_dp_regs" not in mine, "a rulebook that does not apply must be removed"
    assert "difc_dp_reg10" in mine and "uae_fin_enabling_tech" in mine


def test_approved_reduction_removes_the_rulebooks_it_dropped(client) -> None:
    """Removal only happens AFTER Attest approves, so nothing is shed unilaterally."""
    key = _org(client)
    client.put("/v1/policies/profile", headers={"x-api-key": key}, json={
        "jurisdictions": ["difc", "uae_onshore"], "sectors": ["banking"]})
    assert "cbuae_ai_consumer" in {
        p["code"] for p in client.get("/v1/policies/packs/mine",
                                      headers={"x-api-key": key}).json()}

    req_id = client.put("/v1/policies/profile", headers={"x-api-key": key}, json={
        "jurisdictions": ["difc"], "sectors": ["banking"],
        "reason": "onshore entity wound up"}).json()["request_id"]
    # Still applied while pending — the request must not be the evasion.
    assert "cbuae_ai_consumer" in {
        p["code"] for p in client.get("/v1/policies/packs/mine",
                                      headers={"x-api-key": key}).json()}

    client.post(f"/v1/admin/profile-changes/{req_id}/decide?approve=true", headers=A)
    assert "cbuae_ai_consumer" not in {
        p["code"] for p in client.get("/v1/policies/packs/mine",
                                      headers={"x-api-key": key}).json()}


def test_compliance_summary_reports_applied_jurisdictions_from_the_profile(client) -> None:
    """The tile said 'none' for a correctly-configured org that simply had not
    been checked yet, because it was counting findings rather than obligations."""
    key = _org(client)
    client.put("/v1/policies/profile", headers={"x-api-key": key},
               json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    summary = client.get("/v1/policies/compliance-summary",
                         headers={"x-api-key": key}).json()
    assert summary["decisions_total"] == 0, "nothing checked yet"
    assert summary["applied_jurisdictions"] == ["difc"], "yet DIFC plainly applies"


def test_invalid_profiles_are_rejected(client) -> None:
    key = _org(client)
    for payload in (
        {"jurisdictions": ["difc"], "sectors": ["not_a_sector"]},
        {"jurisdictions": ["atlantis"], "sectors": ["banking"]},
        {"jurisdictions": ["internal"], "sectors": ["banking"]},  # not a real jurisdiction
    ):
        assert client.put("/v1/policies/profile", headers={"x-api-key": key},
                          json=payload).status_code == 400
    assert client.put("/v1/policies/profile", headers={"x-api-key": key},
                      json={"jurisdictions": [], "sectors": []}).status_code == 422
