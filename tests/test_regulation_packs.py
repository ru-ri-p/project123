"""Jurisdiction-aware policy: packs, composition, and the advisory posture.

The load-bearing guarantees:
  * an advisory finding can RAISE risk but never flips an allow into a deny;
  * every finding carries its citation and verification status, so an unreviewed
    rule cannot pass for a settled legal position;
  * findings are sealed into the signed policy_decision event, so which rulebook
    was applied is itself auditable after the fact.
"""

from __future__ import annotations

import uuid

import pytest


@pytest.fixture()
def db(db_available: bool):
    if not db_available:
        pytest.skip("PostgreSQL not available")
    from app.db.session import SessionLocal

    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


def _org(db, fail_mode: str = "deny_on_error"):
    from app.auth import hash_api_key
    from app.db.models import Org
    from app.repositories import policies as policy_repo

    org_id = f"org_pack_{uuid.uuid4().hex[:10]}"
    org = Org(
        id=org_id,
        name="Pack Test",
        api_key_hash=hash_api_key(f"key_{uuid.uuid4().hex}"),
        fail_mode=fail_mode,
    )
    db.add(org)
    # The institution authors its OWN policy — deliberately permissive here so
    # any tier rise must come from the jurisdiction packs.
    policy_repo.upsert_policy(
        db,
        org_id=org_id,
        name="Internal",
        version="v1",
        rules={"schema_version": 2, "engine": "json", "rules": []},
        active=True,
    )
    db.commit()
    return org


def test_seed_is_idempotent_and_covers_all_jurisdictions(db) -> None:
    from app.domain.jurisdictions import JURISDICTIONS
    from app.services import regulation_packs as svc

    svc.seed_builtin_packs(db)
    db.commit()
    first = {(p.code, p.version) for p in svc.list_packs(db)}
    svc.seed_builtin_packs(db)
    db.commit()
    second = {(p.code, p.version) for p in svc.list_packs(db)}
    assert first == second, "re-seeding must not duplicate packs"

    covered = {p.jurisdiction for p in svc.list_packs(db)}
    assert {"difc", "adgm", "uae_onshore"} <= covered
    assert covered <= set(JURISDICTIONS)


def test_every_shipped_rule_is_traceable_to_a_source(db) -> None:
    """No rule may cite a provision it cannot evidence, and no pack may claim
    review it has not had."""
    from app.domain.jurisdictions import VERIFICATION_STATUSES
    from app.domain.regulation_packs import BUILTIN_PACKS

    for pack in BUILTIN_PACKS:
        assert pack["verification_status"] in VERIFICATION_STATUSES
        # Nothing ships pre-blessed.
        assert pack["verification_status"] == "unverified"
        assert pack["instrument"], pack["code"]
        for rule in pack["rules"]:
            assert rule.get("reason"), rule["id"]
            assert "topic" in rule, rule["id"]
            # provision may be None (unconfirmed) but the key must be present so
            # a reviewer can see what still needs filling in.
            assert "provision" in rule, rule["id"]


def test_advisory_finding_raises_tier_but_never_denies(db) -> None:
    from app.services import regulation_packs as svc
    from app.services.precheck import run_precheck

    svc.seed_builtin_packs(db)
    db.commit()
    org = _org(db)
    svc.subscribe_org(db, org_id=org.id, pack_code="difc_dp_reg10")
    db.commit()

    # Payload carrying an email address trips the PII feature -> DIFC Reg 10.
    out = run_precheck(
        db,
        org=org,
        trace_id=uuid.uuid4(),
        seq=1,
        action="model_completion",
        payload={"output": "contact me at person@example.com"},
        policy_version=None,
    )
    db.commit()

    assert out["jurisdictions"] == ["difc"]
    assert out["regulatory_findings"], "expected a DIFC finding"
    finding = out["regulatory_findings"][0]
    assert finding["jurisdiction"] == "difc"
    assert finding["advisory_only"] is True
    assert finding["verification_status"] == "unverified"
    assert finding["instrument"].startswith("DIFC")
    assert out["allowed"] is True


def test_red_advisory_finding_raises_tier_without_blocking(db) -> None:
    """The load-bearing guarantee of the advisory posture.

    A pack rule at RED must raise the reported tier above the institution's own
    policy tier — and still not block, even under deny_on_error. An unreviewed
    rule that could halt a customer's business would be a liability, not a
    feature.
    """
    from app.services import regulation_packs as svc
    from app.services.precheck import run_precheck

    svc.seed_builtin_packs(db)
    db.commit()
    org = _org(db, fail_mode="deny_on_error")
    svc.subscribe_org(db, org_id=org.id, pack_code="difc_dp_reg10")
    db.commit()

    # Trips the DIFC Regulation 10 fairness rule (tier: red). No PII, so the
    # institution's own policy stays low and the rise is attributable to the pack.
    out = run_precheck(
        db,
        org=org,
        trace_id=uuid.uuid4(),
        seq=1,
        action="model_completion",
        payload={"output": "declined", "_classifier_tier": "discriminatory_lending"},
        policy_version=None,
    )
    db.commit()

    assert out["tier"] == "red", out
    assert out["policy_tier"] != "red", "the rise must come from the pack, not the policy"
    assert out["allowed"] is True, "an advisory pack must never block the action"
    assert out["approval_id"] is not None, "but it should route to a human"
    assert out["regulatory_findings"][0]["rule_id"] == "difc_reg10_fairness"


def test_findings_are_sealed_into_the_signed_decision_event(db) -> None:
    from app.db.models import Event
    from app.services import regulation_packs as svc
    from app.services.payload_store import read_payload_content
    from app.services.precheck import run_precheck

    svc.seed_builtin_packs(db)
    db.commit()
    org = _org(db)
    svc.subscribe_org(db, org_id=org.id, pack_code="difc_dp_reg10")
    db.commit()

    trace = uuid.uuid4()
    run_precheck(
        db, org=org, trace_id=trace, seq=1, action="model_completion",
        payload={"output": "email person@example.com"}, policy_version=None,
    )
    db.commit()

    ev = db.query(Event).filter(Event.trace_id == trace, Event.seq == 1).one()
    assert ev.type == "policy_decision"
    content = read_payload_content(db, org.id, ev.payload_hash)
    assert content is not None
    assert content["jurisdictions"] == ["difc"]
    assert content["regulatory_findings"][0]["pack_code"] == "difc_dp_reg10"


def test_unsubscribed_org_gets_no_findings(db) -> None:
    from app.services import regulation_packs as svc
    from app.services.precheck import run_precheck

    svc.seed_builtin_packs(db)
    db.commit()
    org = _org(db)  # no packs applied

    out = run_precheck(
        db, org=org, trace_id=uuid.uuid4(), seq=1, action="model_completion",
        payload={"output": "email person@example.com"}, policy_version=None,
    )
    db.commit()
    assert out["regulatory_findings"] == []
    assert out["jurisdictions"] == []


def test_blocking_enforcement_is_refused_until_reviewed(db) -> None:
    from app.services import regulation_packs as svc

    svc.seed_builtin_packs(db)
    db.commit()
    org = _org(db)
    with pytest.raises(svc.PackError):
        svc.subscribe_org(
            db, org_id=org.id, pack_code="difc_dp_reg10", enforcement="blocking"
        )


def test_unknown_pack_is_rejected(db) -> None:
    from app.services import regulation_packs as svc

    org = _org(db)
    with pytest.raises(svc.PackError):
        svc.subscribe_org(db, org_id=org.id, pack_code="no_such_pack")


def test_malformed_pack_rule_does_not_break_evaluation(db) -> None:
    """A broken advisory rule must never take down the customer's action path."""
    from app.db.models import RegulationPack
    from app.services import regulation_packs as svc
    from app.services.policy.features import extract_features
    from app.services.policy.packs import evaluate_packs

    svc.seed_builtin_packs(db)
    db.commit()
    org = _org(db)
    svc.subscribe_org(db, org_id=org.id, pack_code="difc_dp_reg10")
    db.commit()

    pack = svc.latest_pack_by_code(db, "difc_dp_reg10")
    assert pack is not None
    db.query(RegulationPack).filter(RegulationPack.id == pack.id).update(
        {"rules": {"schema_version": 2, "engine": "json",
                   "rules": ["not-an-object", {"id": "bad", "tier": "nonsense"}]}}
    )
    db.commit()

    features = extract_features("model_completion", {"output": "x"})
    findings = evaluate_packs(
        db, org_id=org.id, action="model_completion", payload={"output": "x"},
        features=features,
    )
    assert findings == []
