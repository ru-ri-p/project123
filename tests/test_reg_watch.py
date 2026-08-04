"""Auto-updating regulation packs without inventing anything.

The user asked for auto-publish, with the condition that nothing may be
fabricated. These tests are the proof of that condition, so they are written as
attacks rather than happy paths:

  * a citation that is NOT in the official text must never publish, however
    plausible it looks;
  * a changed regulation must never auto-update rule CONTENT, because deciding
    what a change means is judgement;
  * a source fetched from anywhere but the registered HTTPS URL is refused;
  * an extraction that is not reproducible is treated as unknown;
  * auto-published packs must never claim legal review.
"""

from __future__ import annotations

import uuid

import pytest

# A stand-in for an official text. Contains "Article 26" but NOT "Article 99".
OFFICIAL_TEXT = """
DATA PROTECTION LAW, DIFC LAW NO. 5 OF 2020

Article 10 — High Risk Processing Activities
Article 20 — Data Protection Impact Assessment
Article 26 — List of Adequate Data Protection Regimes
This law came into force on 1 July 2020.
"""


@pytest.fixture()
def db(db_available: bool):
    if not db_available:
        pytest.skip("PostgreSQL not available")
    from app.db.session import SessionLocal

    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


def _pack(db, *, candidates: dict[str, str] | None = None, code: str | None = None):
    """Publish a pack whose rules declare provision CANDIDATES to be confirmed."""
    from app.services.regulation_packs import upsert_pack

    code = code or f"testpack_{uuid.uuid4().hex[:8]}"
    rules = [
        {"id": rule_id, "priority": 100, "tier": "orange", "decision": "flag",
         "match": {"has_pii": True}, "reason": "test", "topic": "t",
         "provision": None, "provision_candidate": candidate}
        for rule_id, candidate in (candidates or {}).items()
    ]
    pack = upsert_pack(db, {
        "code": code, "jurisdiction": "difc", "jurisdictions": ["difc"], "sectors": ["*"],
        "name": "Test Pack", "version": "1.0", "instrument": "Test Instrument",
        "source_url": "https://example.test/official", "verification_status": "unverified",
        "schema_version": 2, "engine": "json", "rules": rules,
    })
    db.commit()
    return pack


def _fetcher(text: str, status: int = 200):
    return lambda url: (status, text)


def test_a_citation_not_in_the_source_is_never_published(db) -> None:
    """THE anti-fabrication test. A plausible but absent citation must not ship."""
    from app.services import reg_watch

    pack = _pack(db, candidates={"real": "Article 26", "invented": "Article 99"})
    reg_watch.register_sources(db)
    source = next(
        s for s in db.query(reg_watch.RegulationSource).all() if s.pack_code == pack.code
    )
    reg_watch.check_source(db, source, fetcher=_fetcher(OFFICIAL_TEXT))
    db.commit()

    published = (
        db.query(reg_watch.RegulationPack)
        .filter(reg_watch.RegulationPack.code == pack.code)
        .order_by(reg_watch.RegulationPack.created_at.desc())
        .first()
    )
    by_id = {r["id"]: r for r in published.rules["rules"]}
    assert by_id["real"]["provision"] == "Article 26", "the provable one is confirmed"
    assert by_id["invented"]["provision"] is None, "the absent one must NOT be published"


def test_verbatim_gate_rejects_paraphrase_and_emptiness() -> None:
    from app.services.reg_watch import appears_verbatim

    assert appears_verbatim("Article 26", OFFICIAL_TEXT)
    assert appears_verbatim("article   26", OFFICIAL_TEXT), "whitespace/case normalised"
    assert not appears_verbatim("Article 26 bis", OFFICIAL_TEXT)
    assert not appears_verbatim("the article about adequacy", OFFICIAL_TEXT), "no paraphrase"
    # An empty claim must not sail through as trivially contained.
    assert not appears_verbatim("", OFFICIAL_TEXT)
    assert not appears_verbatim("   ", OFFICIAL_TEXT)


def test_changed_regulation_never_auto_updates_rule_content(db) -> None:
    """Deciding what a changed regulation MEANS is judgement, not extraction."""
    from app.services import reg_watch

    pack = _pack(db, candidates={"r1": "Article 10"})
    reg_watch.register_sources(db)
    source = next(
        s for s in db.query(reg_watch.RegulationSource).all() if s.pack_code == pack.code
    )
    reg_watch.check_source(db, source, fetcher=_fetcher(OFFICIAL_TEXT))
    db.commit()

    changed = OFFICIAL_TEXT + "\nArticle 30 — A brand new obligation appears.\n"
    changes = reg_watch.check_source(db, source, fetcher=_fetcher(changed))
    db.commit()

    drift = [c for c in changes if c.change_type == reg_watch.CHANGE_SOURCE_DRIFT]
    assert len(drift) == 1
    assert drift[0].status == reg_watch.STATUS_QUARANTINED
    assert "never auto-updated" in drift[0].summary
    # The new obligation was NOT invented into the pack.
    published = (
        db.query(reg_watch.RegulationPack)
        .filter(reg_watch.RegulationPack.code == pack.code)
        .order_by(reg_watch.RegulationPack.created_at.desc())
        .first()
    )
    assert not any("Article 30" in str(r) for r in published.rules["rules"])


def test_non_https_sources_are_refused(db) -> None:
    """Provenance is worthless if the transport can be tampered with."""
    from app.services.reg_watch import WatchError, default_fetcher

    with pytest.raises(WatchError):
        default_fetcher("http://example.test/official")


def test_unreproducible_extraction_is_quarantined_not_published() -> None:
    from app.services.reg_watch import reproducible

    stable, ok = reproducible(lambda: {"a": "1"})
    assert ok and stable == {"a": "1"}

    counter = {"n": 0}

    def flaky() -> dict[str, str]:
        counter["n"] += 1
        return {"a": str(counter["n"])}

    _, ok = reproducible(flaky)
    assert not ok, "variance means the source did not determine it"


def test_auto_published_packs_never_claim_legal_review(db) -> None:
    from app.services import reg_watch

    pack = _pack(db, candidates={"r1": "Article 20"})
    reg_watch.register_sources(db)
    source = next(
        s for s in db.query(reg_watch.RegulationSource).all() if s.pack_code == pack.code
    )
    reg_watch.check_source(db, source, fetcher=_fetcher(OFFICIAL_TEXT))
    db.commit()

    published = (
        db.query(reg_watch.RegulationPack)
        .filter(reg_watch.RegulationPack.code == pack.code)
        .order_by(reg_watch.RegulationPack.created_at.desc())
        .first()
    )
    assert published.verification_status == reg_watch.SOURCE_VERIFIED
    assert published.verification_status != "counsel_reviewed"
    # Published as a NEW version — the old one must remain, so the record of what
    # was live on a given date stays true.
    versions = [
        p.version for p in db.query(reg_watch.RegulationPack).filter(
            reg_watch.RegulationPack.code == pack.code
        )
    ]
    assert "1.0" in versions and len(versions) >= 2


def test_a_confirmed_citation_carries_its_evidence(db) -> None:
    """Someone must be able to re-check the claim against the text it came from."""
    from app.services import reg_watch

    pack = _pack(db, candidates={"r1": "Article 26"})
    reg_watch.register_sources(db)
    source = next(
        s for s in db.query(reg_watch.RegulationSource).all() if s.pack_code == pack.code
    )
    changes = reg_watch.check_source(db, source, fetcher=_fetcher(OFFICIAL_TEXT))
    db.commit()

    published = [c for c in changes if c.status == reg_watch.STATUS_AUTO_PUBLISHED]
    assert len(published) == 1
    ev = published[0].evidence
    assert ev["gates_passed"] == ["provenance", "verbatim", "reproducibility"]
    assert ev["confirmed"] == {"r1": "Article 26"}
    # The snapshot the claim was proven against is retained.
    assert source.snapshot and "Article 26" in source.snapshot
    assert source.content_hash


def test_a_dead_source_is_flagged_not_ignored(db) -> None:
    from app.services import reg_watch

    pack = _pack(db, candidates={"r1": "Article 26"})
    reg_watch.register_sources(db)
    source = next(
        s for s in db.query(reg_watch.RegulationSource).all() if s.pack_code == pack.code
    )
    changes = reg_watch.check_source(db, source, fetcher=_fetcher("", status=404))
    db.commit()

    assert changes[0].change_type == reg_watch.CHANGE_SOURCE_GONE
    assert changes[0].status == reg_watch.STATUS_QUARANTINED
    assert "withdrawn" in changes[0].summary


def test_a_failing_source_does_not_stop_the_sweep(db) -> None:
    from app.services import reg_watch

    _pack(db, candidates={"r1": "Article 26"})
    reg_watch.register_sources(db)

    def exploding(url: str):
        raise ConnectionError("network down")

    summary = reg_watch.run_watch(db, fetcher=exploding)
    db.commit()
    assert summary["sources_checked"] >= 1
    assert summary["quarantined"] >= 1


def test_already_confirmed_provisions_are_not_overwritten(db) -> None:
    """A human-verified citation must not be silently replaced by the machine."""
    from app.services import reg_watch
    from app.services.regulation_packs import upsert_pack

    code = f"testpack_{uuid.uuid4().hex[:8]}"
    upsert_pack(db, {
        "code": code, "jurisdiction": "difc", "jurisdictions": ["difc"], "sectors": ["*"],
        "name": "T", "version": "1.0", "instrument": "I",
        "source_url": "https://example.test/official", "verification_status": "counsel_reviewed",
        "schema_version": 2, "engine": "json",
        "rules": [{"id": "r1", "tier": "orange", "match": {"has_pii": True}, "reason": "x",
                   "provision": "Article 10", "provision_candidate": "Article 26"}],
    })
    db.commit()
    pack = db.query(reg_watch.RegulationPack).filter(
        reg_watch.RegulationPack.code == code).first()
    assert reg_watch.extract_confirmations(pack, OFFICIAL_TEXT) == {}
