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


def _sources(db, pack_code):
    from app.services import reg_watch

    return [
        s
        for s in db.query(reg_watch.RegulationSource).filter(
            reg_watch.RegulationSource.pack_code == pack_code
        )
    ]


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
    # Drift needs confirming across two sweeps, so the first sighting is silent.
    first = reg_watch.check_source(db, source, fetcher=_fetcher(changed))
    db.commit()
    assert not [c for c in first if c.change_type == reg_watch.CHANGE_SOURCE_DRIFT]
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


def test_transient_failures_are_not_reported_as_withdrawn(db) -> None:
    """A rate limit says nothing about the instrument. Claiming it "may have been
    withdrawn" is simply false, and production hit exactly this on DIFC."""
    from app.services import reg_watch

    pack = _pack(db, candidates={"r1": "Article 26"})
    reg_watch.register_sources(db)
    source = next(
        s for s in db.query(reg_watch.RegulationSource).all() if s.pack_code == pack.code
    )

    for status, expected_type, must_say in (
        (429, reg_watch.CHANGE_SOURCE_UNAVAILABLE, "rate limited"),
        (503, reg_watch.CHANGE_SOURCE_UNAVAILABLE, "Transient"),
        (403, reg_watch.CHANGE_SOURCE_BLOCKED, "blocking the fetch"),
        (404, reg_watch.CHANGE_SOURCE_GONE, "withdrawn"),
    ):
        changes = reg_watch.check_source(db, source, fetcher=_fetcher("", status=status))
        db.commit()
        assert changes[0].change_type == expected_type, status
        assert must_say in changes[0].summary, status
        if status != 404:
            assert "withdrawn" not in changes[0].summary, f"{status} must not claim withdrawal"


def test_volatile_page_furniture_is_not_mistaken_for_a_law_change() -> None:
    """Nonces and scripts change on every fetch; the law does not."""
    from app.services.reg_watch import content_hash

    a = '<html><head><script>var t=1754280000;</script></head><body>Article 26</body></html>'
    b = '<html><head><script>var t=9999999999;</script></head><body>Article 26</body></html>'
    assert content_hash(a) == content_hash(b), "script noise must not read as drift"

    c = '<html><body>Article 26 and Article 30</body></html>'
    assert content_hash(a) != content_hash(c), "real text changes must still register"


def test_drift_is_only_reported_once_confirmed(db) -> None:
    from app.services import reg_watch

    pack = _pack(db, candidates={"r1": "Article 26"})
    reg_watch.register_sources(db)
    source = next(
        s for s in db.query(reg_watch.RegulationSource).all() if s.pack_code == pack.code
    )
    reg_watch.check_source(db, source, fetcher=_fetcher(OFFICIAL_TEXT))
    db.commit()

    # A one-off different response must NOT raise an alert...
    odd = OFFICIAL_TEXT + " transient banner"
    assert not [c for c in reg_watch.check_source(db, source, fetcher=_fetcher(odd))
                if c.change_type == reg_watch.CHANGE_SOURCE_DRIFT]
    db.commit()
    # ...and if the page reverts, nothing is ever reported.
    assert not [c for c in reg_watch.check_source(db, source, fetcher=_fetcher(OFFICIAL_TEXT))
                if c.change_type == reg_watch.CHANGE_SOURCE_DRIFT]
    db.commit()


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


# --- politeness: what the first live sweep's 429s prompted --------------------


def test_requests_to_the_same_host_are_spaced_apart() -> None:
    """Two packs cite difc.com. Asking for both at once is what earned the 429."""
    from app.services.reg_watch import HostPacer

    slept: list[float] = []
    now = {"t": 0.0}
    pacer = HostPacer(delay=6.0, sleeper=slept.append, clock=lambda: now["t"])

    pacer.mark("https://www.difc.com/a")
    waited = pacer.wait_for("https://www.difc.com/b")
    assert waited == 6.0 and slept == [6.0], "the second same-host fetch waits"

    # A DIFFERENT host is not made to wait for an unrelated site's limit.
    slept.clear()
    assert pacer.wait_for("https://u.ae/x") == 0.0
    assert slept == []

    # And once enough time has passed, no wait at all.
    now["t"] = 100.0
    slept.clear()
    assert pacer.wait_for("https://www.difc.com/c") == 0.0
    assert slept == []


def test_a_429_is_retried_and_can_then_succeed() -> None:
    """The host asked us to wait, not told us the instrument is gone."""
    from app.services.reg_watch import HostPacer, build_fetcher

    calls: list[str] = []
    responses = [
        (429, "", {"Retry-After": "2"}),
        (200, "<html>Article 26</html>", {}),
    ]

    def getter(url: str):
        calls.append(url)
        return responses[min(len(calls) - 1, len(responses) - 1)]

    slept: list[float] = []
    fetcher = build_fetcher(
        pacer=HostPacer(delay=0, sleeper=slept.append, clock=lambda: 0.0),
        getter=getter,
        sleeper=slept.append,
    )
    status, text = fetcher("https://www.difc.com/x")
    assert (status, len(calls)) == (200, 2), "retried once, then succeeded"
    assert 2.0 in slept, "the host's own Retry-After was honoured"


def test_retries_are_bounded_and_the_last_status_is_reported() -> None:
    """A persistently rate-limited host must not loop forever, and must still be
    reported honestly as transient rather than as a withdrawn instrument."""
    from app.services.reg_watch import (
        CHANGE_SOURCE_UNAVAILABLE,
        MAX_RETRIES,
        HostPacer,
        build_fetcher,
    )

    calls: list[str] = []

    def always_429(url: str):
        calls.append(url)
        return 429, "", {}

    fetcher = build_fetcher(
        pacer=HostPacer(delay=0, sleeper=lambda _: None, clock=lambda: 0.0),
        getter=always_429,
        sleeper=lambda _: None,
    )
    status, _ = fetcher("https://www.difc.com/x")
    assert status == 429
    assert len(calls) == MAX_RETRIES + 1, "bounded attempts, no infinite retry"
    assert CHANGE_SOURCE_UNAVAILABLE  # classified as transient, not source_gone


def test_an_absurd_retry_after_does_not_stall_the_sweep() -> None:
    """A cron holding a database session must not sleep for an hour."""
    from app.services.reg_watch import MAX_RETRY_WAIT, HostPacer, build_fetcher

    slept: list[float] = []
    fetcher = build_fetcher(
        pacer=HostPacer(delay=0, sleeper=lambda _: None, clock=lambda: 0.0),
        getter=lambda url: (429, "", {"Retry-After": "3600"}),
        sleeper=slept.append,
    )
    fetcher("https://www.difc.com/x")
    assert slept and max(slept) <= MAX_RETRY_WAIT


def test_a_malformed_retry_after_falls_back_to_our_own_backoff() -> None:
    from app.services.reg_watch import HostPacer, build_fetcher

    slept: list[float] = []
    fetcher = build_fetcher(
        pacer=HostPacer(delay=0, sleeper=lambda _: None, clock=lambda: 0.0),
        getter=lambda url: (429, "", {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
        sleeper=slept.append,
    )
    fetcher("https://www.difc.com/x")
    assert slept and all(v > 0 for v in slept), "HTTP-date form must not break pacing"


def test_pacing_still_refuses_non_https() -> None:
    from app.services.reg_watch import WatchError, build_fetcher

    fetcher = build_fetcher(getter=lambda url: (200, "", {}), sleeper=lambda _: None)
    with pytest.raises(WatchError):
        fetcher("http://www.difc.com/x")


# --- spreading the sweep across runs ------------------------------------------


def test_a_sweep_only_touches_the_sources_that_are_due(db) -> None:
    """The burst that earned the 429 was every source in one run. Cap it."""
    from app.services import reg_watch

    for _ in range(4):
        _pack(db)
    fetched: list[str] = []

    def fetcher(url: str):
        fetched.append(url)
        return 200, OFFICIAL_TEXT

    summary = reg_watch.run_watch(db, fetcher=fetcher, auto_publish=False, limit=2)
    assert len(fetched) == 2, "the run is bounded, whatever the backlog"
    assert summary["sources_checked"] == 2
    assert summary["sources_total"] > 2
    assert summary["sources_deferred"] > 0, "and it says so, rather than implying it is done"
    assert summary["next_due_at"], "the operator is told when the rest happens"


def test_a_checked_source_is_not_rechecked_until_it_is_due(db) -> None:
    """Otherwise every run hammers the same host — the original bug, per-run."""
    from datetime import UTC, datetime

    from app.services import reg_watch

    pack = _pack(db)
    reg_watch.register_sources(db)
    source = next(
        s for s in db.query(reg_watch.RegulationSource).all() if s.pack_code == pack.code
    )
    reg_watch.check_source(db, source, fetcher=_fetcher(OFFICIAL_TEXT), auto_publish=False)
    db.flush()

    assert source.next_check_at is not None
    assert source.next_check_at > datetime.now(UTC)
    due = reg_watch.due_sources(db, limit=0)
    assert source.id not in {s.id for s in due}, "freshly checked, so not due"


def test_a_source_that_failed_is_still_scheduled(db) -> None:
    """A source that stayed due after failing would be retried on every single
    run — which is exactly the hammering the pacing exists to prevent."""
    from app.services import reg_watch

    pack = _pack(db)
    reg_watch.register_sources(db)
    source = next(
        s for s in db.query(reg_watch.RegulationSource).all() if s.pack_code == pack.code
    )

    def explode(url: str):
        raise ConnectionError("egress blocked")

    changes = reg_watch.check_source(db, source, fetcher=explode, auto_publish=False)
    db.flush()
    assert changes and changes[0].change_type == reg_watch.CHANGE_FETCH_FAILED
    assert source.next_check_at is not None, "a dead source must not be retried in a loop"
    assert source.id not in {s.id for s in reg_watch.due_sources(db, limit=0)}


def test_a_never_checked_source_is_picked_up_first(db) -> None:
    """A newly registered pack must not wait out an interval it was never in."""
    from datetime import UTC, datetime, timedelta

    from app.services import reg_watch

    fresh = _pack(db)     # checked a moment ago — not due
    overdue = _pack(db)   # was due an hour ago
    new = _pack(db)       # never checked, and the youngest of the three
    reg_watch.register_sources(db)
    ours = {
        s.pack_code: s
        for s in db.query(reg_watch.RegulationSource).filter(
            reg_watch.RegulationSource.pack_code.in_([fresh.code, overdue.code, new.code])
        )
    }
    now = datetime.now(UTC)
    ours[fresh.code].next_check_at = now + timedelta(hours=12)
    ours[overdue.code].next_check_at = now - timedelta(hours=1)
    db.flush()

    ordered = [s.pack_code for s in reg_watch.due_sources(db, limit=0)]
    assert new.code in ordered, "a never-checked source is due immediately"
    assert fresh.code not in ordered, "a freshly checked one waits its turn"
    assert ordered.index(new.code) < ordered.index(overdue.code), (
        "and it sorts ahead of merely overdue sources, so a new pack is never starved"
    )



# --- a corrected source URL must actually displace the old one ----------------


def test_a_corrected_source_url_retires_the_dead_one(db) -> None:
    """The ops dashboard showed ADGM's OLD, dead URL being fetched daily long
    after it was corrected. Each pack VERSION is its own row, so the previous
    version kept re-registering its dead link on every sweep — a watcher that
    reports the same 404 forever is one nobody reads."""
    from app.services import reg_watch
    from app.services.regulation_packs import upsert_pack

    code = f"testpack_{uuid.uuid4().hex[:8]}"
    dead = "https://example.test/legal-framework/legislation"
    good = "https://example.test/legal-framework"

    def publish(version: str, url: str):
        upsert_pack(db, {
            "code": code, "jurisdiction": "adgm", "jurisdictions": ["adgm"],
            "sectors": ["*"], "name": "Test", "version": version,
            "instrument": "Test Instrument", "source_url": url,
            "verification_status": "unverified", "schema_version": 2,
            "engine": "json", "rules": [],
        })
        db.commit()

    publish("1.0", dead)
    reg_watch.register_sources(db)
    db.flush()
    assert {s.url for s in _sources(db, code)} == {dead}

    # The dead link is found and corrected — a new pack VERSION, as required.
    publish("1.1", good)
    reg_watch.register_sources(db)
    db.flush()

    by_url = {s.url: s for s in _sources(db, code)}
    assert set(by_url) == {dead, good}, "the old row is kept, not deleted"
    assert by_url[good].retired_at is None, "the corrected URL is live"
    assert by_url[dead].retired_at is not None, "the dead one is retired"

    # And crucially: never fetched again, however overdue it looks. Scoped to
    # this pack — the shared dev database carries rows from earlier runs, and a
    # global URL match would assert about those instead.
    due = {s.url for s in reg_watch.due_sources(db, limit=0) if s.pack_code == code}
    assert good in due and dead not in due

    # Re-running must not resurrect it — this is what looped before.
    reg_watch.register_sources(db)
    db.flush()
    assert {s.url for s in reg_watch.due_sources(db, limit=0) if s.pack_code == code} == {good}


def test_a_retired_source_keeps_its_evidence(db) -> None:
    """Retired, never deleted: the snapshot is the evidence behind anything
    published from that source, and an auditor must still be able to check it."""
    from app.services import reg_watch
    from app.services.regulation_packs import upsert_pack

    pack = _pack(db, candidates={"r1": "Article 26"})
    reg_watch.register_sources(db)
    source = next(s for s in _sources(db, pack.code))
    reg_watch.check_source(db, source, fetcher=_fetcher(OFFICIAL_TEXT), auto_publish=False)
    db.flush()
    assert source.snapshot and source.content_hash

    upsert_pack(db, {
        "code": pack.code, "jurisdiction": "difc", "jurisdictions": ["difc"],
        "sectors": ["*"], "name": "Test Pack", "version": "2.0",
        "instrument": "Test Instrument", "source_url": "https://example.test/moved",
        "verification_status": "unverified", "schema_version": 2,
        "engine": "json", "rules": [],
    })
    db.commit()
    reg_watch.register_sources(db)
    db.flush()

    assert source.retired_at is not None
    assert source.snapshot, "the snapshot survives retirement"
    assert source.content_hash, "and so does the hash it was verified against"


def test_a_pack_citing_a_url_again_brings_it_back(db) -> None:
    """Retirement must be reversible, or a reverted correction is unfetchable."""
    from app.services import reg_watch
    from app.services.regulation_packs import upsert_pack

    code = f"testpack_{uuid.uuid4().hex[:8]}"
    a, b = "https://example.test/a", "https://example.test/b"

    def publish(version: str, url: str):
        upsert_pack(db, {
            "code": code, "jurisdiction": "difc", "jurisdictions": ["difc"],
            "sectors": ["*"], "name": "Test", "version": version,
            "instrument": "I", "source_url": url, "verification_status": "unverified",
            "schema_version": 2, "engine": "json", "rules": [],
        })
        db.commit()

    publish("1.0", a)
    reg_watch.register_sources(db)
    publish("1.1", b)
    reg_watch.register_sources(db)
    db.flush()
    assert {s.url for s in _sources(db, code) if s.retired_at is None} == {b}

    publish("1.2", a)  # the correction is reverted
    reg_watch.register_sources(db)
    db.flush()
    live = {s.url for s in _sources(db, code) if s.retired_at is None}
    assert live == {a}, "the original comes back live, and b retires"


# --- bot protection is not congestion -----------------------------------------


def test_we_identify_ourselves_honestly_to_regulators() -> None:
    """Both centralbank.ae URLs 403'd and both difc.com URLs 429'd on the first
    request of the day, after pacing and retries. That is bot protection, and the
    honest response is to say who we are — not to impersonate a browser."""
    from app.services.reg_watch import request_headers

    h = request_headers()
    ua = h["User-Agent"]
    assert "Attest" in ua, "the operator must be nameable from the log line"
    assert "+http" in ua, "and reachable, so a site owner can allow-list us"
    assert h["Accept"], "absent Accept headers are themselves a scraper signal"
    lowered = ua.lower()
    for pretend in ("mozilla", "chrome", "safari", "webkit", "gecko"):
        assert pretend not in lowered, (
            "we must never pose as a browser to get around a block — if a "
            "regulator refuses an honestly-identified client, that is their call"
        )


def test_a_persistent_429_stops_being_called_transient(db) -> None:
    """Reporting 'transient, will retry' every day about a permanent block is how
    a quarantine queue becomes something nobody reads."""
    from app.services import reg_watch

    pack = _pack(db)
    reg_watch.register_sources(db)
    source = next(s for s in _sources(db, pack.code))

    summaries = []
    for _ in range(reg_watch.PERSISTENT_FAILURE_THRESHOLD):
        source.next_check_at = None
        changes = reg_watch.check_source(
            db, source, fetcher=_fetcher("", status=429), auto_publish=False
        )
        summaries.append(changes[0])
    db.flush()

    first, last = summaries[0], summaries[-1]
    assert first.change_type == reg_watch.CHANGE_SOURCE_UNAVAILABLE
    assert "Transient" in first.summary, "one 429 really might be congestion"

    assert last.change_type == reg_watch.CHANGE_SOURCE_BLOCKED, (
        "a rate limit that never clears is bot protection"
    )
    assert "Transient" not in last.summary
    assert "bot protection" in last.summary
    assert source.consecutive_failures == reg_watch.PERSISTENT_FAILURE_THRESHOLD
    assert last.evidence["consecutive_failures"] == source.consecutive_failures


def test_reaching_the_page_clears_the_streak(db) -> None:
    """Otherwise a site that recovers is libelled as blocked forever."""
    from app.services import reg_watch

    pack = _pack(db)
    reg_watch.register_sources(db)
    source = next(s for s in _sources(db, pack.code))

    for _ in range(4):
        source.next_check_at = None
        reg_watch.check_source(db, source, fetcher=_fetcher("", status=429),
                               auto_publish=False)
    assert source.consecutive_failures == 4

    source.next_check_at = None
    reg_watch.check_source(db, source, fetcher=_fetcher(OFFICIAL_TEXT), auto_publish=False)
    db.flush()
    assert source.consecutive_failures == 0, "a success is a clean slate"


def test_a_404_is_never_softened_by_the_streak_logic(db) -> None:
    """A dead link is evidence about the INSTRUMENT, and must keep saying so
    however many times we have seen it."""
    from app.services import reg_watch

    pack = _pack(db)
    reg_watch.register_sources(db)
    source = next(s for s in _sources(db, pack.code))

    for _ in range(reg_watch.PERSISTENT_FAILURE_THRESHOLD + 1):
        source.next_check_at = None
        changes = reg_watch.check_source(
            db, source, fetcher=_fetcher("", status=404), auto_publish=False
        )
    db.flush()
    assert changes[0].change_type == reg_watch.CHANGE_SOURCE_GONE
    assert "withdrawn" in changes[0].summary
