"""Keeping regulation packs current — automatically, without inventing anything.

THE PROBLEM WITH AUTO-PUBLISHING LAW
====================================
No regulator publishes a machine-readable feed of rule changes; it is web pages
and PDFs. The tempting design is to fetch the page, have something summarise what
changed, and publish the result. That design invents clause numbers. A rules
engine citing "Article 26" of an instrument that has no Article 26 is worse than
one that admits it has not checked — it manufactures false authority, and a
regulator will find it.

So nothing here GENERATES rule content. The pipeline only ever CONFIRMS claims
that are already written down, against the official text they claim to come from.
A claim that cannot be proven verbatim is not published; it is quarantined for a
person. That is what makes "auto-publish" defensible rather than reckless.

THE THREE GATES
===============
Every candidate must pass all three, in order, or it is quarantined:

  GATE 1 — PROVENANCE.  The text must have been fetched over HTTPS from the URL
      already registered against the pack, and the exact bytes are snapshotted
      and hashed. Nothing enters the pipeline from anywhere else, and every
      published claim stays re-checkable against the text it came from.

  GATE 2 — VERBATIM GROUNDING.  Every claim (a provision reference, a quoted
      obligation, an effective date) must appear literally in that snapshot,
      compared on normalised whitespace and case. No paraphrase, no inference,
      no "close enough". This is the gate that makes fabrication structurally
      impossible rather than merely unlikely: if the string is not in the
      official text, it cannot be published, whatever produced it.

  GATE 3 — REPRODUCIBILITY.  The extraction is run repeatedly and only fields
      identical across every run pass. Any variance means the answer was not
      determined by the source, so it is treated as unknown.

WHAT AUTO-PUBLISHES, AND WHAT DOES NOT
======================================
Auto-published: confirming a `provision_candidate` that is found verbatim, and
metadata (effective dates) likewise found verbatim. These add citation precision
to rules a human already wrote.

Never auto-published: new obligations, changed risk tiers, altered rule meaning,
or anything at all when the source text changed materially. Those are
quarantined, because deciding what a changed regulation MEANS is judgement, and
judgement is exactly what this pipeline must not pretend to have.

Auto-published packs are marked SOURCE_VERIFIED — a status that says "mechanically
checked against the official text", and which must never be read as, or promoted
to, `counsel_reviewed`.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.db.models import RegulationChange, RegulationPack, RegulationSource

# A new verification status, distinct from anything implying legal review.
SOURCE_VERIFIED = "source_verified"

CHANGE_SOURCE_DRIFT = "source_drift"
CHANGE_SOURCE_BLOCKED = "source_blocked"
CHANGE_SOURCE_UNAVAILABLE = "source_unavailable"
CHANGE_PROVISION_CONFIRMED = "provision_confirmed"
CHANGE_FETCH_FAILED = "fetch_failed"
CHANGE_SOURCE_GONE = "source_gone"

STATUS_QUARANTINED = "quarantined"
STATUS_AUTO_PUBLISHED = "auto_published"
STATUS_DISMISSED = "dismissed"
STATUS_ACTIONED = "actioned"

# Reproducibility passes required before a claim may be published (Gate 3).
REPRODUCIBILITY_RUNS = 3

# --- politeness ---------------------------------------------------------------
# difc.com returned 429 to two near-simultaneous fetches on the first live sweep:
# two packs cite the same host, and we asked for both at once. The answer has two
# halves, because "all at once" was true in two different ways.
#
#   WITHIN a run — a minimum gap between requests to the SAME host. Per host
#       rather than global, because the constraint belongs to the host; slowing
#       every request to protect one site would make the sweep needlessly slow.
#
#   ACROSS runs — a run only touches sources that are DUE, and at most a handful
#       of them. Seven sources checked daily is seven requests a day; the old
#       design delivered all seven inside one second. Spreading them also keeps
#       the operator's "Run sweep" button responsive, since a request that holds
#       a database session while it sleeps is its own kind of bug.
DEFAULT_HOST_DELAY = float(os.environ.get("REGWATCH_HOST_DELAY_SECONDS", "6"))
# How long a source stays fresh once checked. A regulator does not amend an
# instrument hourly; daily is already far more often than the law changes.
CHECK_INTERVAL_SECONDS = float(
    os.environ.get("REGWATCH_CHECK_INTERVAL_SECONDS", str(24 * 60 * 60))
)
# Most sources one run will touch. Bounds both the politeness burst and the
# wall-clock time an operator spends staring at a spinner.
MAX_SOURCES_PER_RUN = int(os.environ.get("REGWATCH_MAX_SOURCES_PER_RUN", "3"))
MAX_RETRIES = int(os.environ.get("REGWATCH_MAX_RETRIES", "2"))
# Worth retrying: the host is asking us to wait, not telling us anything about
# the instrument.
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
# Cap on how long we will honour a Retry-After. A regulator asking for an hour
# should end the sweep, not stall a cron job holding a database session.
MAX_RETRY_WAIT = 60.0

Fetcher = Callable[[str], tuple[int, str]]


class HostPacer:
    """Keeps a minimum gap between requests to the same host.

    Deliberately in-process and per-sweep: it exists to stop us hammering one
    site within a single run, which is what actually triggered the rate limit.
    """

    def __init__(
        self,
        delay: float = DEFAULT_HOST_DELAY,
        *,
        sleeper: Callable[[float], None] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.delay = max(0.0, delay)
        self._sleep = sleeper or time.sleep
        self._now = clock or time.monotonic
        self._last: dict[str, float] = {}

    @staticmethod
    def host_of(url: str) -> str:
        return urlparse(url).netloc.lower()

    def wait_for(self, url: str) -> float:
        """Sleep long enough that this host has had its breathing room."""
        host = self.host_of(url)
        last = self._last.get(host)
        if last is None or self.delay <= 0:
            return 0.0
        gap = self.delay - (self._now() - last)
        if gap > 0:
            self._sleep(gap)
            return gap
        return 0.0

    def mark(self, url: str) -> None:
        self._last[self.host_of(url)] = self._now()


def _retry_after_seconds(headers: dict[str, str]) -> float | None:
    """Honour the host's own instruction when it gives one."""
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if not raw:
        return None
    try:
        return max(0.0, float(str(raw).strip()))
    except ValueError:
        return None  # HTTP-date form; fall back to our own backoff


class WatchError(RuntimeError):
    """The watcher could not run. Never raised for a mere source change."""


# --- normalisation & hashing --------------------------------------------------


_SCRIPT_STYLE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)
_COMMENT = re.compile(r"<!--.*?-->", re.S)
_TAG = re.compile(r"<[^>]+>")


def visible_text(html: str) -> str:
    """Strip markup down to what a reader would see.

    Regulator pages carry CSRF nonces, session ids, rotating banners and build
    timestamps in scripts and tag attributes. Hashing the raw response makes all
    of that look like the law changing, and a watcher that cries wolf every day
    is worse than no watcher — the queue stops being read. Only the visible text
    can meaningfully be said to have changed.
    """
    if not html:
        return ""
    text = _SCRIPT_STYLE.sub(" ", html)
    text = _COMMENT.sub(" ", text)
    text = _TAG.sub(" ", text)
    return text


def normalise(text: str) -> str:
    """Collapse whitespace and case-fold, so trivial reformatting is not 'change'.

    Deliberately conservative beyond that: it must not normalise away anything
    that could alter meaning, so only whitespace and case are touched.
    """
    return re.sub(r"\s+", " ", text or "").strip().casefold()


def content_hash(text: str) -> str:
    """Fingerprint the READABLE content, not the raw bytes."""
    return hashlib.sha256(normalise(visible_text(text)).encode("utf-8")).hexdigest()


# --- GATE 1: provenance -------------------------------------------------------


def _http_get(url: str) -> tuple[int, str, dict[str, str]]:
    import requests

    response = requests.get(url, timeout=30, headers={"User-Agent": "attest-regwatch/1"})
    return response.status_code, response.text, dict(response.headers)


def build_fetcher(
    *,
    pacer: HostPacer | None = None,
    getter: Callable[[str], tuple[int, str, dict[str, str]]] | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> Fetcher:
    """A fetcher that paces itself per host and retries when asked to wait.

    HTTPS only — a claim's provenance is worth nothing if the transport could be
    tampered with. A 429 or 5xx is the host asking for patience, so we give it
    some (honouring Retry-After when offered) rather than reporting a
    non-conclusion about the instrument.
    """
    pace = pacer or HostPacer()
    fetch = getter or _http_get
    sleep = sleeper or time.sleep

    def fetcher(url: str) -> tuple[int, str]:
        if not url.lower().startswith("https://"):
            msg = f"refusing to fetch a regulation source over a non-HTTPS URL: {url}"
            raise WatchError(msg)

        status: int = 0
        text: str = ""
        headers: dict[str, str] = {}
        for attempt in range(MAX_RETRIES + 1):
            pace.wait_for(url)
            status, text, headers = fetch(url)
            pace.mark(url)
            if status not in RETRY_STATUSES or attempt == MAX_RETRIES:
                return status, text
            # Exponential backoff, overridden by the host's own Retry-After.
            wait = _retry_after_seconds(headers)
            if wait is None:
                wait = min(MAX_RETRY_WAIT, DEFAULT_HOST_DELAY * (2**attempt))
            sleep(min(wait, MAX_RETRY_WAIT))
        return status, text

    return fetcher


def default_fetcher(url: str) -> tuple[int, str]:
    """Single-shot fetch with pacing and retries. Kept for direct callers."""
    return build_fetcher()(url)


def registered_urls(db: Session, pack_code: str) -> set[str]:
    """URLs already registered for a pack. Gate 1 admits nothing else."""
    return {
        row.url
        for row in db.query(RegulationSource).filter(
            RegulationSource.pack_code == pack_code
        )
    }


# --- GATE 2: verbatim grounding ----------------------------------------------


def appears_verbatim(claim: str, snapshot: str) -> bool:
    """Is this claim literally present in the official text?

    The whole anti-fabrication guarantee rests here. An empty claim is NOT
    grounded — otherwise a missing value would sail through.
    """
    if not claim or not claim.strip():
        return False
    return normalise(claim) in normalise(snapshot)


def ground_claims(claims: dict[str, str], snapshot: str) -> tuple[dict[str, str], list[str]]:
    """Split claims into those provable in the snapshot and those that are not."""
    grounded: dict[str, str] = {}
    ungrounded: list[str] = []
    for key, value in claims.items():
        if appears_verbatim(value, snapshot):
            grounded[key] = value
        else:
            ungrounded.append(key)
    return grounded, ungrounded


# --- GATE 3: reproducibility --------------------------------------------------


def reproducible(extract: Callable[[], dict[str, str]], runs: int = REPRODUCIBILITY_RUNS) -> (
    tuple[dict[str, str], bool]
):
    """Run the extraction `runs` times; accept only if every run agrees.

    Variance means the answer was not determined by the source text, so it is
    not knowledge — it is a guess, and guesses do not get published.
    """
    results = [extract() for _ in range(max(1, runs))]
    first = results[0]
    return first, all(r == first for r in results[1:])


# --- extraction (deterministic; confirms, never invents) ----------------------


def extract_confirmations(pack: RegulationPack, snapshot: str) -> dict[str, str]:
    """Find which of a pack's *declared candidates* are provable in the source.

    This does not read the regulation and decide what it says. It takes claims a
    human already wrote into the pack (`provision_candidate` on a rule) and
    checks whether the official text contains them. Confirmation, not authorship.
    """
    doc = pack.rules if isinstance(pack.rules, dict) else {}
    found: dict[str, str] = {}
    for rule in doc.get("rules", []):
        if not isinstance(rule, dict):
            continue
        candidate = rule.get("provision_candidate")
        rule_id = rule.get("id")
        # Only unconfirmed rules are candidates; never overwrite a confirmed one.
        if candidate and rule_id and not rule.get("provision"):
            if appears_verbatim(str(candidate), snapshot):
                found[str(rule_id)] = str(candidate)
    return found


# --- the watcher --------------------------------------------------------------


def _record_change(
    db: Session,
    *,
    pack_code: str,
    url: str,
    change_type: str,
    status: str,
    summary: str,
    evidence: dict[str, Any],
    before_hash: str | None = None,
    after_hash: str | None = None,
    published_version: str | None = None,
) -> RegulationChange:
    change = RegulationChange(
        pack_code=pack_code,
        url=url,
        change_type=change_type,
        status=status,
        summary=summary,
        evidence=evidence,
        before_hash=before_hash,
        after_hash=after_hash,
        published_version=published_version,
    )
    db.add(change)
    db.flush()
    return change


def register_sources(db: Session) -> int:
    """Register each published pack's official source URL. Safe to re-run."""
    registered = 0
    for pack in db.query(RegulationPack).all():
        if not pack.source_url:
            continue
        exists = (
            db.query(RegulationSource)
            .filter(
                RegulationSource.pack_code == pack.code,
                RegulationSource.url == pack.source_url,
            )
            .one_or_none()
        )
        if exists is None:
            db.add(RegulationSource(pack_code=pack.code, url=pack.source_url))
            registered += 1
    db.flush()
    return registered


def check_source(
    db: Session, source: RegulationSource, *, fetcher: Fetcher, auto_publish: bool = True
) -> list[RegulationChange]:
    """Fetch one source, detect drift, and confirm what can be proven."""
    changes: list[RegulationChange] = []
    now = datetime.now(UTC)
    # Booked BEFORE the fetch, so every exit path — success, HTTP error, blocked
    # socket, unhandled exception — leaves the source scheduled. A source that
    # failed and stayed due would be retried on every run, which is precisely the
    # hammering this is meant to stop.
    source.next_check_at = now + timedelta(seconds=CHECK_INTERVAL_SECONDS)

    try:
        status_code, text = fetcher(source.url)
    except Exception as exc:  # noqa: BLE001 — one bad source must not stop the sweep
        source.last_checked_at = now
        source.last_status = "error"
        source.last_error = str(exc)[:500]
        db.flush()
        return [
            _record_change(
                db, pack_code=source.pack_code, url=source.url,
                change_type=CHANGE_FETCH_FAILED, status=STATUS_QUARANTINED,
                summary=f"Could not fetch the official source: {exc}",
                evidence={"error": str(exc)[:500]},
            )
        ]

    source.last_checked_at = now
    source.last_status = str(status_code)
    source.last_error = None

    if status_code >= 400:
        # NOT all failures mean the same thing, and saying "may have been
        # withdrawn" for a rate limit is simply false. Only 404/410 is evidence
        # about the instrument; the rest is evidence about the fetch.
        source.last_error = f"HTTP {status_code}"
        db.flush()
        if status_code in (404, 410):
            change_type, summary = CHANGE_SOURCE_GONE, (
                f"Official source returned HTTP {status_code}. The pack may be citing "
                f"an instrument that has moved or been withdrawn — check the URL."
            )
        elif status_code in (401, 403):
            change_type, summary = CHANGE_SOURCE_BLOCKED, (
                f"Official source refused automated access (HTTP {status_code}). This "
                f"says nothing about the instrument — the site is blocking the fetch. "
                f"Check the URL by hand, or supply the text another way."
            )
        else:
            change_type, summary = CHANGE_SOURCE_UNAVAILABLE, (
                f"Official source was temporarily unavailable (HTTP {status_code}"
                f"{' — rate limited' if status_code == 429 else ''}). Transient; the "
                f"next sweep will retry. No conclusion about the instrument."
            )
        return [
            _record_change(
                db, pack_code=source.pack_code, url=source.url,
                change_type=change_type, status=STATUS_QUARANTINED,
                summary=summary, evidence={"status_code": status_code},
            )
        ]

    new_hash = content_hash(text)
    previous_hash = source.content_hash
    first_sight = previous_hash is None
    changed = (not first_sight) and new_hash != previous_hash

    # Drift is only reported once the SAME new content has been seen twice.
    # A single differing fetch is as likely to be a rotating banner or an A/B
    # variant as a change in the law, and an alert that fires every day is one
    # nobody reads.
    drifted = False
    if changed:
        if source.pending_hash == new_hash:
            drifted = True
            source.pending_hash = None
        else:
            source.pending_hash = new_hash
            db.flush()
            return changes  # await confirmation on the next sweep
    else:
        source.pending_hash = None

    # GATE 1 satisfied: fetched from the registered URL over HTTPS, snapshotted.
    source.snapshot = text[:200_000]
    source.content_hash = new_hash
    db.flush()

    pack = (
        db.query(RegulationPack)
        .filter(RegulationPack.code == source.pack_code)
        .order_by(RegulationPack.created_at.desc())
        .first()
    )
    if pack is None:
        return changes

    if drifted:
        # Material change: what it MEANS is judgement, so a person decides.
        changes.append(
            _record_change(
                db, pack_code=source.pack_code, url=source.url,
                change_type=CHANGE_SOURCE_DRIFT, status=STATUS_QUARANTINED,
                summary=(
                    "The official source text changed, confirmed across two "
                    "consecutive sweeps. Rule content is never auto-updated from a "
                    "changed source — review what changed and publish a new pack "
                    "version if the obligations moved."
                ),
                evidence={
                    "reason": "interpretation required",
                    "snapshot_bytes": len(text),
                },
                before_hash=previous_hash, after_hash=new_hash,
            )
        )

    # GATES 2 and 3: confirm declared candidates against this snapshot.
    confirmed, is_reproducible = reproducible(
        lambda: extract_confirmations(pack, source.snapshot or "")
    )
    if confirmed and not is_reproducible:
        changes.append(
            _record_change(
                db, pack_code=source.pack_code, url=source.url,
                change_type=CHANGE_PROVISION_CONFIRMED, status=STATUS_QUARANTINED,
                summary="Extraction was not reproducible across runs; not published.",
                evidence={"gate": "reproducibility", "candidates": confirmed},
                after_hash=new_hash,
            )
        )
    elif confirmed and is_reproducible:
        if auto_publish:
            version = _publish_confirmations(db, pack, confirmed, source)
            changes.append(
                _record_change(
                    db, pack_code=source.pack_code, url=source.url,
                    change_type=CHANGE_PROVISION_CONFIRMED, status=STATUS_AUTO_PUBLISHED,
                    summary=(
                        f"Confirmed {len(confirmed)} provision citation(s) verbatim "
                        f"against the official source and published {version}."
                    ),
                    evidence={
                        "gates_passed": ["provenance", "verbatim", "reproducibility"],
                        "confirmed": confirmed,
                        "verification_status": SOURCE_VERIFIED,
                    },
                    after_hash=new_hash, published_version=version,
                )
            )
        else:
            changes.append(
                _record_change(
                    db, pack_code=source.pack_code, url=source.url,
                    change_type=CHANGE_PROVISION_CONFIRMED, status=STATUS_QUARANTINED,
                    summary=f"{len(confirmed)} citation(s) provable; auto-publish is off.",
                    evidence={"confirmed": confirmed}, after_hash=new_hash,
                )
            )
    return changes


def _publish_confirmations(
    db: Session, pack: RegulationPack, confirmed: dict[str, str], source: RegulationSource
) -> str:
    """Publish a NEW pack version with the confirmed citations filled in.

    A new version, never an edit in place: the record of which rulebook was live
    on a given date has to stay true.
    """
    from app.services.regulation_packs import upsert_pack

    doc = dict(pack.rules if isinstance(pack.rules, dict) else {})
    rules = []
    for rule in doc.get("rules", []):
        rule = dict(rule) if isinstance(rule, dict) else rule
        if isinstance(rule, dict) and rule.get("id") in confirmed:
            rule["provision"] = confirmed[str(rule["id"])]
            rule["provision_source"] = source.url
            rule["provision_confirmed_at"] = datetime.now(UTC).isoformat()
        rules.append(rule)

    version = f"{pack.version}+sv{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
    upsert_pack(
        db,
        {
            "code": pack.code,
            "jurisdiction": pack.jurisdiction,
            "jurisdictions": doc.get("jurisdictions") or [pack.jurisdiction],
            "sectors": doc.get("sectors") or ["*"],
            "name": pack.name,
            "version": version,
            "instrument": pack.instrument,
            "instrument_notes": pack.instrument_notes,
            "source_url": pack.source_url,
            "effective_date": pack.effective_date,
            # Mechanically checked against the official text. NOT legal review.
            "verification_status": SOURCE_VERIFIED,
            "schema_version": doc.get("schema_version", 2),
            "engine": doc.get("engine", "json"),
            "rules": rules,
        },
    )
    return version


def due_sources(
    db: Session, *, now: datetime | None = None, limit: int | None = None
) -> list[RegulationSource]:
    """Sources eligible for checking now, longest-overdue first.

    A never-checked source (NULL) sorts first, so a freshly registered pack is
    picked up on the very next run rather than waiting out an interval it was
    never part of.
    """
    now = now or datetime.now(UTC)
    cap = MAX_SOURCES_PER_RUN if limit is None else limit
    query = (
        db.query(RegulationSource)
        .filter(
            (RegulationSource.next_check_at.is_(None))
            | (RegulationSource.next_check_at <= now)
        )
        .order_by(RegulationSource.next_check_at.asc().nullsfirst(),
                  RegulationSource.created_at.asc())
    )
    if cap > 0:
        query = query.limit(cap)
    return list(query)


def run_watch(
    db: Session,
    *,
    fetcher: Fetcher | None = None,
    auto_publish: bool = True,
    limit: int | None = None,
) -> dict[str, Any]:
    """Check the sources that are due. Returns a summary for the dashboard.

    Not every source, every run: see the politeness note at the top of the file.
    `limit=0` means no cap, for a scheduled job that can afford the wall clock.
    """
    # One pacer for the whole sweep: two packs citing the same host must be
    # spaced apart from each other, which a per-call pacer could not do.
    fetch = fetcher or build_fetcher()
    register_sources(db)

    now = datetime.now(UTC)
    total = db.query(RegulationSource).count()
    sources = due_sources(db, now=now, limit=limit)

    all_changes: list[RegulationChange] = []
    for source in sources:
        all_changes.extend(
            check_source(db, source, fetcher=fetch, auto_publish=auto_publish)
        )

    # Read AFTER the sweep, so it reflects what this run scheduled.
    soonest = (
        db.query(RegulationSource.next_check_at)
        .filter(RegulationSource.next_check_at.isnot(None))
        .order_by(RegulationSource.next_check_at.asc())
        .limit(1)
        .scalar()
    )
    still_due = sum(
        1
        for s in db.query(RegulationSource).all()
        if s.next_check_at is None or s.next_check_at <= now
    )

    return {
        "sources_checked": len(sources),
        "sources_total": total,
        # Honest about what this run left alone — a summary that says "3 checked"
        # with no denominator reads as "everything is up to date".
        "sources_deferred": still_due,
        "next_due_at": soonest.isoformat() if soonest else None,
        "changes": len(all_changes),
        "auto_published": sum(1 for c in all_changes if c.status == STATUS_AUTO_PUBLISHED),
        "quarantined": sum(1 for c in all_changes if c.status == STATUS_QUARANTINED),
        "checked_at": now.isoformat(),
    }
