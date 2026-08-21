"""Export a human-readable snapshot of the database to Markdown.

Run in the Render shell (after deploying this script):

    python scripts/export_backup_md.py > /tmp/attest_backup.md
    cat /tmp/attest_backup.md     # copy the output somewhere safe

BE CLEAR ABOUT WHAT THIS IS. Markdown is a RECORD, not a restore file — you can
read it, show it to an auditor, and rebuild orgs/packs from it by hand, but you
cannot feed it back to Postgres. The restorable backup is a pg_dump or Render's
own Backups tab (paid plans). Use this as the belt to that suspender, and as the
thing that survives even if the database itself is lost.

Event payload ENVELOPES are deliberately omitted: they are ciphertext (often
under customer-held keys we cannot read) and can be large. What IS exported per
event — seq, type, payload hash, chain hash, signature — is exactly what the
tamper-evidence rests on, so the chain in this file remains independently
checkable against any copy of the content.

Every section is wrapped so one broken table cannot sink the rest of the export
(same spirit as the verifier: report and continue, never raise).
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Caps keep the file copy-pasteable from a web shell. Anything truncated is said
# out loud — a backup that silently drops rows reads as complete when it is not.
MAX_ORGS = 1000
MAX_TRACES = 2000
MAX_EVENTS = 5000
MAX_REQUESTS = 500


def section(title: str):
    print(f"\n## {title}\n")


def safe(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 — a backup must report, not die
        print(f"\n> **EXPORT ERROR in this section:** `{type(exc).__name__}: {str(exc)[:300]}`\n")


def cell(v) -> str:
    if v is None:
        return ""
    return str(v).replace("|", "\\|").replace("\n", " ")


def main() -> int:
    from sqlalchemy import text

    from app.db.session import SessionLocal, engine

    print("# Attest database snapshot")
    print(f"\nExported {datetime.now(UTC).isoformat()}")

    try:
        with engine.connect() as c:
            version = c.execute(text("select version_num from alembic_version")).scalar()
        print(f"Schema (alembic): `{version}`")
    except Exception as exc:  # noqa: BLE001
        print(f"\n**DATABASE UNREACHABLE — nothing to export.** `{str(exc)[:300]}`")
        return 1

    db = SessionLocal()

    def counts():
        from app.db.models import (
            AccessRequest,
            Anchor,
            Batch,
            Event,
            Org,
            OrgProfile,
            RegulationChange,
            RegulationPack,
            RegulationSource,
            Trace,
        )

        section("Row counts")
        print("| table | rows |")
        print("|---|---|")
        for name, model in [
            ("orgs", Org), ("org_profiles", OrgProfile), ("traces", Trace),
            ("events", Event), ("batches", Batch), ("anchors", Anchor),
            ("access_requests", AccessRequest), ("regulation_packs", RegulationPack),
            ("regulation_sources", RegulationSource), ("regulation_changes", RegulationChange),
        ]:
            print(f"| {name} | {db.query(model).count()} |")

    def orgs():
        from app.db.models import Org, OrgProfile

        section("Organisations")
        profiles = {p.org_id: p for p in db.query(OrgProfile)}
        rows = db.query(Org).order_by(Org.created_at).limit(MAX_ORGS).all()
        total = db.query(Org).count()
        print("| id | name | region | mode | requires_profile "
              "| jurisdictions | sectors | created |")
        print("|---|---|---|---|---|---|---|---|")
        for o in rows:
            p = profiles.get(o.id)
            print(f"| {cell(o.id)} | {cell(o.name)} | {cell(o.region)} "
                  f"| {cell(o.confidentiality_mode)} | {o.requires_profile} "
                  f"| {cell(','.join(p.jurisdictions or []) if p else '')} "
                  f"| {cell(','.join(p.sectors or []) if p else '')} "
                  f"| {o.created_at.date()} |")
        if total > MAX_ORGS:
            print(f"\n> TRUNCATED: {total - MAX_ORGS} more org(s) not shown.")
        print("\n> API keys are stored only as hashes and are NOT exported — "
              "a lost key is re-minted, never recovered.")

    def packs():
        import json

        from app.db.models import RegulationPack

        section("Regulation packs (full rule content — this is the rebuildable part)")
        for p in db.query(RegulationPack).order_by(RegulationPack.code, RegulationPack.created_at):
            print(f"\n### {p.code} @ {p.version}  \n"
                  f"status: `{p.verification_status}` · jurisdiction: {p.jurisdiction} · "
                  f"instrument: {cell(p.instrument)}")
            if p.source_url:
                print(f"source: {p.source_url}")
            print("\n```json")
            print(json.dumps(p.rules, indent=1, ensure_ascii=False, default=str)[:20000])
            print("```")

    def sources():
        from app.db.models import RegulationSource

        section("Regulation sources")
        print("| pack | url | mode | content_hash | attested_by | retired |")
        print("|---|---|---|---|---|---|")
        for s in db.query(RegulationSource).order_by(RegulationSource.pack_code):
            mode = cell(getattr(s, "check_mode", "auto"))
            print(f"| {cell(s.pack_code)} | {cell(s.url)} | {mode} "
                  f"| {cell((s.content_hash or '')[:16])} | {cell(s.attested_by)} "
                  f"| {'yes' if s.retired_at else ''} |")
        print("\n> Text snapshots omitted for size; content hashes above identify them.")

    def chain():
        from app.db.models import Event, Trace

        section("Traces and the event chain")
        print("Envelopes (encrypted content) omitted; hashes and signatures below are "
              "the tamper-evidence itself and stay independently checkable.\n")
        total_e = db.query(Event).count()
        traces = db.query(Trace).order_by(Trace.created_at).limit(MAX_TRACES).all()
        shown = 0
        for t in traces:
            events = (db.query(Event).filter(Event.trace_id == t.id)
                      .order_by(Event.seq).all())
            if not events:
                continue
            if shown + len(events) > MAX_EVENTS:
                print(f"\n> TRUNCATED at {shown} events (of {total_e}).")
                break
            print(f"\n### trace {t.id} · org {t.org_id} · {t.created_at.isoformat()}")
            print("| seq | type | payload_hash | hash | prev | signature | deferred |")
            print("|---|---|---|---|---|---|---|")
            for e in events:
                print(f"| {e.seq} | {cell(e.type)} | {cell(e.payload_hash)} "
                      f"| {cell(e.hash)} | {cell(e.prev_hash)} | {cell(e.signature)} "
                      f"| {'yes' if e.deferred else ''} |")
            shown += len(events)

    def anchors():
        from app.db.models import Anchor, Batch

        section("Batches and anchors")
        print("| batch | root | sealed | anchored |")
        print("|---|---|---|---|")
        anchored = {a.batch_id: a for a in db.query(Anchor)}
        for b in db.query(Batch).order_by(Batch.sealed_at):
            a = anchored.get(b.id)
            print(f"| {b.id} | {cell(b.root)} | {b.sealed_at.isoformat()} "
                  f"| {a.anchored_at.isoformat() if a else ''} |")

    def requests():
        from app.db.models import AccessRequest

        section("Access requests (the consent trail)")
        print("| id | org | status | reason | created |")
        print("|---|---|---|---|---|")
        for r in db.query(AccessRequest).order_by(AccessRequest.created_at).limit(MAX_REQUESTS):
            print(f"| {r.id} | {cell(r.org_id)} | {cell(r.status)} "
                  f"| {cell((r.reason or '')[:80])} | {r.created_at.date()} |")

    for fn in (counts, orgs, packs, sources, chain, anchors, requests):
        safe(fn)
    db.close()

    print("\n---\n*End of snapshot. This file is a record, not a restore image — "
          "keep a pg_dump or Render backup for actual restoration.*")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
