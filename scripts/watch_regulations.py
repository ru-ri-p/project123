#!/usr/bin/env python3
"""Scheduled sweep of the official regulation sources that are due.

Runs on the deployed service, which has outbound access to the regulator sites.
Auto-publishes only what is provable verbatim against the fetched official text;
everything requiring judgement is quarantined for a person to review in /admin.

Unlike the dashboard button, this defaults to NO per-run cap: a cron has the wall
clock to spare, and the per-host pacing keeps it polite regardless. Set
REGWATCH_MAX_SOURCES_PER_RUN and pass REGWATCH_CRON_LIMIT to bound it anyway.

Set REGWATCH_AUTO_PUBLISH=false to observe without publishing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.session import SessionLocal  # noqa: E402
from app.services import reg_watch  # noqa: E402


def main() -> int:
    auto_publish = os.environ.get("REGWATCH_AUTO_PUBLISH", "true").lower() != "false"
    limit = int(os.environ.get("REGWATCH_CRON_LIMIT", "0"))  # 0 = everything due
    db = SessionLocal()
    try:
        summary = reg_watch.run_watch(db, auto_publish=auto_publish, limit=limit)
        db.commit()
    except Exception as exc:  # noqa: BLE001 — a cron must report, not vanish
        db.rollback()
        print(f"[regwatch] FAILED: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()

    print(
        f"[regwatch] checked {summary['sources_checked']} of "
        f"{summary['sources_total']} source(s): "
        f"{summary['auto_published']} auto-published, "
        f"{summary['quarantined']} quarantined for review; "
        f"{summary['sources_deferred']} still due, next due {summary['next_due_at']}"
    )
    if summary["quarantined"]:
        # Deliberately loud: a quarantined change means a regulation may have
        # moved and a pack is now potentially out of date.
        print("[regwatch] review the quarantine queue at /admin -> Regulation Watch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
