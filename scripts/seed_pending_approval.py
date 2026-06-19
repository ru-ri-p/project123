#!/usr/bin/env python3
"""Create a pending approval for dashboard demo (Phase 3 will open these from precheck)."""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.db.session import SessionLocal
from app.repositories import approvals as approval_repo
from app.repositories import traces as trace_repo


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed a pending approval")
    parser.add_argument("--org-id", default="org_demo")
    parser.add_argument("--trace-id", required=True, help="Existing trace UUID")
    args = parser.parse_args()

    trace_uuid = uuid.UUID(args.trace_id)
    db = SessionLocal()
    try:
        trace = trace_repo.get_trace_for_org(db, args.org_id, trace_uuid)
        if trace is None:
            print(f"Trace {args.trace_id} not found for org {args.org_id}", file=sys.stderr)
            sys.exit(1)
        approval = approval_repo.create_approval(
            db, org_id=args.org_id, trace_id=trace_uuid, event_id=None
        )
        db.commit()
        print(f"Pending approval created: {approval.id}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
