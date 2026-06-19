#!/usr/bin/env python3
"""Seed default governance policy for dev orgs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.db.session import SessionLocal
from app.domain.default_policy import DEFAULT_POLICY_RULES
from app.repositories import policies as policy_repo

DEFAULT_VERSION = "v1"


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed dev policy document")
    parser.add_argument("--org-id", default="org_demo")
    parser.add_argument("--version", default=DEFAULT_VERSION)
    args = parser.parse_args()

    db = SessionLocal()
    try:
        policy = policy_repo.upsert_policy(
            db,
            org_id=args.org_id,
            name="Attest starter (finance)",
            version=args.version,
            rules=DEFAULT_POLICY_RULES,
            active=True,
        )
        db.commit()
        print(f"Policy {policy.version} active for {args.org_id}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
