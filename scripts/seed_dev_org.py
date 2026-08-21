#!/usr/bin/env python3
"""Seed development organisations for local testing."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.auth import hash_api_key
from app.db.models import Org
from app.db.session import SessionLocal

ORGS = (
    {
        "id": "org_demo",
        "name": "Demo Organisation",
        "api_key": "org_demo_key",
        "region": "uae",
        "fail_mode": "deny_on_error",
    },
    {
        "id": "org_other",
        "name": "Other Tenant (isolation tests)",
        "api_key": "org_other_key",
        "region": "uae",
        "fail_mode": "allow_with_flag",
    },
)


def main() -> None:
    db = SessionLocal()
    try:
        for spec in ORGS:
            existing = db.query(Org).filter(Org.id == spec["id"]).one_or_none()
            if existing is None:
                db.add(
                    Org(
                        id=spec["id"],
                        name=spec["name"],
                        api_key_hash=hash_api_key(spec["api_key"]),
                        region=spec["region"],
                        fail_mode=spec["fail_mode"],
                        # These stand in for customers that predate the
                        # onboarding gate. On a rebuilt-from-scratch dev
                        # database they would otherwise be created as NEW orgs
                        # and gated (409 profile_required), which fails every
                        # legacy-path test for an environmental reason.
                        requires_profile=False,
                    )
                )
                print(f"Created org '{spec['id']}'.")
            else:
                print(f"Org '{spec['id']}' already exists.")
            print(f"  API key (dev only): {spec['api_key']}")
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    main()
