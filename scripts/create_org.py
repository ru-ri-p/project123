#!/usr/bin/env python3
"""Create a new organisation with a hashed API key (admin/dev use only)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.db.session import SessionLocal
from app.domain.org_settings import DEFAULT_FAIL_MODE, DEFAULT_REGION
from app.services.orgs import create_org_with_api_key


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a Attest organisation")
    parser.add_argument("--id", required=True, help="Organisation id (e.g. org_acme)")
    parser.add_argument("--name", required=True, help="Display name")
    parser.add_argument("--region", default=DEFAULT_REGION, help="Data region (default: uae)")
    parser.add_argument(
        "--fail-mode",
        default=DEFAULT_FAIL_MODE,
        dest="fail_mode",
        help="deny_on_error | allow_with_flag",
    )
    parser.add_argument("--api-key", default=None, help="Optional fixed API key (dev only)")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        org, api_key = create_org_with_api_key(
            db,
            org_id=args.id,
            name=args.name,
            region=args.region,
            fail_mode=args.fail_mode,
            api_key=args.api_key,
        )
        db.commit()
        print(f"Created org: {org.id} ({org.name})")
        print(f"  region:    {org.region}")
        print(f"  fail_mode: {org.fail_mode}")
        print(f"  API key (store securely — shown once): {api_key}")
    except ValueError as exc:
        db.rollback()
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
