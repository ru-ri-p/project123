"""Attest-ops side of the consent ceremony (the counterpart to attest_sdk.consent_cli).

Uses the ADMIN key to file a scoped access request and to read a record via an
approved grant. This is what the Attest team runs during a live test, while the
customer runs `python -m attest_sdk.consent_cli` on their side.

    export ATTEST_BASE_URL="https://attest-api-xxxx.onrender.com"
    export ATTEST_ADMIN_KEY="the-admin-key-set-in-render"

    # File a request for one record (prints request_id + grantee public key):
    python scripts/consent_admin.py file --org <ORG_ID> --hash <PAYLOAD_HASH> --reason "dispute #42"

    # Try to read a record via the request (403 until the customer approves):
    python scripts/consent_admin.py read --request-id <REQUEST_ID> --hash <PAYLOAD_HASH>
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests

TIMEOUT = 30.0


def _cfg(args: argparse.Namespace) -> tuple[str, dict[str, str]]:
    base_url = args.url or os.environ.get("ATTEST_BASE_URL")
    admin_key = args.admin_key or os.environ.get("ATTEST_ADMIN_KEY")
    if not base_url or not admin_key:
        sys.exit("error: set --url/ATTEST_BASE_URL and --admin-key/ATTEST_ADMIN_KEY")
    return base_url.rstrip("/"), {"x-admin-key": admin_key}


def _emit(resp: requests.Response) -> None:
    print(f"HTTP {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except ValueError:
        print(resp.text)


def _cmd_file(args: argparse.Namespace) -> None:
    base_url, headers = _cfg(args)
    resp = requests.post(
        f"{base_url}/v1/admin/access-requests",
        headers=headers,
        json={
            "org_id": args.org,
            "payload_hashes": args.hash,
            "reason": args.reason,
            "required_approvals": args.approvals,
            "ttl_seconds": args.ttl,
        },
        timeout=TIMEOUT,
    )
    _emit(resp)


def _cmd_read(args: argparse.Namespace) -> None:
    base_url, headers = _cfg(args)
    resp = requests.get(
        f"{base_url}/v1/admin/access-requests/{args.request_id}/records/{args.hash}",
        headers=headers,
        timeout=TIMEOUT,
    )
    _emit(resp)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="consent-admin", description=__doc__)
    parser.add_argument("--url", help="Attest service URL (or ATTEST_BASE_URL)")
    parser.add_argument("--admin-key", help="Admin key (or ATTEST_ADMIN_KEY)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("file", help="File a scoped access request")
    p.add_argument("--org", required=True, help="Target org id")
    p.add_argument("--hash", required=True, nargs="+", help="Payload hash(es) in scope")
    p.add_argument("--reason", required=True)
    p.add_argument("--approvals", type=int, default=1, help="Required approvals (M-of-N)")
    p.add_argument("--ttl", type=int, default=3600, help="Grant TTL in seconds")
    p.set_defaults(func=_cmd_file)

    p = sub.add_parser("read", help="Read a record via the request's grant")
    p.add_argument("--request-id", required=True)
    p.add_argument("--hash", required=True, help="Payload hash to read")
    p.set_defaults(func=_cmd_read)

    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
