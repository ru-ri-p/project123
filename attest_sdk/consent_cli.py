"""Command-line front end for the consent ceremony (Slice 5b).

Run in the ORG's environment. The org private key stays on this machine; only the
public key and re-wrapped per-record keys ever leave.

    python -m attest_sdk.consent_cli keygen --out-private org_priv.pem --out-public org_pub.pem
    python -m attest_sdk.consent_cli enable  --public org_pub.pem
    python -m attest_sdk.consent_cli list    [--status pending]
    python -m attest_sdk.consent_cli show    --request-id <id>
    python -m attest_sdk.consent_cli approve --request-id <id> --approver officer_1 \
        --private org_priv.pem
    python -m attest_sdk.consent_cli deny    --request-id <id>
    python -m attest_sdk.consent_cli revoke  --request-id <id>

Config (flags override environment):
    --url / ATTEST_BASE_URL     the Attest service URL
    --key / ATTEST_API_KEY      the org API key
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .consent import ConsentClient


def _client(args: argparse.Namespace) -> ConsentClient:
    base_url = args.url or os.environ.get("ATTEST_BASE_URL")
    api_key = args.key or os.environ.get("ATTEST_API_KEY")
    if not base_url or not api_key:
        sys.exit("error: set --url/ATTEST_BASE_URL and --key/ATTEST_API_KEY")
    return ConsentClient(api_key=api_key, base_url=base_url)


def _emit(data: Any) -> None:
    print(json.dumps(data, indent=2))


def _cmd_keygen(args: argparse.Namespace) -> None:
    from .orgcrypto import generate_wrapping_keypair

    private_pem, public_pem = generate_wrapping_keypair()
    # Write the private key with tight permissions; it is the org's secret.
    fd = os.open(args.out_private, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_pem)
    with open(args.out_public, "wb") as fh:
        fh.write(public_pem)
    _emit(
        {
            "private_key": args.out_private,
            "public_key": args.out_public,
            "note": "Keep the private key secret. Register only the public key with Attest.",
        }
    )


def _cmd_enable(args: argparse.Namespace) -> None:
    with open(args.public, "rb") as fh:
        public_pem = fh.read()
    _emit(_client(args).enable_customer_key(public_pem))


def _cmd_signing_key(args: argparse.Namespace) -> None:
    _emit(_client(args).provision_signing_key())


def _cmd_list(args: argparse.Namespace) -> None:
    _emit(_client(args).list_requests(status=args.status))


def _cmd_show(args: argparse.Namespace) -> None:
    _emit(_client(args).get_request(args.request_id))


def _cmd_approve(args: argparse.Namespace) -> None:
    with open(args.private, "rb") as fh:
        private_pem = fh.read()
    _emit(_client(args).approve(args.request_id, args.approver, private_pem))


def _cmd_deny(args: argparse.Namespace) -> None:
    _emit(_client(args).deny(args.request_id))


def _cmd_revoke(args: argparse.Namespace) -> None:
    _emit(_client(args).revoke(args.request_id))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attest-consent", description=__doc__)
    parser.add_argument("--url", help="Attest service URL (or ATTEST_BASE_URL)")
    parser.add_argument("--key", help="Org API key (or ATTEST_API_KEY)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="Generate a wrapping keypair")
    p.add_argument("--out-private", default="org_private.pem")
    p.add_argument("--out-public", default="org_public.pem")
    p.set_defaults(func=_cmd_keygen)

    p = sub.add_parser("enable", help="Enable customer-key mode with a public key")
    p.add_argument("--public", required=True, help="Path to the public wrapping PEM")
    p.set_defaults(func=_cmd_enable)

    p = sub.add_parser("signing-key", help="Provision a per-org signing key")
    p.set_defaults(func=_cmd_signing_key)

    p = sub.add_parser("list", help="List access requests")
    p.add_argument("--status", default=None, help="Filter by status (e.g. pending)")
    p.set_defaults(func=_cmd_list)

    p = sub.add_parser("show", help="Show one request and its scope")
    p.add_argument("--request-id", required=True)
    p.set_defaults(func=_cmd_show)

    p = sub.add_parser("approve", help="Approve a request, releasing only in-scope keys")
    p.add_argument("--request-id", required=True)
    p.add_argument("--approver", required=True, help="Approver id (e.g. officer_1)")
    p.add_argument("--private", required=True, help="Path to the org private PEM")
    p.set_defaults(func=_cmd_approve)

    p = sub.add_parser("deny", help="Deny a pending request")
    p.add_argument("--request-id", required=True)
    p.set_defaults(func=_cmd_deny)

    p = sub.add_parser("revoke", help="Revoke a granted request")
    p.add_argument("--request-id", required=True)
    p.set_defaults(func=_cmd_revoke)

    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
