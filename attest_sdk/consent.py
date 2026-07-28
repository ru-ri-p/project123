"""Org-side client for the consent-gated access ceremony (Slice 5b).

When an org runs in customer-key confidentiality mode, the content it records is
dark to Attest at rest. If Attest ever needs to see a specific record (a dispute,
an audit, a support case), it files a SCOPED access request. This client is the
org's side of answering that request:

  1. `enable_customer_key(...)` — go dark: hand Attest the PUBLIC wrapping key.
  2. `list_requests(...)` / `get_request(...)` — see what Attest is asking for.
  3. `approve(...)` — using the org's PRIVATE key (locally, never sent), re-wrap
     ONLY the in-scope records' content keys to Attest's one-time access key, and
     post them. Attest can then open exactly those records, until the request
     expires — nothing else.
  4. `deny(...)` / `revoke(...)` — refuse, or pull a previously granted access.

The org private key is only ever used inside `approve()`, in this process. Attest
never receives it. This is what makes the access "consent-gated": no approval,
no key release, no visibility.

`approve()` needs the wrapping crypto, so install `attest-sdk[consent]`.
"""

from __future__ import annotations

import base64
from typing import Any

import requests

DEFAULT_TIMEOUT = 10.0


class ConsentClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "http://localhost:8000",
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"x-api-key": self.api_key}

    # --- Go dark / signing key ------------------------------------------------

    def enable_customer_key(self, wrapping_public_pem: bytes | str) -> dict[str, Any]:
        """Switch the org to customer-key mode by registering its PUBLIC wrapping key.

        After this, everything the org records is encrypted under a key Attest can
        wrap but not open. Pass the PUBLIC PEM only — never the private key.
        """
        pem = (
            wrapping_public_pem.decode("utf-8")
            if isinstance(wrapping_public_pem, bytes)
            else wrapping_public_pem
        )
        response = requests.post(
            f"{self.base_url}/v1/org/confidentiality",
            headers=self._headers(),
            json={"wrapping_public_pem": pem},
            timeout=self.timeout,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    def provision_signing_key(self) -> dict[str, Any]:
        """Ask Attest to mint a per-org signing key (returns key_id + public PEM)."""
        response = requests.post(
            f"{self.base_url}/v1/org/signing-key",
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    # --- Inspect requests -----------------------------------------------------

    def list_requests(self, status: str | None = None) -> list[dict[str, Any]]:
        """List access requests Attest has filed against this org (optionally by status)."""
        params = {"status": status} if status is not None else None
        response = requests.get(
            f"{self.base_url}/v1/access-requests",
            headers=self._headers(),
            params=params,
            timeout=self.timeout,
        )
        response.raise_for_status()
        data: list[dict[str, Any]] = response.json()
        return data

    def get_request(self, request_id: str) -> dict[str, Any]:
        """Fetch one request with its scope (the org-wrapped key for each record)."""
        response = requests.get(
            f"{self.base_url}/v1/access-requests/{request_id}",
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    # --- Approve (the only place the private key is used) ---------------------

    def approve(
        self,
        request_id: str,
        approver_id: str,
        org_private_pem: bytes | str,
    ) -> dict[str, Any]:
        """Approve a request by releasing ONLY the in-scope keys.

        Fetches the request scope, and for each in-scope record re-wraps the
        content key from the org's private key to the request's one-time grantee
        key — locally, in this process. Posts the released keys and the approval.
        The org private key never leaves here.
        """
        from .orgcrypto import regrant_key

        private_pem = (
            org_private_pem.encode("utf-8")
            if isinstance(org_private_pem, str)
            else org_private_pem
        )

        detail = self.get_request(request_id)
        grantee_public = detail["grantee_public_pem"].encode("utf-8")

        released: dict[str, str] = {}
        for item in detail.get("scope", []):
            wrapped_for_org_b64 = item.get("wrapped_key_for_org")
            if wrapped_for_org_b64 is None:
                # Not a customer-key record (nothing to release) — skip it.
                continue
            wrapped_for_org = base64.b64decode(wrapped_for_org_b64)
            regranted = regrant_key(private_pem, wrapped_for_org, grantee_public)
            released[item["payload_hash"]] = base64.b64encode(regranted).decode("ascii")

        response = requests.post(
            f"{self.base_url}/v1/access-requests/{request_id}/approve",
            headers=self._headers(),
            json={"approver_id": approver_id, "released_keys": released},
            timeout=self.timeout,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    # --- Refuse / revoke ------------------------------------------------------

    def _resolve(self, request_id: str, status: str) -> dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/v1/access-requests/{request_id}/resolve",
            headers=self._headers(),
            json={"status": status},
            timeout=self.timeout,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    def deny(self, request_id: str) -> dict[str, Any]:
        """Refuse a pending request outright (no key is ever released)."""
        return self._resolve(request_id, "denied")

    def revoke(self, request_id: str) -> dict[str, Any]:
        """Revoke access. New reads via this request stop; expiry still applies too."""
        return self._resolve(request_id, "revoked")
