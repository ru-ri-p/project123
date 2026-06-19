#!/usr/bin/env python3
"""Standalone Attest evidence bundle verifier — no server access required.

Usage:
    python verify.py [path/to/bundle.json] [--tsa-roots trusted_tsa_roots.pem]

Core verification (event hashes, signatures, hash chain, Merkle proofs, batch
root signature) depends only on Python stdlib + cryptography (instructions §4f).

Optional external-anchor verification (RFC 3161 timestamp token) additionally
needs `rfc3161-client` (pip install rfc3161-client). It checks that the token
timestamps exactly this batch root, and — when you pass --tsa-roots with the
trusted TSA's root certificate(s) — that the token's TSA signature chains to a
root you trust. Without --tsa-roots the anchor is reported as time-bound but
its trust chain is left unverified.

Prints ALL EVENTS VERIFIED on success; exits non-zero on failure.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(obj: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


# Algorithm suites this verifier can check. An event under any other suite
# fails closed — keep this in sync with app/crypto/algorithms.py.
SUPPORTED_ALGORITHMS = {"sha256-ed25519-v1"}


def build_envelope(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "alg": event.get("alg"),
        "trace_id": str(event["trace_id"]),
        "seq": event["seq"],
        "type": event["type"],
        "payload_hash": event["payload_hash"],
        "prev_hash": event.get("prev_hash"),
        "policy_version": event.get("policy_version"),
        "created_at": event["created_at"],
    }


def verify_hex(public_pem: bytes, message_hex: str, signature_hex: str) -> bool:
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, Ed25519PublicKey):
        return False
    try:
        key.verify(bytes.fromhex(signature_hex), bytes.fromhex(message_hex))
    except InvalidSignature:
        return False
    return True


def _digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def verify_merkle_proof(leaf_hex: str, index: int, proof: list[str], root_hex: str) -> bool:
    current = bytes.fromhex(leaf_hex)
    idx = index
    for sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        if idx % 2 == 1:
            current = _digest(sibling + current)
        else:
            current = _digest(current + sibling)
        idx //= 2
    return current.hex() == root_hex


def _tsa_leaf_from_token(resp: Any) -> Any:
    """Pick the TSA signing certificate (timeStamping EKU) embedded in the token."""
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    certs = []
    for item in resp.signed_data.certificates:
        cert = (
            x509.load_der_x509_certificate(bytes(item))
            if isinstance(item, (bytes, bytearray))
            else item
        )
        certs.append(cert)
    for cert in certs:
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.TIME_STAMPING in eku:
                return cert
        except x509.ExtensionNotFound:
            continue
    return certs[0] if certs else None


def verify_anchor(token_b64: str, root_hex: str, tsa_roots_pem: bytes | None) -> dict[str, Any]:
    """Validate an RFC 3161 anchor token offline. Returns a result dict; never raises.

    status: "trusted" (imprint matches root AND TSA chains to a supplied trust root)
            "bound"   (imprint matches root; trust root not supplied)
            "skipped" (rfc3161-client not installed)
            "failed"  (imprint mismatch, bad token, or chain/signature failure)
    """
    result: dict[str, Any] = {"status": "failed", "detail": "", "gen_time": None, "tsa": None}
    try:
        from rfc3161_client import VerifierBuilder, decode_timestamp_response
        from rfc3161_client.errors import VerificationError
    except ImportError:
        result["status"] = "skipped"
        result["detail"] = "rfc3161-client not installed; anchor not checked"
        return result

    # The verifier must never raise on bad input (instructions §4): a broad guard
    # here turns any malformed token/cert into a reported failure, not a crash.
    try:
        from cryptography import x509

        resp = decode_timestamp_response(base64.b64decode(token_b64.encode("ascii")))
        tst = resp.tst_info
        result["gen_time"] = tst.gen_time.isoformat() if tst.gen_time else None

        root_bytes = bytes.fromhex(root_hex)
        if tst.message_imprint.message != hashlib.sha256(root_bytes).digest():
            result["detail"] = "token message imprint does not match the batch root"
            return result

        leaf = _tsa_leaf_from_token(resp)
        if leaf is not None:
            result["tsa"] = leaf.subject.rfc4514_string()

        if not tsa_roots_pem:
            result["status"] = "bound"
            result["detail"] = "imprint matches root; supply --tsa-roots to verify the TSA chain"
            return result

        roots = x509.load_pem_x509_certificates(tsa_roots_pem)
        if leaf is None or not roots:
            result["detail"] = "missing TSA certificate in token or no trust roots provided"
            return result

        builder = VerifierBuilder().tsa_certificate(leaf)
        for root_cert in roots:
            builder = builder.add_root_certificate(root_cert)
        try:
            ok = builder.build().verify_message(resp, root_bytes)
        except VerificationError as exc:
            result["detail"] = f"TSA chain/signature verification failed: {exc}"
            return result
        if ok:
            result["status"] = "trusted"
            result["detail"] = "imprint matches root and TSA signature chains to a trusted root"
        else:
            result["detail"] = "TSA verification returned false"
        return result
    except Exception as exc:  # noqa: BLE001 - verifier must never raise on bad input
        result["detail"] = f"anchor verification error: {type(exc).__name__}: {exc}"
        return result


def _print_summary(bundle: dict[str, Any]) -> None:
    manifest = bundle.get("manifest") or {}
    compliance = bundle.get("compliance_summary") or {}
    events = bundle.get("events") or []
    print(f"Trace: {bundle.get('trace_id', manifest.get('trace_id', '?'))}")
    print(f"Events verified: {len(events)}")
    if manifest:
        signing = manifest.get("signing") or {}
        print(f"Signing backend: {signing.get('backend', 'unknown')}")
    if compliance:
        gate = compliance.get("workflow_gate") or {}
        print(f"Workflow: {gate.get('workflow_status', 'n/a')}")
        policy = compliance.get("policy_decisions") or []
        if policy:
            last = policy[-1]
            print(f"Last policy tier: {last.get('tier')} allowed={last.get('allowed')}")


def verify_bundle(bundle: dict[str, Any], *, tsa_roots_pem: bytes | None = None) -> bool:
    public_pem = bundle["public_key_pem"].encode("utf-8")
    events = bundle["events"]
    prev_hash: str | None = None
    all_ok = True

    for event in events:
        envelope = build_envelope(event)
        recomputed = sha256_hex(envelope)
        hash_ok = recomputed == event["hash"]
        alg_ok = event.get("alg") in SUPPORTED_ALGORITHMS
        sig_ok = alg_ok and verify_hex(public_pem, event["hash"], event["signature"])
        chain_ok = event.get("prev_hash") == prev_hash
        ok = hash_ok and sig_ok and chain_ok
        all_ok = all_ok and ok
        if not ok:
            print(
                f"FAIL seq={event['seq']}: hash_ok={hash_ok} sig_ok={sig_ok} "
                f"chain_ok={chain_ok} alg_ok={alg_ok} alg={event.get('alg')}"
            )
        prev_hash = event["hash"]

    batches = bundle.get("batches") or []
    if not batches and bundle.get("batch"):
        batches = [bundle["batch"]]

    event_by_id = {e["id"]: e for e in events}
    for batch_info in batches:
        root = batch_info["root"]
        batch_event_ids: list[str] = batch_info["event_ids"]
        leaf_hash_map: dict[str, str] = batch_info.get("leaf_hashes", {})

        proofs: dict[str, Any] = batch_info.get("merkle_proofs", {})
        for eid, proof in proofs.items():
            try:
                index = batch_event_ids.index(eid)
            except ValueError:
                print(f"FAIL merkle: event {eid} not in batch")
                all_ok = False
                continue
            ev = event_by_id.get(eid)
            if ev is not None:
                ev_hash = ev["hash"]
            else:
                ev_hash = leaf_hash_map.get(eid)
                if ev_hash is None:
                    print(f"FAIL merkle: missing hash for event {eid}")
                    all_ok = False
                    continue
            if not verify_merkle_proof(ev_hash, index, proof, root):
                label = ev["seq"] if ev else eid
                print(f"FAIL merkle proof for seq={label}")
                all_ok = False

        sig_ok = verify_hex(public_pem, root, batch_info["signature"])
        if not sig_ok:
            print("FAIL batch root signature")
            all_ok = False

        anchor = batch_info.get("anchor")
        if anchor and anchor.get("token"):
            res = verify_anchor(anchor["token"], root, tsa_roots_pem)
            status = res["status"]
            if status == "trusted":
                print(f"ANCHOR trusted: TSA={res['tsa']} genTime={res['gen_time']}")
            elif status == "bound":
                print(f"ANCHOR bound: genTime={res['gen_time']} ({res['detail']})")
            elif status == "skipped":
                print(f"ANCHOR not checked: {res['detail']}")
            else:
                print(f"FAIL anchor: {res['detail']}")
                all_ok = False

    return all_ok


def main() -> int:
    parser = argparse.ArgumentParser(description="Attest evidence bundle verifier")
    parser.add_argument("bundle", nargs="?", default="bundle.json", help="path to bundle.json")
    parser.add_argument(
        "--tsa-roots",
        dest="tsa_roots",
        default=None,
        help="PEM file of trusted TSA root certificate(s) to verify the RFC 3161 anchor",
    )
    args = parser.parse_args()

    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    tsa_roots_pem = Path(args.tsa_roots).read_bytes() if args.tsa_roots else None
    if verify_bundle(bundle, tsa_roots_pem=tsa_roots_pem):
        print("ALL EVENTS VERIFIED")
        _print_summary(bundle)
        return 0
    print("VERIFICATION FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
