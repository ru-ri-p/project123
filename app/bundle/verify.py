#!/usr/bin/env python3
"""Standalone Attest evidence bundle verifier — no server access required.

Usage:
    python verify.py [path/to/bundle.json]

Depends only on Python stdlib + cryptography (instructions §4f).
Prints ALL EVENTS VERIFIED on success; exits non-zero on failure.
"""

from __future__ import annotations

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


def verify_bundle(bundle: dict[str, Any]) -> bool:
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

    return all_ok


def main() -> int:
    bundle_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("bundle.json")
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    if verify_bundle(bundle):
        print("ALL EVENTS VERIFIED")
        _print_summary(bundle)
        return 0
    print("VERIFICATION FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
