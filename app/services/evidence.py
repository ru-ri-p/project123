"""Evidence bundle construction and export."""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.crypto.keys import load_public_pem
from app.crypto.merkle import merkle_proof
from app.crypto.signing_provider import get_signing_provider
from app.db.models import Anchor, Batch, Event
from app.repositories import batches as batch_repo
from app.repositories import events as event_repo
from app.repositories import orgs as org_repo
from app.services.access import TraceNotFoundError
from app.services.compliance_summary import build_compliance_summary
from app.services.envelope import now_utc_iso
from app.services.replay import replay_trace
from app.services.trace_access import ensure_trace_access

BUNDLE_SCHEMA_VERSION = "1.0"

BUNDLE_DIR = Path(__file__).resolve().parents[1] / "bundle"
VERIFY_SCRIPT = (BUNDLE_DIR / "verify.py").read_text(encoding="utf-8")
VERIFY_README = (BUNDLE_DIR / "VERIFY_README.txt").read_text(encoding="utf-8")


def _serialize_event(db: Session, org_id: str, event: Event) -> dict[str, Any]:
    payload_row = event_repo.get_payload(db, org_id, event.payload_hash)
    content = event_repo.read_payload_content(db, org_id, event.payload_hash)
    created_at = event.envelope["created_at"]
    return {
        "id": str(event.id),
        "trace_id": str(event.trace_id),
        "seq": event.seq,
        "type": event.type,
        "payload_hash": event.payload_hash,
        "payload": content,
        "payload_erased": payload_row.erased_at is not None if payload_row else False,
        "pii_redacted": payload_row.pii_labels if payload_row else [],
        "prev_hash": event.prev_hash,
        "hash": event.hash,
        "signature": event.signature,
        "alg": event.envelope.get("alg"),
        "policy_version": event.policy_version,
        "created_at": created_at,
        "batch_id": str(event.batch_id) if event.batch_id else None,
    }


def _batch_leaf_hashes(db: Session, batch: Batch) -> list[str]:
    leaves: list[str] = []
    for event_id in batch.event_ids:
        event = db.query(Event).filter(Event.id == uuid.UUID(event_id)).one()
        leaves.append(event.hash)
    return leaves


def _serialize_batch(db: Session, batch: Batch, trace_event_ids: set[str]) -> dict[str, Any]:
    leaf_hashes = _batch_leaf_hashes(db, batch)
    leaf_hash_map = dict(zip(batch.event_ids, leaf_hashes, strict=True))
    merkle_proofs: dict[str, list[str]] = {}
    for index, event_id in enumerate(batch.event_ids):
        if event_id in trace_event_ids:
            merkle_proofs[event_id] = merkle_proof(leaf_hashes, index)

    anchor = db.query(Anchor).filter(Anchor.batch_id == batch.id).one_or_none()
    anchor_data = None
    if anchor is not None:
        anchor_data = {
            "kind": anchor.kind,
            "token": anchor.token,
            "anchored_at": anchor.anchored_at.isoformat(),
        }

    return {
        "batch_id": str(batch.id),
        "root": batch.root,
        "signature": batch.signature,
        "event_ids": batch.event_ids,
        "leaf_hashes": leaf_hash_map,
        "sealed_at": batch.sealed_at.isoformat(),
        "merkle_proofs": merkle_proofs,
        "anchor": anchor_data,
    }


def build_evidence_bundle(db: Session, *, org_id: str, trace_id: uuid.UUID) -> dict[str, Any]:
    ensure_trace_access(db, org_id, trace_id)
    events = event_repo.events_for_trace(db, org_id, trace_id)
    if not events:
        raise TraceNotFoundError(f"trace not found: {trace_id}")

    replay = replay_trace(db, org_id=org_id, trace_id=trace_id)
    serialized = [_serialize_event(db, org_id, event) for event in events]
    trace_event_ids = {str(event.id) for event in events}

    batches = batch_repo.batches_for_event_ids(db, [event.id for event in events])
    batch_data = [_serialize_batch(db, batch, trace_event_ids) for batch in batches]

    org = org_repo.get_org_by_id(db, org_id)
    compliance = build_compliance_summary(db, org_id=org_id, trace_id=trace_id)
    signing_meta = get_signing_provider().metadata()
    public_pem = load_public_pem().decode("utf-8")

    manifest = {
        "bundle_schema": BUNDLE_SCHEMA_VERSION,
        "product": "Attest",
        "trace_id": str(trace_id),
        "exported_at": now_utc_iso(),
        "org": {
            "id": org_id,
            "name": org.name if org else org_id,
            "region": org.region if org else None,
            "fail_mode": org.fail_mode if org else None,
        },
        "signing": signing_meta,
        "event_count": len(events),
        "batch_count": len(batch_data),
        "all_replay_verified": replay.all_verified,
    }

    return {
        "trace_id": str(trace_id),
        "exported_at": manifest["exported_at"],
        "bundle_schema": BUNDLE_SCHEMA_VERSION,
        "manifest": manifest,
        "compliance_summary": compliance,
        "public_key_pem": public_pem,
        "replay_summary": {
            "all_verified": replay.all_verified,
            "events": [asdict(item) for item in replay.events],
        },
        "events": serialized,
        "batches": batch_data,
        "batch": batch_data[0] if len(batch_data) == 1 else None,
        "verification_instructions": VERIFY_README,
        "verify_script": VERIFY_SCRIPT,
    }


def bundle_to_zip(bundle: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bundle.json", json.dumps(bundle, indent=2, ensure_ascii=False))
        archive.writestr(
            "manifest.json",
            json.dumps(bundle.get("manifest", {}), indent=2, ensure_ascii=False),
        )
        archive.writestr(
            "compliance_summary.json",
            json.dumps(bundle.get("compliance_summary", {}), indent=2, ensure_ascii=False),
        )
        archive.writestr("verify.py", bundle["verify_script"])
        archive.writestr("VERIFY_README.txt", bundle["verification_instructions"])
        archive.writestr("public_key.pem", bundle["public_key_pem"])
    return buffer.getvalue()
