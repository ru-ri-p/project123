"""Trace replay — independent re-verification of hash chain and signatures."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.crypto.keys import load_public_pem
from app.repositories import events as event_repo
from app.services.access import TraceNotFoundError
from app.services.org_signing import public_pem_for_key
from app.services.trace_access import ensure_trace_access
from app.services.verification import TraceReplayResult, VerifiableEvent, verify_event_chain


def replay_trace(db: Session, *, org_id: str, trace_id: uuid.UUID) -> TraceReplayResult:
    ensure_trace_access(db, org_id, trace_id)
    events = event_repo.events_for_trace(db, org_id, trace_id)
    if not events:
        raise TraceNotFoundError(f"trace not found: {trace_id}")

    global_pem = load_public_pem()

    def resolve(event: VerifiableEvent) -> bytes:
        # Per-org key if this event was signed with one; else the global key.
        key_id = getattr(event, "signing_key_id", None)
        return public_pem_for_key(db, key_id) if key_id is not None else global_pem

    return verify_event_chain(str(trace_id), events, resolve_public_pem=resolve)
