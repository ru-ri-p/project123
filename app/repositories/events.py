"""Org-scoped database access for events and payloads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Event, Payload, Trace
from app.repositories import traces as trace_repo
from app.services.access import TraceAccessDeniedError


def get_or_create_trace(
    db: Session,
    org_id: str,
    trace_id: uuid.UUID,
    policy_version: str | None,
) -> Trace:
    existing = trace_repo.get_trace_by_id(db, trace_id)
    if existing is not None:
        if existing.org_id != org_id:
            raise TraceAccessDeniedError(f"trace access denied: {trace_id}")
        return existing

    trace = Trace(id=trace_id, org_id=org_id, policy_version=policy_version)
    db.add(trace)
    db.flush()
    return trace


def last_event_for_trace(db: Session, org_id: str, trace_id: uuid.UUID) -> Event | None:
    return (
        db.query(Event)
        .filter(Event.org_id == org_id, Event.trace_id == trace_id)
        .order_by(Event.seq.desc())
        .first()
    )


def events_for_trace(db: Session, org_id: str, trace_id: uuid.UUID) -> list[Event]:
    return (
        db.query(Event)
        .filter(Event.org_id == org_id, Event.trace_id == trace_id)
        .order_by(Event.seq.asc())
        .all()
    )


def get_payload(db: Session, org_id: str, payload_hash: str) -> Payload | None:
    return (
        db.query(Payload)
        .filter(Payload.org_id == org_id, Payload.payload_hash == payload_hash)
        .one_or_none()
    )


def read_payload_content(db: Session, org_id: str, payload_hash: str) -> dict[str, Any] | None:
    from app.services.payload_store import read_payload_content as _read

    return _read(db, org_id, payload_hash)


def store_encrypted_payload(
    db: Session,
    *,
    org_id: str,
    payload_hash: str,
    content: dict[str, Any],
    pii_labels: list[str],
) -> None:
    from app.services.payload_store import store_encrypted_payload as _store

    _store(
        db,
        org_id=org_id,
        payload_hash=payload_hash,
        content=content,
        pii_labels=pii_labels,
    )


def insert_event(
    db: Session,
    *,
    org_id: str,
    trace_id: uuid.UUID,
    seq: int,
    event_type: str,
    payload_hash: str,
    envelope: dict[str, Any],
    prev_hash: str | None,
    event_hash: str,
    signature: str,
    policy_version: str | None,
    alg: str,
    created_at: datetime,
) -> Event:
    event = Event(
        org_id=org_id,
        trace_id=trace_id,
        seq=seq,
        type=event_type,
        payload_hash=payload_hash,
        envelope=envelope,
        prev_hash=prev_hash,
        hash=event_hash,
        signature=signature,
        policy_version=policy_version,
        alg=alg,
        created_at=created_at,
    )
    db.add(event)
    db.flush()
    return event
