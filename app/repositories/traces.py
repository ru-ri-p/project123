"""Org-scoped trace database access."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.db.models import Trace


def get_trace_by_id(db: Session, trace_id: uuid.UUID) -> Trace | None:
    return db.query(Trace).filter(Trace.id == trace_id).one_or_none()


def get_trace_for_org(db: Session, org_id: str, trace_id: uuid.UUID) -> Trace | None:
    return (
        db.query(Trace)
        .filter(Trace.org_id == org_id, Trace.id == trace_id)
        .one_or_none()
    )


def list_traces_for_org(
    db: Session,
    org_id: str,
    *,
    limit: int = 50,
    offset: int = 0,
) -> list[Trace]:
    return (
        db.query(Trace)
        .filter(Trace.org_id == org_id)
        .order_by(Trace.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def event_count_for_trace(db: Session, org_id: str, trace_id: uuid.UUID) -> int:
    from app.db.models import Event

    return (
        db.query(Event)
        .filter(Event.org_id == org_id, Event.trace_id == trace_id)
        .count()
    )
