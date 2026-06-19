"""Org-scoped and global batch database access."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import Anchor, Batch, Event


def unbatched_events(db: Session) -> list[Event]:
    """Events not yet assigned to a sealed batch, oldest first."""
    return (
        db.query(Event)
        .filter(Event.batch_id.is_(None))
        .order_by(Event.created_at.asc())
        .all()
    )


def insert_batch(
    db: Session,
    *,
    org_id: str | None,
    root: str,
    signature: str,
    event_ids: list[str],
    sealed_at: datetime,
) -> Batch:
    batch = Batch(
        org_id=org_id,
        root=root,
        signature=signature,
        event_ids=event_ids,
        sealed_at=sealed_at,
    )
    db.add(batch)
    db.flush()
    return batch


def assign_events_to_batch(
    db: Session,
    *,
    event_ids: list[uuid.UUID],
    batch_id: uuid.UUID,
) -> None:
    (
        db.query(Event)
        .filter(Event.id.in_(event_ids))
        .update({Event.batch_id: batch_id}, synchronize_session=False)
    )


def batch_by_id(db: Session, batch_id: uuid.UUID) -> Batch | None:
    return db.query(Batch).filter(Batch.id == batch_id).one_or_none()


def batches_for_event_ids(db: Session, event_ids: list[uuid.UUID]) -> list[Batch]:
    """Distinct batches that contain any of the given event ids."""
    if not event_ids:
        return []
    batches = (
        db.query(Batch)
        .join(Event, Event.batch_id == Batch.id)
        .filter(Event.id.in_(event_ids))
        .distinct()
        .all()
    )
    return batches


def unanchored_batches(db: Session) -> list[Batch]:
    return (
        db.query(Batch)
        .outerjoin(Anchor, Anchor.batch_id == Batch.id)
        .filter(Anchor.id.is_(None))
        .order_by(Batch.sealed_at.asc())
        .all()
    )


def insert_anchor(
    db: Session,
    *,
    batch_id: uuid.UUID,
    kind: str,
    token: str,
    anchored_at: datetime,
) -> Anchor:
    anchor = Anchor(
        batch_id=batch_id,
        kind=kind,
        token=token,
        anchored_at=anchored_at,
    )
    db.add(anchor)
    db.flush()
    return anchor
