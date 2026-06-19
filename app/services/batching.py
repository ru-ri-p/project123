"""Seal unbatched events into signed Merkle batches."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.crypto.merkle import merkle_root
from app.crypto.signing_provider import sign_message_hex
from app.repositories import batches as batch_repo
from app.services.envelope import now_utc_iso


@dataclass(frozen=True)
class SealedBatchResult:
    batch_id: uuid.UUID
    root: str
    signature: str
    event_count: int


def seal_batch(db: Session) -> SealedBatchResult | None:
    """Gather unbatched events, compute Merkle root, sign, and persist batch."""
    events = batch_repo.unbatched_events(db)
    if not events:
        return None

    leaf_hashes = [event.hash for event in events]
    root = merkle_root(leaf_hashes)
    signature = sign_message_hex(root)

    sealed_at = datetime.fromisoformat(now_utc_iso()).replace(tzinfo=UTC)
    event_ids = [str(event.id) for event in events]

    org_ids = {event.org_id for event in events}
    org_id: str | None = next(iter(org_ids)) if len(org_ids) == 1 else None

    batch = batch_repo.insert_batch(
        db,
        org_id=org_id,
        root=root,
        signature=signature,
        event_ids=event_ids,
        sealed_at=sealed_at,
    )
    batch_repo.assign_events_to_batch(
        db,
        event_ids=[event.id for event in events],
        batch_id=batch.id,
    )

    return SealedBatchResult(
        batch_id=batch.id,
        root=root,
        signature=signature,
        event_count=len(events),
    )
