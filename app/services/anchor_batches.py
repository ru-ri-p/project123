"""Anchor sealed batches to an external RFC 3161 timestamp authority."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.config import get_settings
from app.repositories import batches as batch_repo
from app.services.anchoring import encode_token_b64, request_tsa_timestamp
from app.services.envelope import now_utc_iso


@dataclass(frozen=True)
class AnchorResult:
    batch_id: uuid.UUID
    anchor_id: uuid.UUID
    kind: str
    anchored_at: str


def anchor_batch(db: Session, batch_id: uuid.UUID) -> AnchorResult:
    """Timestamp the batch Merkle root with an external TSA."""
    batch = batch_repo.batch_by_id(db, batch_id)
    if batch is None:
        msg = f"batch not found: {batch_id}"
        raise ValueError(msg)

    existing = batch.anchor
    if existing is not None:
        msg = f"batch already anchored: {batch_id}"
        raise ValueError(msg)

    settings = get_settings()
    root_bytes = bytes.fromhex(batch.root)
    token_bytes = request_tsa_timestamp(root_bytes, tsa_url=settings.tsa_url)

    anchored_at = datetime.fromisoformat(now_utc_iso()).replace(tzinfo=UTC)
    anchor = batch_repo.insert_anchor(
        db,
        batch_id=batch_id,
        kind="rfc3161",
        token=encode_token_b64(token_bytes),
        anchored_at=anchored_at,
    )

    return AnchorResult(
        batch_id=batch_id,
        anchor_id=anchor.id,
        kind="rfc3161",
        anchored_at=now_utc_iso(),
    )


def anchor_unanchored_batches(db: Session) -> list[AnchorResult]:
    """Anchor every sealed batch that lacks an external timestamp."""
    results: list[AnchorResult] = []
    for batch in batch_repo.unanchored_batches(db):
        results.append(anchor_batch(db, batch.id))
    return results
