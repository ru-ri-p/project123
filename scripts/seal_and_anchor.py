#!/usr/bin/env python3
"""Seal unbatched events and anchor batches to an external TSA (cron-friendly)."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.db.session import SessionLocal
from app.services.anchor_batches import anchor_unanchored_batches
from app.services.batching import seal_batch

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seal and anchor Attest event batches")
    parser.add_argument("--seal-only", action="store_true", help="Only seal, do not anchor")
    parser.add_argument("--anchor-only", action="store_true", help="Only anchor existing batches")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        if not args.anchor_only:
            sealed = seal_batch(db)
            if sealed is None:
                logger.info("No unbatched events to seal.")
            else:
                logger.info(
                    "Sealed batch %s: %d events, root=%s...",
                    sealed.batch_id,
                    sealed.event_count,
                    sealed.root[:16],
                )
            db.commit()

        if not args.seal_only:
            anchored = anchor_unanchored_batches(db)
            if not anchored:
                logger.info("No unanchored batches.")
            for result in anchored:
                logger.info("Anchored batch %s at %s", result.batch_id, result.anchored_at)
            db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
