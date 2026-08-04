"""regulation_sources.retired_at — stop sweeping URLs no pack cites any more

register_sources walked every pack ROW, and each pack version is its own row, so
a corrected source URL never displaced the old one: the previous version kept
re-registering its dead link on every sweep. The watcher then reported the same
404 daily, about a URL nothing cites — the crying-wolf failure the drift
confirmation exists to prevent.

Retired rather than deleted: the snapshot is the evidence behind anything
published from that source, and it has to stay re-checkable.

Revision ID: d8e1f2a63b47
Revises: c7d3e4f81a25
Create Date: 2026-08-04

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d8e1f2a63b47"
down_revision: str | Sequence[str] | None = "c7d3e4f81a25"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "regulation_sources",
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("regulation_sources", "retired_at")
