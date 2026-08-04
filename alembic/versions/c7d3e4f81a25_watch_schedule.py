"""regulation_sources.next_check_at — spread the sweep over time

The first live sweep asked several regulators for pages at the same moment and
difc.com answered 429. A sweep now only touches sources that are due, so the work
spreads across runs instead of arriving as one burst. NULL means never checked,
which is due immediately.

Revision ID: c7d3e4f81a25
Revises: b1f6c8d420ae
Create Date: 2026-08-04

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c7d3e4f81a25"
down_revision: str | Sequence[str] | None = "b1f6c8d420ae"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "regulation_sources",
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_regulation_sources_next_check_at", "regulation_sources", ["next_check_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_regulation_sources_next_check_at", table_name="regulation_sources")
    op.drop_column("regulation_sources", "next_check_at")
