"""regulation sources + change log (the auto-update pipeline)

Sources are fetched on a schedule, snapshotted and hashed. A change either
auto-publishes — only if it is provable verbatim against the retained snapshot —
or is quarantined for a person.

Revision ID: a4e7d92c31b8
Revises: f2b81d603ca9
Create Date: 2026-08-04

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "a4e7d92c31b8"
down_revision: str | Sequence[str] | None = "f2b81d603ca9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "regulation_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pack_code", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=True),
        sa.Column("snapshot", sa.Text(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.Text(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("pack_code", "url", name="uq_regulation_source_pack_url"),
    )
    op.create_index("ix_regulation_sources_pack_code", "regulation_sources", ["pack_code"])

    op.create_table(
        "regulation_changes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pack_code", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("change_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="quarantined", nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("before_hash", sa.Text(), nullable=True),
        sa.Column("after_hash", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("published_version", sa.Text(), nullable=True),
        sa.Column("reviewed_by", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_regulation_changes_pack_code", "regulation_changes", ["pack_code"])
    op.create_index("ix_regulation_changes_status", "regulation_changes", ["status"])


def downgrade() -> None:
    op.drop_index("ix_regulation_changes_status", table_name="regulation_changes")
    op.drop_index("ix_regulation_changes_pack_code", table_name="regulation_changes")
    op.drop_table("regulation_changes")
    op.drop_index("ix_regulation_sources_pack_code", table_name="regulation_sources")
    op.drop_table("regulation_sources")
