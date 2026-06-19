"""add batches anchors event batch_id

Revision ID: cb84d388d98e
Revises: 0382943be7cf
Create Date: 2026-06-01

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "cb84d388d98e"
down_revision: str | Sequence[str] | None = "0382943be7cf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "batches",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=True),
        sa.Column("root", sa.Text(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("event_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_batches_org_id"), "batches", ["org_id"], unique=False)

    op.create_table(
        "anchors",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("batch_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(length=32), server_default="rfc3161", nullable=False),
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("anchored_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["batch_id"], ["batches.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("batch_id"),
    )
    op.create_index(op.f("ix_anchors_batch_id"), "anchors", ["batch_id"], unique=False)

    op.add_column("events", sa.Column("batch_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_events_batch_id", "events", "batches", ["batch_id"], ["id"])
    op.create_index(op.f("ix_events_batch_id"), "events", ["batch_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_events_batch_id"), table_name="events")
    op.drop_constraint("fk_events_batch_id", "events", type_="foreignkey")
    op.drop_column("events", "batch_id")
    op.drop_index(op.f("ix_anchors_batch_id"), table_name="anchors")
    op.drop_table("anchors")
    op.drop_index(op.f("ix_batches_org_id"), table_name="batches")
    op.drop_table("batches")
