"""add approvals table

Revision ID: c8365aa99909
Revises: 0e67ee927d45
Create Date: 2026-06-01

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "c8365aa99909"
down_revision: str | Sequence[str] | None = "0e67ee927d45"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("trace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("approver_id", sa.Text(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.ForeignKeyConstraint(["trace_id"], ["traces.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_approvals_org_id"), "approvals", ["org_id"], unique=False)
    op.create_index(op.f("ix_approvals_trace_id"), "approvals", ["trace_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_approvals_trace_id"), table_name="approvals")
    op.drop_index(op.f("ix_approvals_org_id"), table_name="approvals")
    op.drop_table("approvals")
