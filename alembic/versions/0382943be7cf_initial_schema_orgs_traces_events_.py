"""initial schema orgs traces events payloads

Revision ID: 0382943be7cf
Revises:
Create Date: 2026-06-01 02:33:58.029400

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0382943be7cf"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "orgs",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("api_key_hash", sa.Text(), nullable=False),
        sa.Column("region", sa.String(length=16), server_default="uae", nullable=False),
        sa.Column("retention_days_payload", sa.Integer(), server_default="365", nullable=False),
        sa.Column("fail_mode", sa.String(length=32), server_default="deny_on_error", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("api_key_hash"),
    )
    op.create_table(
        "traces",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=True),
        sa.Column("root_hash", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_traces_org_id"), "traces", ["org_id"], unique=False)
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("trace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("envelope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("prev_hash", sa.Text(), nullable=True),
        sa.Column("hash", sa.Text(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.ForeignKeyConstraint(["trace_id"], ["traces.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("trace_id", "seq", name="uq_events_trace_seq"),
    )
    op.create_index(op.f("ix_events_org_id"), "events", ["org_id"], unique=False)
    op.create_index(op.f("ix_events_trace_id"), "events", ["trace_id"], unique=False)
    op.create_table(
        "payloads",
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.PrimaryKeyConstraint("payload_hash"),
    )
    op.create_index(op.f("ix_payloads_org_id"), "payloads", ["org_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_payloads_org_id"), table_name="payloads")
    op.drop_table("payloads")
    op.drop_index(op.f("ix_events_trace_id"), table_name="events")
    op.drop_index(op.f("ix_events_org_id"), table_name="events")
    op.drop_table("events")
    op.drop_index(op.f("ix_traces_org_id"), table_name="traces")
    op.drop_table("traces")
    op.drop_table("orgs")
