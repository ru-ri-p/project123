"""policy decision summaries — non-sensitive index for the compliance dashboards

The signed policy_decision event stays authoritative, but its payload is
encrypted (and dark to Attest for customer-key orgs), so findings could not be
read back for display. This index stores tier + rule identifiers only: no payload,
no PII, nothing that weakens the darkness guarantee.

Revision ID: b7e3a92c15d4
Revises: a1d5f7c40e93
Create Date: 2026-08-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "b7e3a92c15d4"
down_revision: str | Sequence[str] | None = "a1d5f7c40e93"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "policy_decision_summaries",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("trace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("event_hash", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("tier", sa.String(length=16), nullable=False),
        sa.Column("policy_tier", sa.String(length=16), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=True),
        sa.Column("findings", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("jurisdictions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_policy_decision_summaries_org_id", "policy_decision_summaries", ["org_id"]
    )
    op.create_index(
        "ix_policy_decision_summaries_trace_id", "policy_decision_summaries", ["trace_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_policy_decision_summaries_trace_id", table_name="policy_decision_summaries")
    op.drop_index("ix_policy_decision_summaries_org_id", table_name="policy_decision_summaries")
    op.drop_table("policy_decision_summaries")
