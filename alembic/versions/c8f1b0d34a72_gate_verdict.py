"""gate verdict on policy decision summaries

The gate returns a verdict (compliant | flagged | blocked | unevaluated). Store
it alongside the decision so the dashboards show exactly what the caller was
told, instead of recomputing it and risking divergence. NULL for decisions made
through the older precheck path.

Revision ID: c8f1b0d34a72
Revises: b7e3a92c15d4
Create Date: 2026-08-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c8f1b0d34a72"
down_revision: str | Sequence[str] | None = "b7e3a92c15d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "policy_decision_summaries", sa.Column("status", sa.String(length=16), nullable=True)
    )
    op.add_column(
        "policy_decision_summaries", sa.Column("output_seq", sa.Integer(), nullable=True)
    )
    op.add_column(
        "policy_decision_summaries", sa.Column("output_hash", sa.Text(), nullable=True)
    )
    op.create_index(
        "ix_policy_decision_summaries_status", "policy_decision_summaries", ["status"]
    )


def downgrade() -> None:
    op.drop_index("ix_policy_decision_summaries_status", table_name="policy_decision_summaries")
    op.drop_column("policy_decision_summaries", "output_hash")
    op.drop_column("policy_decision_summaries", "output_seq")
    op.drop_column("policy_decision_summaries", "status")
