"""policy_decision_summaries: the remediation loop's index columns

Three columns, three moments in the story:
  remediation       — shape of the fix offered (hash, kinds, counts; no content)
  remediation_of    — on the curing decision: the flagged seq it remediates
  remediated_by_seq — on the cured decision: the compliant seq that closed it

The signed events stay authoritative; these make "flagged → fixed → proven"
readable by the dashboards without touching (possibly dark) event payloads.

Revision ID: a2f83d19c7e4
Revises: f31d84b6c05a
Create Date: 2026-08-23

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "a2f83d19c7e4"
down_revision: str | Sequence[str] | None = "f31d84b6c05a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "policy_decision_summaries",
        sa.Column("remediation", JSONB(), nullable=True),
    )
    op.add_column(
        "policy_decision_summaries",
        sa.Column("remediation_of", sa.Integer(), nullable=True),
    )
    op.add_column(
        "policy_decision_summaries",
        sa.Column("remediated_by_seq", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("policy_decision_summaries", "remediated_by_seq")
    op.drop_column("policy_decision_summaries", "remediation_of")
    op.drop_column("policy_decision_summaries", "remediation")
