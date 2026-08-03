"""org profiles (jurisdictions x sectors) + reduction approval

Obligations are derived from the profile instead of picked from a menu, so a firm
cannot cherry-pick its way to a clean dashboard. Adding applies at once; removing
needs Attest's approval.

Revision ID: e9c47b21f5a0
Revises: d5a20c19e847
Create Date: 2026-08-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "e9c47b21f5a0"
down_revision: str | Sequence[str] | None = "d5a20c19e847"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "org_profiles",
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("jurisdictions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("sectors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("updated_by", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.PrimaryKeyConstraint("org_id"),
    )

    op.create_table(
        "profile_change_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "proposed_jurisdictions", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("proposed_sectors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("removed", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("decided_by", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_profile_change_requests_org_id", "profile_change_requests", ["org_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_profile_change_requests_org_id", table_name="profile_change_requests")
    op.drop_table("profile_change_requests")
    op.drop_table("org_profiles")
