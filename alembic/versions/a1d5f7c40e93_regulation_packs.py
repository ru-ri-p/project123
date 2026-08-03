"""regulation packs + per-org subscriptions

Jurisdiction-aware policy: packs are versioned rulebooks per jurisdiction
(DIFC/ADGM/UAE onshore), separate from the org's own internal Policy. Advisory
in the MVP — findings and citations, not blocking.

Revision ID: a1d5f7c40e93
Revises: f4c9a2e18b60
Create Date: 2026-08-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "a1d5f7c40e93"
down_revision: str | Sequence[str] | None = "f4c9a2e18b60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "regulation_packs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("code", sa.Text(), nullable=False),
        sa.Column("jurisdiction", sa.String(length=32), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("instrument", sa.Text(), nullable=False),
        sa.Column("instrument_notes", sa.Text(), nullable=True),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("effective_date", sa.String(length=32), nullable=True),
        sa.Column(
            "verification_status", sa.String(length=32), server_default="unverified", nullable=False
        ),
        sa.Column("reviewed_by", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rules", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code", "version", name="uq_regulation_pack_code_version"),
    )
    op.create_index("ix_regulation_packs_code", "regulation_packs", ["code"])
    op.create_index("ix_regulation_packs_jurisdiction", "regulation_packs", ["jurisdiction"])

    op.create_table(
        "org_regulation_packs",
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("pack_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("enforcement", sa.String(length=16), server_default="advisory", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.ForeignKeyConstraint(["pack_id"], ["regulation_packs.id"]),
        sa.PrimaryKeyConstraint("org_id", "pack_id"),
    )


def downgrade() -> None:
    op.drop_table("org_regulation_packs")
    op.drop_index("ix_regulation_packs_jurisdiction", table_name="regulation_packs")
    op.drop_index("ix_regulation_packs_code", table_name="regulation_packs")
    op.drop_table("regulation_packs")
