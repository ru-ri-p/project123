"""orgs.requires_profile — the onboarding gate

An org must declare its profile before it can record, so obligations are
established BEFORE evidence exists. Existing orgs are grandfathered to False in
this migration: a live integration must never break because we shipped a gate.
New orgs default to True.

Revision ID: f2b81d603ca9
Revises: e9c47b21f5a0
Create Date: 2026-08-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f2b81d603ca9"
down_revision: str | Sequence[str] | None = "e9c47b21f5a0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Added with server_default false so every EXISTING row is grandfathered...
    op.add_column(
        "orgs",
        sa.Column("requires_profile", sa.Boolean(), server_default="false", nullable=False),
    )
    # ...then flipped to true, so rows created from here on are gated.
    op.alter_column("orgs", "requires_profile", server_default="true")


def downgrade() -> None:
    op.drop_column("orgs", "requires_profile")
