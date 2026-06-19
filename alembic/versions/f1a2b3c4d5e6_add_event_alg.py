"""add per-event algorithm id

Revision ID: f1a2b3c4d5e6
Revises: e2002c48d966
Create Date: 2026-06-19

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f1a2b3c4d5e6"
down_revision: str | Sequence[str] | None = "e2002c48d966"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Default suite for any pre-existing rows; matches app/crypto/algorithms.py.
ALG_DEFAULT = "sha256-ed25519-v1"


def upgrade() -> None:
    op.add_column(
        "events",
        sa.Column("alg", sa.Text(), nullable=False, server_default=ALG_DEFAULT),
    )


def downgrade() -> None:
    op.drop_column("events", "alg")
