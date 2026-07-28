"""org confidentiality mode + wrapping key, wrapped payload keys

Revision ID: b5d1f0a3c8e2
Revises: a7c3e9d24b10
Create Date: 2026-06-19

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b5d1f0a3c8e2"
down_revision: str | Sequence[str] | None = "a7c3e9d24b10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "orgs",
        sa.Column(
            "confidentiality_mode",
            sa.String(length=32),
            nullable=False,
            server_default="attest_managed",
        ),
    )
    op.add_column("orgs", sa.Column("wrapping_public_pem", sa.Text(), nullable=True))
    op.add_column("payload_keys", sa.Column("wrap_alg", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("payload_keys", "wrap_alg")
    op.drop_column("orgs", "wrapping_public_pem")
    op.drop_column("orgs", "confidentiality_mode")
