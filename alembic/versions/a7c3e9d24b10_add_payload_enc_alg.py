"""add payload content-encryption suite id

Revision ID: a7c3e9d24b10
Revises: f1a2b3c4d5e6
Create Date: 2026-06-19

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a7c3e9d24b10"
down_revision: str | Sequence[str] | None = "f1a2b3c4d5e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Default content-encryption suite; matches app/crypto/algorithms.py.
ENC_ALG_DEFAULT = "aes-256-gcm-v1"


def upgrade() -> None:
    op.add_column(
        "payloads",
        sa.Column("enc_alg", sa.Text(), nullable=False, server_default=ENC_ALG_DEFAULT),
    )


def downgrade() -> None:
    op.drop_column("payloads", "enc_alg")
