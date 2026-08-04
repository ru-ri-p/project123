"""regulation_sources.pending_hash — confirm drift before reporting it

A single differing fetch is as likely to be a rotating banner or a CSRF nonce as
a change in the law. Drift is now only reported when the same new content is seen
on two consecutive sweeps, so the queue stays worth reading.

Revision ID: b1f6c8d420ae
Revises: a4e7d92c31b8
Create Date: 2026-08-04

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b1f6c8d420ae"
down_revision: str | Sequence[str] | None = "a4e7d92c31b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("regulation_sources", sa.Column("pending_hash", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("regulation_sources", "pending_hash")
