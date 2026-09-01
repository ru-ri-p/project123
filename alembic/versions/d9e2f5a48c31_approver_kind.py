"""approvals.approver_kind: authenticated (session-verified person) vs
asserted (name supplied over the org machine key). Nullable — historical
rows predate the distinction and stay honestly unlabeled.

Revision ID: d9e2f5a48c31
Revises: c8d4e7f31a92
Create Date: 2026-09-01

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d9e2f5a48c31"
down_revision: str | Sequence[str] | None = "c8d4e7f31a92"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("approvals", sa.Column("approver_kind", sa.String(16), nullable=True))


def downgrade() -> None:
    op.drop_column("approvals", "approver_kind")
