"""regulation_sources.consecutive_failures — tell a blip from a wall

The first live sweeps showed failures grouping by HOST, not frequency: both
centralbank.ae URLs 403, both difc.com URLs 429, on the first request of the day
and after retries. That is bot protection, not a rate limit — and reporting it as
"transient, the next sweep will retry" every day would make the quarantine queue
worthless.

Counting the streak lets the summary say which it is.

Revision ID: e5a72c19d834
Revises: d8e1f2a63b47
Create Date: 2026-08-10

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e5a72c19d834"
down_revision: str | Sequence[str] | None = "d8e1f2a63b47"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "regulation_sources",
        sa.Column(
            "consecutive_failures",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("regulation_sources", "consecutive_failures")
