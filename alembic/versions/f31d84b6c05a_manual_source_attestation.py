"""regulation_sources: hand-supplied official text, attested by a named person

difc.com and rulebook.centralbank.ae refuse automated clients — 429 and 403 on the
first request of the day, after pacing, retries, and honest self-identification.
Four of seven sources could never be checked, and a permanently red queue is one
nobody reads.

So a person may supply the official text instead. Gate 1 then rests on their
attestation rather than on our fetch, which is a weaker guarantee and is recorded
as such: check_mode, attested_by, attested_at, attestation_note.

Revision ID: f31d84b6c05a
Revises: e5a72c19d834
Create Date: 2026-08-10

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f31d84b6c05a"
down_revision: str | Sequence[str] | None = "e5a72c19d834"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "regulation_sources",
        sa.Column(
            "check_mode", sa.String(16), nullable=False, server_default="auto"
        ),
    )
    op.add_column(
        "regulation_sources", sa.Column("attested_by", sa.Text(), nullable=True)
    )
    op.add_column(
        "regulation_sources",
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "regulation_sources", sa.Column("attestation_note", sa.Text(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("regulation_sources", "attestation_note")
    op.drop_column("regulation_sources", "attested_at")
    op.drop_column("regulation_sources", "attested_by")
    op.drop_column("regulation_sources", "check_mode")
