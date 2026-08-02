"""access_requests.trace_id — the consent trail's trace

Every consent action (request filed, approval, denial/revocation, each read via
the grant) becomes a signed hash-chained event in a per-request trace, making the
access ceremony itself tamper-evident. Nullable: requests that predate the
feature keep NULL and simply have no trail.

Revision ID: f4c9a2e18b60
Revises: e3b8f5c07d29
Create Date: 2026-08-02

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "f4c9a2e18b60"
down_revision: str | Sequence[str] | None = "e3b8f5c07d29"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "access_requests",
        sa.Column("trace_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_access_requests_trace_id", "access_requests", "traces", ["trace_id"], ["id"]
    )


def downgrade() -> None:
    op.drop_constraint("fk_access_requests_trace_id", "access_requests", type_="foreignkey")
    op.drop_column("access_requests", "trace_id")
