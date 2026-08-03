"""SDK devices + offline (deferred) event provenance

When Attest is unreachable the SDK buffers events and signs them into a local
chain with its own registered key. On recovery they are grafted in, carrying the
device's signature, the customer-claimed occurrence time, and a deferred flag —
so the outage window is evidenced rather than merely asserted.

Revision ID: d5a20c19e847
Revises: c8f1b0d34a72
Create Date: 2026-08-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "d5a20c19e847"
down_revision: str | Sequence[str] | None = "c8f1b0d34a72"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sdk_devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("device_id", sa.Text(), nullable=False),
        sa.Column("public_pem", sa.Text(), nullable=False),
        sa.Column("label", sa.Text(), nullable=True),
        sa.Column("revoked", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "device_id", name="uq_sdk_device_org_device"),
    )
    op.create_index("ix_sdk_devices_org_id", "sdk_devices", ["org_id"])

    op.add_column("events", sa.Column("deferred", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("events", sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("events", sa.Column("client_device_id", sa.Text(), nullable=True))
    op.add_column("events", sa.Column("client_signature", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("events", "client_signature")
    op.drop_column("events", "client_device_id")
    op.drop_column("events", "occurred_at")
    op.drop_column("events", "deferred")
    op.drop_index("ix_sdk_devices_org_id", table_name="sdk_devices")
    op.drop_table("sdk_devices")
