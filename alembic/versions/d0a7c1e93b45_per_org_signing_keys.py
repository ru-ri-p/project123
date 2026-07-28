"""per-org signing keys + event signing_key_id

Revision ID: d0a7c1e93b45
Revises: c9e2b4f60a17
Create Date: 2026-06-19

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "d0a7c1e93b45"
down_revision: str | Sequence[str] | None = "c9e2b4f60a17"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ALG_DEFAULT = "sha256-ed25519-v1"


def upgrade() -> None:
    op.create_table(
        "org_signing_keys",
        sa.Column("key_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("alg", sa.Text(), server_default=ALG_DEFAULT, nullable=False),
        sa.Column("public_pem", sa.Text(), nullable=False),
        sa.Column("private_pem", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), server_default="active", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.PrimaryKeyConstraint("key_id"),
    )
    op.create_index(
        op.f("ix_org_signing_keys_org_id"), "org_signing_keys", ["org_id"], unique=False
    )
    op.add_column(
        "events",
        sa.Column("signing_key_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_events_signing_key_id",
        "events",
        "org_signing_keys",
        ["signing_key_id"],
        ["key_id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_events_signing_key_id", "events", type_="foreignkey")
    op.drop_column("events", "signing_key_id")
    op.drop_index(op.f("ix_org_signing_keys_org_id"), table_name="org_signing_keys")
    op.drop_table("org_signing_keys")
