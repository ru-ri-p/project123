"""consent-gated access review: requests, approvals, grant keys

Revision ID: c9e2b4f60a17
Revises: b5d1f0a3c8e2
Create Date: 2026-06-19

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "c9e2b4f60a17"
down_revision: str | Sequence[str] | None = "b5d1f0a3c8e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "access_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("required_approvals", sa.Integer(), server_default="1", nullable=False),
        sa.Column("grantee_public_pem", sa.Text(), nullable=False),
        sa.Column("grantee_private_pem", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_access_requests_org_id"), "access_requests", ["org_id"], unique=False)

    op.create_table(
        "access_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approver_id", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["request_id"], ["access_requests.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id", "approver_id", name="uq_access_approval_request_approver"),
    )
    op.create_index(
        op.f("ix_access_approvals_request_id"), "access_approvals", ["request_id"], unique=False
    )

    op.create_table(
        "access_grant_keys",
        sa.Column("request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("wrapped_key_b64", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["request_id"], ["access_requests.id"]),
        sa.PrimaryKeyConstraint("request_id", "payload_hash"),
    )


def downgrade() -> None:
    op.drop_table("access_grant_keys")
    op.drop_index(op.f("ix_access_approvals_request_id"), table_name="access_approvals")
    op.drop_table("access_approvals")
    op.drop_index(op.f("ix_access_requests_org_id"), table_name="access_requests")
    op.drop_table("access_requests")
