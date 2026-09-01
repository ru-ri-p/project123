"""Password login: users get an Argon2id hash + lockout brake; sessions record
how they were earned ("code" proves inbox custody and may reset a password;
"password" must know the current one to change it).

Revision ID: c8d4e7f31a92
Revises: b6c9d2e14f70
Create Date: 2026-09-01

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c8d4e7f31a92"
down_revision: str | Sequence[str] | None = "b6c9d2e14f70"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("password_hash", sa.Text(), nullable=True))
    op.add_column(
        "users",
        sa.Column("failed_logins", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "auth_sessions",
        sa.Column("method", sa.String(16), nullable=False, server_default="code"),
    )


def downgrade() -> None:
    op.drop_column("auth_sessions", "method")
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_logins")
    op.drop_column("users", "password_hash")
