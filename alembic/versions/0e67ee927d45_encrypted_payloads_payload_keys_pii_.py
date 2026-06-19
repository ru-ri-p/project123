"""encrypted payloads payload_keys pii erasure

Revision ID: 0e67ee927d45
Revises: cb84d388d98e
Create Date: 2026-06-01

"""

from __future__ import annotations

import base64
import json
from collections.abc import Sequence

import sqlalchemy as sa
from cryptography.fernet import Fernet
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0e67ee927d45"
down_revision: str | Sequence[str] | None = "cb84d388d98e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _encrypt(content: dict) -> tuple[str, str]:
    key = Fernet.generate_key()
    blob = Fernet(key).encrypt(json.dumps(content, ensure_ascii=False).encode("utf-8"))
    return base64.b64encode(blob).decode("ascii"), base64.b64encode(key).decode("ascii")


def upgrade() -> None:
    op.add_column("payloads", sa.Column("encrypted_blob", sa.Text(), nullable=True))
    op.add_column("payloads", sa.Column("pii_labels", postgresql.JSONB(), nullable=True))
    op.add_column("payloads", sa.Column("erased_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "payload_keys",
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("key_b64", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"]),
        sa.ForeignKeyConstraint(["payload_hash"], ["payloads.payload_hash"]),
        sa.PrimaryKeyConstraint("payload_hash"),
    )
    op.create_index(op.f("ix_payload_keys_org_id"), "payload_keys", ["org_id"], unique=False)

    bind = op.get_bind()
    rows = bind.execute(
        sa.text("SELECT payload_hash, org_id, content FROM payloads")
    ).fetchall()
    for payload_hash, org_id, content in rows:
        payload_dict = content if isinstance(content, dict) else {}
        encrypted_blob, key_b64 = _encrypt(payload_dict)
        bind.execute(
            sa.text(
                "UPDATE payloads SET encrypted_blob = :blob, pii_labels = CAST(:labels AS jsonb) "
                "WHERE payload_hash = :hash"
            ),
            {"blob": encrypted_blob, "labels": json.dumps([]), "hash": payload_hash},
        )
        bind.execute(
            sa.text(
                "INSERT INTO payload_keys (payload_hash, org_id, key_b64) "
                "VALUES (:hash, :org_id, :key_b64)"
            ),
            {"hash": payload_hash, "org_id": org_id, "key_b64": key_b64},
        )

    op.drop_column("payloads", "content")
    op.alter_column("payloads", "encrypted_blob", nullable=False)
    op.alter_column("payloads", "pii_labels", nullable=False)


def downgrade() -> None:
    op.add_column(
        "payloads",
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT p.payload_hash, p.encrypted_blob, k.key_b64 "
            "FROM payloads p JOIN payload_keys k ON p.payload_hash = k.payload_hash"
        )
    ).fetchall()
    for payload_hash, encrypted_blob, key_b64 in rows:
        key = base64.b64decode(key_b64.encode("ascii"))
        blob = base64.b64decode(encrypted_blob.encode("ascii"))
        content = json.loads(Fernet(key).decrypt(blob).decode("utf-8"))
        bind.execute(
            sa.text("UPDATE payloads SET content = CAST(:content AS jsonb) WHERE payload_hash = :hash"),
            {"content": json.dumps(content), "hash": payload_hash},
        )

    op.drop_index(op.f("ix_payload_keys_org_id"), table_name="payload_keys")
    op.drop_table("payload_keys")
    op.drop_column("payloads", "erased_at")
    op.drop_column("payloads", "pii_labels")
    op.drop_column("payloads", "encrypted_blob")
    op.alter_column("payloads", "content", nullable=False)
