"""composite (org_id, payload_hash) PK for payloads + payload_keys

Multi-tenancy fix: the same content hash can legitimately recur across orgs, so
a payload must be keyed by (org_id, payload_hash), not the hash alone. A global
payload_hash PK made a second org storing identical content collide on insert.

Revision ID: e3b8f5c07d29
Revises: d0a7c1e93b45
Create Date: 2026-07-28

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "e3b8f5c07d29"
down_revision: str | Sequence[str] | None = "d0a7c1e93b45"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Drop the single-column FK before touching the PK it references.
    op.drop_constraint("payload_keys_payload_hash_fkey", "payload_keys", type_="foreignkey")
    # Widen both primary keys to (org_id, payload_hash).
    op.drop_constraint("payload_keys_pkey", "payload_keys", type_="primary")
    op.drop_constraint("payloads_pkey", "payloads", type_="primary")
    op.create_primary_key("payloads_pkey", "payloads", ["org_id", "payload_hash"])
    op.create_primary_key("payload_keys_pkey", "payload_keys", ["org_id", "payload_hash"])
    # Recreate the FK as a composite referencing the new payloads PK.
    op.create_foreign_key(
        "payload_keys_payload_fkey",
        "payload_keys",
        "payloads",
        ["org_id", "payload_hash"],
        ["org_id", "payload_hash"],
    )


def downgrade() -> None:
    op.drop_constraint("payload_keys_payload_fkey", "payload_keys", type_="foreignkey")
    op.drop_constraint("payload_keys_pkey", "payload_keys", type_="primary")
    op.drop_constraint("payloads_pkey", "payloads", type_="primary")
    op.create_primary_key("payloads_pkey", "payloads", ["payload_hash"])
    op.create_primary_key("payload_keys_pkey", "payload_keys", ["payload_hash"])
    op.create_foreign_key(
        "payload_keys_payload_hash_fkey",
        "payload_keys",
        "payloads",
        ["payload_hash"],
        ["payload_hash"],
    )
