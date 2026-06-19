"""SQLAlchemy models — keep in sync with instructions.txt §9."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.crypto.algorithms import DEFAULT_ALGORITHM, DEFAULT_CONTENT_ALGORITHM
from app.db.base import Base

EVENT_TYPES = (
    "model_completion",
    "tool_call",
    "policy_decision",
    "approval_action",
    "mitigation",
    "erasure",
)


class Org(Base):
    __tablename__ = "orgs"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    api_key_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    region: Mapped[str] = mapped_column(String(16), nullable=False, server_default="uae")
    retention_days_payload: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="365"
    )
    fail_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="deny_on_error"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    traces: Mapped[list[Trace]] = relationship(back_populates="org")
    events: Mapped[list[Event]] = relationship(back_populates="org")
    policies: Mapped[list[Policy]] = relationship(back_populates="org")


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("org_id", "version", name="uq_policies_org_version"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    rules: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    active: Mapped[bool] = mapped_column(nullable=False, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    org: Mapped[Org] = relationship(back_populates="policies")


class Trace(Base):
    __tablename__ = "traces"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    policy_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    root_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    org: Mapped[Org] = relationship(back_populates="traces")
    events: Mapped[list[Event]] = relationship(back_populates="trace")


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (UniqueConstraint("trace_id", "seq", name="uq_events_trace_seq"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    trace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("traces.id"), nullable=False, index=True
    )
    batch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("batches.id"), nullable=True, index=True
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)
    payload_hash: Mapped[str] = mapped_column(Text, nullable=False)
    envelope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    prev_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    hash: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    # Algorithm suite used to hash+sign this event (also stored inside the
    # signed envelope). Lets the verifier dispatch on it for crypto-agility.
    alg: Mapped[str] = mapped_column(Text, nullable=False, server_default=DEFAULT_ALGORITHM)
    policy_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    org: Mapped[Org] = relationship(back_populates="events")
    trace: Mapped[Trace] = relationship(back_populates="events")
    batch: Mapped[Batch | None] = relationship(back_populates="events")


class Batch(Base):
    __tablename__ = "batches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("orgs.id"), nullable=True, index=True
    )
    root: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    event_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    sealed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    events: Mapped[list[Event]] = relationship(back_populates="batch")
    anchor: Mapped[Anchor | None] = relationship(back_populates="batch", uselist=False)


class Anchor(Base):
    __tablename__ = "anchors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("batches.id"), nullable=False, unique=True, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False, server_default="rfc3161")
    token: Mapped[str] = mapped_column(Text, nullable=False)
    anchored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    batch: Mapped[Batch] = relationship(back_populates="anchor")


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    trace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("traces.id"), nullable=False, index=True
    )
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("events.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")
    approver_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Payload(Base):
    """Encrypted content store — separate from signed envelope (instructions §4d)."""

    __tablename__ = "payloads"

    payload_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    encrypted_blob: Mapped[str] = mapped_column(Text, nullable=False)
    # Content-encryption suite for this blob; lets the read path dispatch and
    # supports migrating the cipher without losing older records.
    enc_alg: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=DEFAULT_CONTENT_ALGORITHM
    )
    pii_labels: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    erased_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class PayloadKey(Base):
    """Per-record encryption key — deleting this row crypto-shreds the payload."""

    __tablename__ = "payload_keys"

    payload_hash: Mapped[str] = mapped_column(
        Text, ForeignKey("payloads.payload_hash"), primary_key=True
    )
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    key_b64: Mapped[str] = mapped_column(Text, nullable=False)
