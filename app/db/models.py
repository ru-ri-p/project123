"""SQLAlchemy models — keep in sync with instructions.txt §9."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
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
    # Confidentiality: "attest_managed" (Attest can read stored content) or
    # "customer_key" (content keys are wrapped to wrapping_public_pem, so stored
    # content is dark to Attest until the org releases a key via consent).
    confidentiality_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="attest_managed"
    )
    # Org's PUBLIC wrapping key (PEM). Attest holds only this; the private key
    # stays in the org's custody. Required for confidentiality_mode=customer_key.
    wrapping_public_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    # Which per-org signing key signed this event. NULL = the global service key
    # (backward compatible with events signed before per-org keys existed).
    signing_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("org_signing_keys.key_id"), nullable=True
    )
    policy_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # --- offline provenance -------------------------------------------------
    # Set only for events buffered during an Attest outage and grafted in later.
    # created_at is when Attest recorded it; occurred_at is when the customer's
    # system says it happened, and client_signature is the device's signature
    # over that claim — so the gap is evidenced rather than merely asserted.
    deferred: Mapped[bool] = mapped_column(nullable=False, server_default="false")
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    client_device_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    client_signature: Mapped[str | None] = mapped_column(Text, nullable=True)

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

    # Composite PK: the same content hash can legitimately recur across orgs, so
    # a record is identified by (org_id, payload_hash), never the hash alone.
    org_id: Mapped[str] = mapped_column(
        Text, ForeignKey("orgs.id"), primary_key=True, index=True
    )
    payload_hash: Mapped[str] = mapped_column(Text, primary_key=True)
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
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "payload_hash"],
            ["payloads.org_id", "payloads.payload_hash"],
            name="payload_keys_payload_fkey",
        ),
    )

    # Composite PK mirrors payloads: one key row per (org_id, payload_hash).
    org_id: Mapped[str] = mapped_column(
        Text, ForeignKey("orgs.id"), primary_key=True, index=True
    )
    payload_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    # base64 of the content key (DEK). If wrap_alg is NULL the DEK is stored as-is
    # (attest_managed). If wrap_alg is set, key_b64 is the DEK WRAPPED to the org's
    # public key — Attest cannot unwrap it, so the content is dark.
    key_b64: Mapped[str] = mapped_column(Text, nullable=False)
    wrap_alg: Mapped[str | None] = mapped_column(Text, nullable=True)


class AccessRequest(Base):
    """Attest's request to view a scoped set of a customer-key org's records.

    The org approves (1 or M-of-N) and releases keys for exactly the scope. The
    grantee keypair is ephemeral, generated per request; the org only ever
    re-wraps content keys to grantee_public_pem, never exposes its master key.
    """

    __tablename__ = "access_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(Text, nullable=False)  # Attest operator
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")
    required_approvals: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    grantee_public_pem: Mapped[str] = mapped_column(Text, nullable=False)
    grantee_private_pem: Mapped[str] = mapped_column(Text, nullable=False)  # Attest's ephemeral key
    # The request's CONSENT TRACE: every lifecycle action (filed, approved,
    # denied/revoked, each read via the grant) is a signed hash-chained event in
    # this trace, so the access trail is tamper-evident like any customer record.
    # NULL only for requests that predate the consent-trail feature.
    trace_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("traces.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AccessApproval(Base):
    """One officer's approval of an access request (M-of-N counts these rows)."""

    __tablename__ = "access_approvals"
    __table_args__ = (
        UniqueConstraint("request_id", "approver_id", name="uq_access_approval_request_approver"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("access_requests.id"), nullable=False, index=True
    )
    approver_id: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AccessGrantKey(Base):
    """Scope + released key for one record in a request. wrapped_key_b64 is NULL
    until approval, then holds the record's content key re-wrapped to the grantee."""

    __tablename__ = "access_grant_keys"

    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("access_requests.id"), primary_key=True
    )
    payload_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    wrapped_key_b64: Mapped[str | None] = mapped_column(Text, nullable=True)


class OrgProfile(Base):
    """Where an institution is licensed and what it does.

    This is the anti-evasion mechanism. Obligations are DERIVED from the profile
    rather than picked from a menu — a firm cannot adopt the data-protection
    rulebook, skip the conduct one, and show a clean dashboard.

    Adding a jurisdiction or sector takes effect immediately: taking on more
    obligations is never the thing to guard against. REMOVING one requires Attest
    to approve, because that is the move that sheds obligations, and it is
    recorded either way.
    """

    __tablename__ = "org_profiles"

    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), primary_key=True)
    jurisdictions: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    sectors: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_by: Mapped[str | None] = mapped_column(Text, nullable=True)


class ProfileChangeRequest(Base):
    """A request to REMOVE a jurisdiction or sector — needs Attest's approval.

    Additions never come through here; they apply at once. Only reductions do,
    because only reductions shed obligations.
    """

    __tablename__ = "profile_change_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    # The profile as it would be if approved.
    proposed_jurisdictions: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    proposed_sectors: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    removed: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")
    decided_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class SdkDevice(Base):
    """An SDK instance's own signing key, registered automatically on first run.

    Exists for one reason: when Attest is unreachable, the SDK must keep a record
    that is still tamper-evident. Events buffered during an outage are signed
    into a local chain by this key and verified server-side when they are grafted
    in. Without it, the outage window would be "trust the client's buffer" —
    exactly the assumption the product exists to remove, given the threat model
    includes compromised insiders on the client side.

    Attest holds only the public half; the private key never leaves the SDK host.
    """

    __tablename__ = "sdk_devices"
    __table_args__ = (
        UniqueConstraint("org_id", "device_id", name="uq_sdk_device_org_device"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(Text, nullable=False)
    public_pem: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked: Mapped[bool] = mapped_column(nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RegulationPack(Base):
    """A versioned rulebook for one jurisdiction, published by Attest.

    Separate from Policy (which is the institution's OWN policy, authored by the
    institution). Packs are advisory in the MVP: they raise findings and cite the
    instrument, they do not block. verification_status travels with every finding
    so an unreviewed rule can never pass for a settled legal position.
    """

    __tablename__ = "regulation_packs"
    __table_args__ = (
        UniqueConstraint("code", "version", name="uq_regulation_pack_code_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    jurisdiction: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    instrument: Mapped[str] = mapped_column(Text, nullable=False)
    instrument_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    effective_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # unverified | self_reviewed | counsel_reviewed
    verification_status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="unverified"
    )
    reviewed_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rules: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class OrgRegulationPack(Base):
    """Which packs apply to an org. An institution may span several jurisdictions."""

    __tablename__ = "org_regulation_packs"

    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), primary_key=True)
    pack_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("regulation_packs.id"), primary_key=True
    )
    # advisory = raise findings only (MVP). blocking reserved for a later slice,
    # once rule content has had legal review — a bad rule that blocks stops the
    # customer's business.
    enforcement: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="advisory"
    )
    enabled: Mapped[bool] = mapped_column(nullable=False, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class PolicyDecisionSummary(Base):
    """Non-sensitive index of policy decisions, for the compliance dashboards.

    The full decision lives in the signed policy_decision event, whose payload is
    encrypted — and for a customer-key org that payload is dark to Attest, so
    neither dashboard could read findings back out of it. This table stores only
    metadata that is NOT customer content: risk tier, which rulebooks fired, and
    which rule ids. No payload, no PII, nothing that would weaken the darkness
    guarantee. The event remains the authoritative record; this is an index.
    """

    __tablename__ = "policy_decision_summaries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    trace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    event_hash: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    tier: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_tier: Mapped[str] = mapped_column(String(16), nullable=False)
    allowed: Mapped[bool] = mapped_column(nullable=False)
    policy_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    # [{pack_code, jurisdiction, instrument, rule_id, tier, topic, provision,
    #   verification_status, advisory_only}] — rule identifiers only.
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    jurisdictions: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    # Verdict as the caller was told it (compliant | flagged | blocked |
    # unevaluated). Stored rather than recomputed so the dashboards cannot drift
    # from what the customer's code actually received. NULL for decisions made
    # through the older precheck path, which had no gate verdict.
    status: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    # The gated output this decision judged, when it came through the gate.
    output_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class OrgSigningKey(Base):
    """A per-org signing key. The 'active' key signs new events; retired keys keep
    verifying the events they signed (the key-id is recorded on each event).
    private_pem is NULL for customer-controlled keys (signing happens org-side)."""

    __tablename__ = "org_signing_keys"

    key_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    alg: Mapped[str] = mapped_column(Text, nullable=False, server_default=DEFAULT_ALGORITHM)
    public_pem: Mapped[str] = mapped_column(Text, nullable=False)
    private_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
