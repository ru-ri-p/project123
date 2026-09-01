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
    # Onboarding gate: an org must declare its profile (jurisdictions x sectors)
    # before it can record anything, so obligations are always established BEFORE
    # evidence exists. Orgs that predate the gate are grandfathered to False so a
    # live integration is never broken by a deploy; they are prompted instead.
    requires_profile: Mapped[bool] = mapped_column(nullable=False, server_default="true")
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
    # How the approver's identity was established: "authenticated" (a signed-in
    # user resolved it; approver_id is their verified email) or "asserted" (the
    # org's machine key resolved it and TOLD us a name — legacy/SDK path).
    # Evidence-weight differs; the chain event records the same distinction.
    approver_kind: Mapped[str | None] = mapped_column(String(16), nullable=True)
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


class RegulationSource(Base):
    """An official source a pack is drawn from, and what we last saw there.

    The snapshot is retained deliberately: every auto-published claim must be
    re-checkable against the exact text it was drawn from, months later, by
    someone who does not trust us.
    """

    __tablename__ = "regulation_sources"
    __table_args__ = (
        UniqueConstraint("pack_code", "url", name="uq_regulation_source_pack_url"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pack_code: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    # SHA-256 of the normalised fetched text — the drift signal.
    content_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    # A differing hash awaiting confirmation on the next sweep. Drift is only
    # reported once the same new content is seen twice, so a rotating banner or
    # an A/B variant does not raise a false alarm every day.
    pending_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Set when a pack stops citing this URL — usually because a dead link was
    # corrected. Retired sources are never fetched again, but are NOT deleted:
    # the snapshot is the evidence behind anything published from it, and that
    # has to stay re-checkable by someone who does not trust us.
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # When this source next becomes eligible. A sweep only touches what is due,
    # so the work spreads over time instead of hitting every regulator at once.
    # NULL means "never checked" — due immediately.
    next_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Consecutive failed checks, reset to 0 by any success. Without it a
    # permanently blocked host reports "transient — the next sweep will retry"
    # every single day, and a queue that is always wrong is one nobody reads.
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    # "auto" — we fetch it ourselves (Gate 1 is a machine guarantee).
    # "manual" — the host refuses automated clients, so a named person supplied
    # the official text and attested where it came from. Gate 1 then rests on
    # that attestation, NOT on our fetch, and anything published from it is
    # labelled distinctly so the two can never be confused.
    check_mode: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="auto"
    )
    attested_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    attested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Where the person says they got it — the audit trail for a human Gate 1.
    attestation_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class RegulationChange(Base):
    """Something changed at a source. Either auto-published or quarantined.

    Auto-publication is only ever reached by claims that are provable verbatim
    against the retained snapshot. Anything requiring judgement lands here as
    `quarantined` and waits for a person.
    """

    __tablename__ = "regulation_changes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pack_code: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    # source_drift | provision_confirmed | fetch_failed | source_gone
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # quarantined | auto_published | dismissed | actioned
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="quarantined", index=True
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    before_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    after_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    # What was checked, and how it passed or failed — the audit of the audit.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    published_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    # Remediation, shape only (plan_hash, edit kinds, counts) — the full plan
    # derives from customer content and is never stored here. Set when the gate
    # offered a fix for this (non-compliant) decision.
    remediation: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Set on the CURING decision: seq of the flagged decision it remediates.
    remediation_of: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Set on the CURED decision once a linked re-gate came back compliant: seq
    # of the decision that closed it. This is what flips the console chip to
    # REMEDIATED, so silence (an open flag) stays conspicuous.
    remediated_by_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
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


class User(Base):
    """A named human at a customer org — dashboard identity, distinct from
    machine auth (the org API key). Approvals and confirmations should trace to
    a PERSON; this is that person. Login is passwordless (email + one-time
    code), so there is deliberately no password column to protect."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(Text, ForeignKey("orgs.id"), nullable=False, index=True)
    # Globally unique: a login starts from an email alone, so it must name one
    # person at one org. The same human at two orgs uses two addresses.
    email: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    # admin (manage users/policy) | officer (approve, confirm rewrites) |
    # viewer (read-only). Enforced at the route layer.
    role: Mapped[str] = mapped_column(String(16), nullable=False, server_default="officer")
    # Argon2id hash, or NULL until the person sets one (invitation flow: a
    # one-time emailed code proves inbox custody, then they choose a password).
    # Only ever the hash — the password itself exists nowhere on this side.
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Online-guessing brake: failures count up, a threshold locks the account
    # for a cooling-off window, success resets. All server-side and durable.
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    disabled: Mapped[bool] = mapped_column(nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class LoginCode(Base):
    """One-time login code. Only the SHA-256 of the code is stored, it expires
    in minutes, dies on first use, and locks after a few wrong attempts — the
    combination that makes a 6-digit space safe enough for its lifetime."""

    __tablename__ = "login_codes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    code_hash: Mapped[str] = mapped_column(Text, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AuthSession(Base):
    """A browser session. The bearer token is random (256-bit) and stored only
    as its SHA-256, so a database read never yields a usable session. Revocation
    is a column write — logout works even if the cookie survives."""

    __tablename__ = "auth_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    # How this session was earned: "code" (proved inbox custody — may SET a
    # password without knowing the old one, i.e. the reset path) or "password".
    method: Mapped[str] = mapped_column(String(16), nullable=False, server_default="code")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
