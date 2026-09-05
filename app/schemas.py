"""Pydantic request/response models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

EventType = Literal[
    "model_completion",
    "tool_call",
    "policy_decision",
    "approval_action",
    "mitigation",
    "erasure",
]
# EventType lists the STANDARD event types (some trigger special server behaviour).
# Custom event types are allowed — the `type` field below accepts any non-empty
# string so a customer can record actions in their own vocabulary.


class EventIn(BaseModel):
    trace_id: str
    seq: int = Field(ge=1)
    type: str = Field(
        min_length=1,
        description="Event type; standard values recommended, custom labels allowed.",
    )
    payload: dict[str, Any]
    policy_version: str | None = None


class EventOut(BaseModel):
    hash: str
    signature: str
    seq: int
    prev_hash: str = ""
    event_id: str | None = None


class EventReplayItem(BaseModel):
    seq: int
    type: str
    verified: bool
    hash_ok: bool
    signature_ok: bool
    chain_ok: bool


class TraceReplayOut(BaseModel):
    trace_id: str
    all_verified: bool
    events: list[EventReplayItem]


class EvidenceBundleOut(BaseModel):
    trace_id: str
    exported_at: str
    bundle_schema: str = "1.0"
    manifest: dict[str, Any] | None = None
    compliance_summary: dict[str, Any] | None = None
    public_key_pem: str
    replay_summary: dict[str, Any]
    events: list[dict[str, Any]]
    batches: list[dict[str, Any]]
    batch: dict[str, Any] | None = None
    verification_instructions: str
    verify_script: str


class OrgOut(BaseModel):
    id: str
    name: str
    region: str
    fail_mode: str
    retention_days_payload: int

    model_config = {"from_attributes": True}


class OrgSettingsUpdate(BaseModel):
    region: str | None = None
    fail_mode: str | None = None
    retention_days_payload: int | None = Field(default=None, ge=1, le=3650)


class ErasureIn(BaseModel):
    trace_id: str
    target_seq: int = Field(ge=1, description="Seq of the event whose payload to erase")
    approver_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class ErasureOut(BaseModel):
    trace_id: str
    erasure_seq: int
    target_seq: int
    target_payload_hash: str
    hash: str
    signature: str


class TraceSummary(BaseModel):
    trace_id: str
    created_at: str
    policy_version: str
    event_count: int


class ApprovalOut(BaseModel):
    id: str
    trace_id: str
    event_id: str | None
    status: str
    approver_id: str | None
    # "authenticated" (a signed-in person; approver_id is their verified
    # email) | "asserted" (name supplied over the org machine key) | None
    # (resolved before the distinction existed).
    approver_kind: str | None = None
    comment: str | None
    created_at: str
    resolved_at: str | None


class ApprovalResolveIn(BaseModel):
    status: Literal["approved", "denied"]
    # Required on the machine-key path; IGNORED for a signed-in person, whose
    # verified identity is recorded instead of anything the body claims.
    approver_id: str | None = Field(default=None, min_length=1)
    comment: str | None = None


class ApprovalResolveOut(BaseModel):
    approval_id: str
    trace_id: str
    status: str
    event_seq: int
    event_hash: str
    resume_allowed: bool
    workflow_status: str


class MitigateIn(BaseModel):
    trace_id: str
    seq: int = Field(ge=1)
    mitigation_ids: list[str] = Field(min_length=1)
    source_payload: dict[str, Any]
    policy_decision_seq: int | None = None
    policy_version: str | None = None


class MitigateOut(BaseModel):
    trace_id: str
    seq: int
    hash: str
    mitigation_ids: list[str]
    mitigated_payload: dict[str, Any]


class WorkflowGateOut(BaseModel):
    trace_id: str
    workflow_status: str
    resume_allowed: bool
    approval_id: str | None = None
    approval_status: str | None = None
    approver_id: str | None = None
    policy_tier: str | None = None
    policy_reasons: list[str] = Field(default_factory=list)
    message: str


RiskTier = Literal["green", "yellow", "orange", "red"]


class PrecheckIn(BaseModel):
    trace_id: str
    seq: int = Field(ge=1, description="Monotonic seq for the policy_decision event")
    action: str = Field(min_length=1, description="Proposed action, e.g. model_completion")
    payload: dict[str, Any]
    policy_version: str | None = None


class PrecheckOut(BaseModel):
    trace_id: str
    tier: RiskTier
    decision: Literal["allow", "deny", "flag"]
    allowed: bool
    reasons: list[str]
    policy_version: str
    policy_decision_seq: int
    policy_decision_hash: str
    approval_id: str | None = None
    rule_id: str | None = None
    regulatory_refs: list[str] = Field(default_factory=list)
    risk_score: int = 0
    layer_results: list[dict[str, Any]] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    # Tier from the institution's OWN policy, before advisory jurisdiction
    # findings were layered on. Kept distinct so a customer can see which of the
    # two raised the risk.
    policy_tier: RiskTier | None = None
    jurisdictions: list[str] = Field(default_factory=list)
    regulatory_findings: list[dict[str, Any]] = Field(default_factory=list)


class JurisdictionOut(BaseModel):
    code: str
    name: str
    regulators: list[str]
    summary: str
    official_sources: list[str]


class RegulationPackOut(BaseModel):
    id: str
    code: str
    jurisdiction: str
    name: str
    version: str
    instrument: str
    instrument_notes: str | None = None
    source_url: str | None = None
    effective_date: str | None = None
    verification_status: str
    reviewed_by: str | None = None
    rule_count: int
    enabled: bool | None = None  # set when listed in an org context
    enforcement: str | None = None


class OrgProfileIn(BaseModel):
    """Where the institution is licensed, and what it does."""

    jurisdictions: list[str] = Field(min_length=1)
    sectors: list[str] = Field(min_length=1)
    reason: str | None = Field(
        default=None,
        description="Required only when the change removes a jurisdiction or sector.",
    )
    updated_by: str | None = None


class OrgProfileOut(BaseModel):
    org_id: str
    configured: bool
    jurisdictions: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)
    updated_at: str | None = None
    updated_by: str | None = None
    mandatory_pack_codes: list[str] = Field(default_factory=list)
    pending_changes: int = 0


class ProfileUpdateOut(BaseModel):
    applied: bool
    pending_approval: bool
    removed: list[str] = Field(default_factory=list)
    message: str
    request_id: str | None = None
    profile: OrgProfileOut


class ProfileChangeRequestOut(BaseModel):
    id: str
    org_id: str
    requested_by: str
    reason: str
    removed: list[str] = Field(default_factory=list)
    proposed_jurisdictions: list[str] = Field(default_factory=list)
    proposed_sectors: list[str] = Field(default_factory=list)
    status: str
    created_at: str


class RegulationChangeOut(BaseModel):
    id: str
    pack_code: str
    url: str
    change_type: str
    status: str
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    published_version: str | None = None
    created_at: str


class RegulationSourceOut(BaseModel):
    pack_code: str
    url: str
    content_hash: str | None = None
    last_checked_at: str | None = None
    next_check_at: str | None = None
    # Set when no pack cites this URL any more. Kept and shown, never fetched.
    retired_at: str | None = None
    last_status: str | None = None
    last_error: str | None = None
    consecutive_failures: int = 0
    # "auto" = we fetch it. "manual" = a named person supplies the text, so
    # Gate 1 rests on their attestation and not on a fetch by Attest.
    check_mode: str = "auto"
    attested_by: str | None = None
    attested_at: str | None = None
    attestation_note: str | None = None


class WatchRunOut(BaseModel):
    sources_checked: int
    sources_total: int = 0
    sources_deferred: int = 0
    next_due_at: str | None = None
    changes: int
    auto_published: int
    quarantined: int
    checked_at: str


class PackSubscriptionIn(BaseModel):
    pack_code: str = Field(min_length=1)
    enabled: bool = True
    enforcement: Literal["advisory"] = "advisory"  # blocking reserved for post-review


class DeviceRegisterIn(BaseModel):
    device_id: str = Field(min_length=8, max_length=128)
    public_pem: str = Field(min_length=1)
    label: str | None = None


class DeviceRegisterOut(BaseModel):
    device_id: str
    registered: bool


class OfflineBundleOut(BaseModel):
    """Rules the SDK evaluates against while Attest is unreachable."""

    policy_version: str | None = None
    policy_rules: dict[str, Any] = Field(default_factory=dict)
    packs: list[dict[str, Any]] = Field(default_factory=list)
    fail_mode: str = "deny_on_error"


class ReplayItemIn(BaseModel):
    """One event buffered during an outage, signed by the SDK's device key."""

    action: str = Field(min_length=1)
    output: dict[str, Any]
    occurred_at: str
    local_seq: int
    prev_local: str | None = None
    payload_hash: str
    client_signature: str
    trace_id: str | None = None
    local_status: str | None = None


class ReplayIn(BaseModel):
    device_id: str = Field(min_length=8)
    items: list[ReplayItemIn] = Field(min_length=1, max_length=500)


class ReplayOut(BaseModel):
    accepted: int
    results: list[dict[str, Any]] = Field(default_factory=list)


GateStatus = Literal["compliant", "flagged", "blocked", "unevaluated"]


class GateIn(BaseModel):
    """One AI output to check and log."""

    action: str = Field(
        min_length=1,
        description="What the AI did, in your own vocabulary (e.g. model_completion).",
    )
    output: dict[str, Any] = Field(description="The output and any context to evaluate.")
    trace_id: str | None = Field(
        default=None,
        description="Omit for a standalone record; pass one to group several steps.",
    )
    policy_version: str | None = None
    remediates: int | None = Field(
        default=None,
        ge=1,
        description=(
            "Seq of a flagged/blocked decision in the SAME trace that this "
            "output is the fix for. Requires trace_id. If this output comes "
            "back compliant, the flagged decision is marked remediated — the "
            "chain then reads flagged, fix, proven fixed."
        ),
    )


class GateOut(BaseModel):
    trace_id: str
    status: GateStatus
    allowed: bool
    tier: str | None = None
    reasons: list[str] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    jurisdictions: list[str] = Field(default_factory=list)
    policy_version: str | None = None
    decision_seq: int | None = None
    output_seq: int
    output_hash: str
    signature: str
    approval_id: str | None = None
    # Deterministic remediation plan for a non-compliant verdict: revised
    # output, per-edit citations, honest unresolved list. Returned here only —
    # the signed chain carries its hash, never its content.
    suggested_fix: dict[str, Any] | None = None
    remediation_of: int | None = None


class PolicyDecisionOut(BaseModel):
    trace_id: str
    seq: int
    action: str
    tier: str
    policy_tier: str
    allowed: bool
    policy_version: str | None = None
    jurisdictions: list[str] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    event_hash: str
    created_at: str
    status: str | None = None
    output_seq: int | None = None
    output_hash: str | None = None
    # Shape of the fix offered at gate time (plan_hash, edit kinds, counts) —
    # the content itself was returned to the caller only, never stored.
    remediation: dict[str, Any] | None = None
    remediation_of: int | None = None
    remediated_by_seq: int | None = None


class ComplianceSummaryOut(BaseModel):
    """Headline numbers for the compliance screens."""

    decisions_total: int
    flagged_total: int
    by_tier: dict[str, int]
    by_jurisdiction: dict[str, int]
    # Jurisdictions the profile says apply. Distinct from by_jurisdiction, which
    # counts findings actually raised.
    applied_jurisdictions: list[str] = Field(default_factory=list)
    unverified_packs: int
    active_policy_version: str | None = None


class InternalPolicyIn(BaseModel):
    """The institution authors its own policy; Attest does not supply it."""

    name: str = Field(min_length=1)
    version: str = Field(min_length=1, max_length=32)
    rules: dict[str, Any]
    activate: bool = True


class ConfidentialityIn(BaseModel):
    wrapping_public_pem: str = Field(min_length=1)


class SigningKeyOut(BaseModel):
    key_id: str
    public_pem: str


class AccessRequestCreateIn(BaseModel):
    org_id: str
    payload_hashes: list[str] = Field(min_length=1)
    reason: str = Field(min_length=1)
    required_approvals: int = Field(default=1, ge=1)
    ttl_seconds: int = Field(default=3600, ge=1)


class AccessRequestOut(BaseModel):
    request_id: str
    org_id: str
    status: str
    reason: str
    required_approvals: int
    approvals: int = 0
    grantee_public_pem: str
    expires_at: str
    requested_by: str | None = None
    trace_id: str | None = None  # the request's consent-trail trace


class AccessScopeItem(BaseModel):
    payload_hash: str
    wrapped_key_for_org: str | None = None


class AccessRequestDetailOut(AccessRequestOut):
    scope: list[AccessScopeItem]


class AccessApproveIn(BaseModel):
    approver_id: str = Field(min_length=1)
    released_keys: dict[str, str] = Field(default_factory=dict)


class AccessResolveIn(BaseModel):
    status: Literal["denied", "revoked"]


class GrantRecordOut(BaseModel):
    payload_hash: str
    content: dict[str, Any]


class AdminOrgOut(BaseModel):
    id: str
    name: str
    region: str
    confidentiality_mode: str
    fail_mode: str
    created_at: str
    requires_profile: bool = False
    # What the customer declared, so the gate is never switched on blind.
    profile_configured: bool = False
    jurisdictions: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)


class AdminOrgCreateIn(BaseModel):
    org_id: str = Field(min_length=1, pattern=r"^[a-zA-Z0-9_\-]+$")
    name: str = Field(min_length=1)
    region: str = "uae"
    api_key: str | None = Field(
        default=None,
        min_length=12,
        description="Optional fixed key (dev/pilot); omit for a random one.",
    )


class AdminOrgKeyOut(BaseModel):
    org_id: str
    api_key: str  # shown once; only the hash is stored


class AdminScopeItem(BaseModel):
    payload_hash: str
    released: bool


class AdminRequestOut(AccessRequestOut):
    requested_by: str
    trace_id: str | None = None


class AdminRequestDetailOut(AdminRequestOut):
    scope: list[AdminScopeItem]


class AdminTraceEventOut(BaseModel):
    seq: int
    type: str
    payload_hash: str
    hash: str
    prev_hash: str | None
    created_at: str


class DailyCount(BaseModel):
    day: str  # YYYY-MM-DD
    count: int


class AdminOrgActivity(BaseModel):
    id: str
    name: str
    confidentiality_mode: str
    events_today: int
    daily: list[DailyCount]


class AdminStatsOut(BaseModel):
    signing_backend: str
    anchored_batches: int
    pending_batches: int
    last_anchor_at: str | None
    unbatched_events: int
    events_24h: int
    pending_requests: int
    orgs: list[AdminOrgActivity]


class OrgOverviewOut(BaseModel):
    org_id: str
    name: str
    confidentiality_mode: str
    wrapping_key_fingerprint: str | None
    signing_key_id: str | None
    total_events: int
    last_event_at: str | None
    pending_requests: int
    daily: list[DailyCount]
    # Setup state the console needs on landing: without a policy nothing can be
    # prechecked, so the dashboard says so rather than letting them find out later.
    active_policy_version: str | None = None
    jurisdictions_adopted: list[str] = Field(default_factory=list)
    # True only for orgs created after the onboarding gate shipped. Grandfathered
    # orgs are prompted, never blocked — and must not be trapped in the wizard.
    requires_profile: bool = False


class TraceEventMetaOut(BaseModel):
    seq: int
    type: str
    payload_hash: str
    hash: str
    created_at: str


class PolicyOut(BaseModel):
    id: str
    org_id: str
    name: str
    version: str
    active: bool
    schema_version: int | None = None
    engine: str | None = None
    rules: dict[str, Any]


class SupplyTextIn(BaseModel):
    """Official text obtained by hand, for a source whose host refuses us.

    `attested_by` is required and is the whole point: Gate 1 becomes a named
    person's word rather than a fetch by Attest, so there must be a name on it.
    """

    pack_code: str = Field(min_length=1)
    url: str = Field(min_length=1)
    text: str = Field(min_length=1)
    attested_by: str = Field(min_length=1, max_length=200)
    note: str | None = Field(
        default=None,
        max_length=2000,
        description="Where it came from — e.g. 'downloaded the PDF from difc.com'.",
    )
    auto_publish: bool = True


# --- human auth (dashboard logins) -----------------------------------------


class AuthRequestCodeIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class AuthVerifyIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class AuthUserOut(BaseModel):
    email: str
    display_name: str
    role: str
    org_id: str


class AuthSessionOut(BaseModel):
    user: AuthUserOut
    # Also set as an HttpOnly cookie; returned in the body for API clients
    # and tests. Treat it like a password: never log it.
    token: str
    expires_at: str


class AdminCreateUserIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=200)
    role: str = Field(default="officer", pattern=r"^(admin|officer|viewer)$")


class AuthLoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    # No minimum here: login must accept whatever was set; policy applies
    # only when SETTING a password.
    password: str = Field(min_length=1, max_length=128)


class AuthSetPasswordIn(BaseModel):
    new_password: str = Field(min_length=12, max_length=128)
    # Required when the session was earned by password; a code-earned session
    # (invitation/reset — inbox custody already proven) sets one without it.
    current_password: str | None = Field(default=None, max_length=128)


# --- work queue -------------------------------------------------------------


class WorkQueueApprovalItem(BaseModel):
    approval_id: str
    trace_id: str
    created_at: str
    # The decision this approval gates, so the officer sees what they are
    # deciding. None only for approvals whose trace predates decision indexing.
    action: str | None = None
    tier: str | None = None
    decision_status: str | None = None


class WorkQueueFlagItem(BaseModel):
    trace_id: str
    seq: int
    action: str
    tier: str
    status: str | None = None
    created_at: str
    remediation: dict[str, Any] | None = None
    findings_count: int = 0


class WorkQueueCounts(BaseModel):
    approvals: int
    open_flags: int
    rewrite_confirmations: int
    total: int


class WorkQueueOut(BaseModel):
    pending_approvals: list[WorkQueueApprovalItem]
    open_flags: list[WorkQueueFlagItem]
    rewrite_confirmations: list[WorkQueueFlagItem]
    counts: WorkQueueCounts


class PolicyPreviewIn(BaseModel):
    action: str = Field(default="model_completion", min_length=1)
    output: dict[str, Any]
    # Test against a specific stored version; omitted = the active policy.
    policy_version: str | None = None
    # A candidate ruleset to test WITHOUT activating it. Omitted = use the
    # stored policy's rules. Same shape as a policy's `rules`.
    candidate_rules: dict[str, Any] | None = None


class PolicyPreviewOut(BaseModel):
    status: str
    error: str | None = None
    tier: str | None = None
    policy_tier: str | None = None
    decision: str | None = None
    allowed: bool | None = None
    reasons: list[str] = Field(default_factory=list)
    rule_id: str | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    jurisdictions: list[str] = Field(default_factory=list)
    remediation_preview: dict[str, Any] | None = None
    recorded: bool = False
