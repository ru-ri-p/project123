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


class EventIn(BaseModel):
    trace_id: str
    seq: int = Field(ge=1)
    type: EventType
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
    comment: str | None
    created_at: str
    resolved_at: str | None


class ApprovalResolveIn(BaseModel):
    status: Literal["approved", "denied"]
    approver_id: str = Field(min_length=1)
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


class PolicyOut(BaseModel):
    id: str
    org_id: str
    name: str
    version: str
    active: bool
    schema_version: int | None = None
    engine: str | None = None
    rules: dict[str, Any]
