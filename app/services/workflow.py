"""Workflow gate — whether a trace may proceed after precheck and human approval."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.repositories import approvals as approval_repo
from app.repositories import events as event_repo
from app.services.trace_access import ensure_trace_access

WorkflowStatus = Literal[
    "proceed",
    "blocked_pending_approval",
    "blocked_denied",
    "blocked_not_allowed",
]


def workflow_gate(
    db: Session,
    *,
    org_id: str,
    trace_id: uuid.UUID,
) -> dict[str, Any]:
    ensure_trace_access(db, org_id, trace_id)

    trace_approvals = approval_repo.list_approvals_for_trace(db, org_id, trace_id, limit=20)
    pending = next((a for a in trace_approvals if a.status == "pending"), None)
    if pending is not None:
        policy = _policy_summary_from_events(db, org_id, trace_id)
        return {
            "trace_id": str(trace_id),
            "workflow_status": "blocked_pending_approval",
            "resume_allowed": False,
            "approval_id": str(pending.id),
            "approval_status": "pending",
            "policy_tier": policy.get("tier"),
            "policy_reasons": policy.get("reasons", []),
            "message": "Human approval required before this workflow may continue.",
        }

    latest_resolved = next(
        (a for a in trace_approvals if a.status in ("approved", "denied")),
        None,
    )
    if latest_resolved is not None:
        if latest_resolved.status == "denied":
            return {
                "trace_id": str(trace_id),
                "workflow_status": "blocked_denied",
                "resume_allowed": False,
                "approval_id": str(latest_resolved.id),
                "approval_status": "denied",
                "approver_id": latest_resolved.approver_id,
                "message": "Workflow aborted — approval was denied.",
            }
        return {
            "trace_id": str(trace_id),
            "workflow_status": "proceed",
            "resume_allowed": True,
            "approval_id": str(latest_resolved.id),
            "approval_status": "approved",
            "approver_id": latest_resolved.approver_id,
            "message": "Human approval granted — workflow may continue.",
        }

    policy = _policy_summary_from_events(db, org_id, trace_id)
    if policy.get("tier") == "red" and policy.get("allowed") is False:
        return {
            "trace_id": str(trace_id),
            "workflow_status": "blocked_not_allowed",
            "resume_allowed": False,
            "approval_id": None,
            "approval_status": None,
            "policy_tier": "red",
            "policy_reasons": policy.get("reasons", []),
            "message": "RED policy decision blocks this action until approved.",
        }

    return {
        "trace_id": str(trace_id),
        "workflow_status": "proceed",
        "resume_allowed": True,
        "approval_id": None,
        "approval_status": None,
        "policy_tier": policy.get("tier"),
        "policy_reasons": policy.get("reasons", []),
        "message": "No approval gate — workflow may continue.",
    }


def resume_allowed_for_approval_status(status: str) -> bool:
    return status == "approved"


def _policy_summary_from_events(
    db: Session,
    org_id: str,
    trace_id: uuid.UUID,
) -> dict[str, Any]:
    events = event_repo.events_for_trace(db, org_id, trace_id)
    for event in reversed(events):
        if event.type != "policy_decision":
            continue
        content = _read_policy_payload(db, org_id, event.payload_hash)
        if content is not None:
            return {
                "tier": content.get("tier"),
                "allowed": content.get("allowed"),
                "reasons": content.get("reasons") or [],
                "seq": event.seq,
            }
    return {}


def _read_policy_payload(db: Session, org_id: str, payload_hash: str) -> dict[str, Any] | None:
    from app.services.payload_store import read_payload_content

    content = read_payload_content(db, org_id, payload_hash)
    if isinstance(content, dict):
        return content
    return None
