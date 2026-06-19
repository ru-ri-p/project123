"""Compliance-oriented summary for evidence bundles (audit / design partner)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Event
from app.repositories import approvals as approval_repo
from app.repositories import events as event_repo
from app.repositories import orgs as org_repo
from app.services.replay import replay_trace
from app.services.workflow import workflow_gate


def _count_event_types(events: list[Event]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        counts[event.type] = counts.get(event.type, 0) + 1
    return counts


def build_compliance_summary(
    db: Session,
    *,
    org_id: str,
    trace_id: uuid.UUID,
) -> dict[str, Any]:
    events = event_repo.events_for_trace(db, org_id, trace_id)
    replay = replay_trace(db, org_id=org_id, trace_id=trace_id)
    gate = workflow_gate(db, org_id=org_id, trace_id=trace_id)
    org = org_repo.get_org_by_id(db, org_id)

    policy_decisions: list[dict[str, Any]] = []
    mitigations: list[dict[str, Any]] = []
    erasures: list[dict[str, Any]] = []
    approval_actions: list[dict[str, Any]] = []

    for event in events:
        content = event_repo.read_payload_content(db, org_id, event.payload_hash)
        if event.type == "policy_decision" and isinstance(content, dict):
            policy_decisions.append(
                {
                    "seq": event.seq,
                    "tier": content.get("tier"),
                    "allowed": content.get("allowed"),
                    "rule_id": content.get("rule_id"),
                    "regulatory_refs": content.get("regulatory_refs") or [],
                    "reasons": content.get("reasons") or [],
                }
            )
        elif event.type == "mitigation" and isinstance(content, dict):
            mitigations.append({"seq": event.seq, "mitigation_ids": content.get("mitigation_ids")})
        elif event.type == "erasure" and isinstance(content, dict):
            erasures.append(
                {
                    "seq": event.seq,
                    "target_seq": content.get("target_seq"),
                    "approver_id": content.get("approver_id"),
                }
            )
        elif event.type == "approval_action" and isinstance(content, dict):
            approval_actions.append(
                {
                    "seq": event.seq,
                    "status": content.get("status"),
                    "approver_id": content.get("approver_id"),
                }
            )

    trace_approvals = approval_repo.list_approvals_for_trace(db, org_id, trace_id, limit=50)
    approvals = [
        {
            "approval_id": str(row.id),
            "status": row.status,
            "approver_id": row.approver_id,
            "comment": row.comment,
            "created_at": row.created_at.isoformat(),
        }
        for row in trace_approvals
    ]

    return {
        "org_id": org_id,
        "org_name": org.name if org else org_id,
        "org_region": org.region if org else None,
        "org_fail_mode": org.fail_mode if org else None,
        "event_count": len(events),
        "event_types": _count_event_types(events),
        "all_replay_verified": replay.all_verified,
        "workflow_gate": gate,
        "policy_decisions": policy_decisions,
        "approval_actions": approval_actions,
        "approvals": approvals,
        "mitigations": mitigations,
        "erasures": erasures,
        "pitch_note": (
            "Attest records institutional policy decisions and human oversight; "
            "it does not certify legal compliance or factual correctness of model output."
        ),
    }
