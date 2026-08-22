"""Precheck orchestration — policy tiers, signed policy_decision, optional approval."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Org, PolicyDecisionSummary
from app.domain.policy_contract import PolicyInput
from app.repositories import approvals as approval_repo
from app.repositories import events as event_repo
from app.repositories import policies as policy_repo
from app.services import remediation
from app.services.events import EventSequenceError, record_event
from app.services.policy.evaluator import evaluate_policy_input
from app.services.policy.features import extract_features
from app.services.policy.packs import combined_tier, evaluate_packs, jurisdictions_touched
from app.services.policy.rules import PolicyEngineError
from app.services.policy.tiers import RiskTier
from app.services.verdict import STATUS_BLOCKED, STATUS_FLAGGED, derive_status

TIERS_REQUIRING_APPROVAL: frozenset[str] = frozenset({"orange", "red"})


class NoActivePolicyError(LookupError):
    """No active policy configured for this org."""


def tier_allows_action(tier: RiskTier, *, fail_mode: str, allowed: bool) -> bool:
    """Trust the evaluator's verdict; do not re-derive blocking from the tier.

    The evaluator already encodes every legitimate block: a customer rule that
    denies, and the red+flag human-approval gate (which consults fail_mode).
    This function used to ALSO block on tier==red even when the evaluator said
    allowed — so an advisory layer or pack that merely raised the tier could
    block an output the customer's own policy permitted. Caught live: a
    cross-border output was blocked for an org whose policy said nothing about
    cross-border. Only the customer's own policy may block.
    """
    return bool(allowed)


def run_precheck(
    db: Session,
    *,
    org: Org,
    trace_id: uuid.UUID,
    seq: int,
    action: str,
    remediation_of: int | None = None,
    payload: dict[str, Any],
    policy_version: str | None,
) -> dict[str, Any]:
    if policy_version:
        policy = policy_repo.get_policy_by_version(db, org.id, policy_version)
    else:
        policy = policy_repo.get_active_policy(db, org.id)

    if policy is None:
        raise NoActivePolicyError("no active policy for org")

    event_repo.get_or_create_trace(db, org.id, trace_id, policy.version)
    features = extract_features(action, payload)

    try:
        policy_input = PolicyInput(
            org_id=org.id,
            action=action,
            payload=payload,
            fail_mode=org.fail_mode,
            policy_version=policy.version,
            features=features,
        )
        output = evaluate_policy_input(policy_input, policy.rules)
    except PolicyEngineError as exc:
        if org.fail_mode == "deny_on_error":
            return _fail_closed_response(
                db,
                org=org,
                trace_id=trace_id,
                seq=seq,
                action=action,
                policy_version=policy.version,
                detail=str(exc),
            )
        from app.domain.policy_contract import PolicyOutput

        output = PolicyOutput(
            tier="yellow",
            decision="flag",
            allowed=True,
            reasons=(f"policy evaluation error (allow_with_flag): {exc}",),
            rule_id=None,
            regulatory_refs=(),
            risk_score=35,
            layer_results=(),
        )

    # Jurisdiction layer: the institution's own policy decided above; regulation
    # packs now add cited findings on top. Advisory in the MVP — a finding can
    # raise the risk tier (strictest wins) but never flips an allow into a deny.
    findings = evaluate_packs(
        db, org_id=org.id, action=action, payload=payload, features=features
    )
    effective_tier = combined_tier(output.tier, findings)

    # The allow/deny decision is computed from the INSTITUTION'S OWN policy tier
    # only. Advisory findings raise the reported tier (and can route the action
    # to a human approver) but must never turn an allow into a deny: pack content
    # has not had legal review, and a drafting error must not stop the customer's
    # business. Blocking on packs is a deliberate later decision, per pack.
    allowed = tier_allows_action(output.tier, fail_mode=org.fail_mode, allowed=output.allowed)

    # Remediation: for any non-compliant verdict (orange included — that is
    # where the most remediable finding, personal data, lives), build a
    # deterministic plan. The SHAPE of the plan is sealed into the signed
    # decision event; the full plan — which derives from customer content — is
    # returned to the caller only and never persisted outside their
    # content-encryption rules.
    finding_dicts = [f.to_dict() for f in findings]
    status = derive_status(allowed=allowed, tier=effective_tier, findings=finding_dicts)
    remediation_plan: dict[str, Any] | None = None
    if status in (STATUS_FLAGGED, STATUS_BLOCKED):
        remediation_plan = remediation.plan(
            payload=payload,
            features=features,
            findings=finding_dicts,
            policy_reasons=list(output.reasons),
            blocked=not allowed,
        )

    decision_payload: dict[str, Any] = {
        "action": action,
        "tier": effective_tier,
        "policy_tier": output.tier,
        "decision": output.decision,
        "allowed": allowed,
        "reasons": list(output.reasons),
        "policy_version": policy.version,
        "fail_mode": org.fail_mode,
        "rule_id": output.rule_id,
        "regulatory_refs": list(output.regulatory_refs),
        "risk_score": output.risk_score,
        "features": features.to_dict(),
        "layer_results": [layer.to_dict() for layer in output.layer_results],
        "mitigations": list(output.mitigations),
        # Sealed into the signed policy_decision event: which jurisdictional
        # rulebook was applied, citing what, and how well verified. This is what
        # makes the rulebook itself auditable after the fact.
        "jurisdictions": jurisdictions_touched(findings),
        "regulatory_findings": finding_dicts,
    }
    if remediation_plan is not None:
        decision_payload["remediation"] = remediation.chain_summary(remediation_plan)
    if remediation_of is not None:
        # This decision judges a REVISED output, offered as the cure for an
        # earlier flagged decision in the same trace. Sealed in the event so the
        # flagged → fixed link is part of the tamper-evident story, not an
        # annotation someone could quietly drop.
        decision_payload["remediation_of"] = remediation_of

    event_result = record_event(
        db,
        org_id=org.id,
        trace_id=trace_id,
        seq=seq,
        event_type="policy_decision",
        payload=decision_payload,
        policy_version=policy.version,
    )

    # Index the decision for the compliance dashboards. Metadata only — the
    # signed event above stays authoritative, and for a customer-key org its
    # payload is unreadable to us, so without this index neither side could see
    # what was flagged.
    db.add(
        PolicyDecisionSummary(
            org_id=org.id,
            trace_id=trace_id,
            seq=event_result.seq,
            event_hash=event_result.hash,
            action=action,
            tier=effective_tier,
            policy_tier=output.tier,
            allowed=allowed,
            policy_version=policy.version,
            findings=finding_dicts,
            jurisdictions=jurisdictions_touched(findings),
            remediation=(
                remediation.chain_summary(remediation_plan)
                if remediation_plan is not None
                else None
            ),
            remediation_of=remediation_of,
        )
    )
    db.flush()

    approval_id: str | None = None
    policy_event_id: uuid.UUID | None = None
    if event_result.event_id:
        policy_event_id = uuid.UUID(event_result.event_id)

    if effective_tier in TIERS_REQUIRING_APPROVAL:
        approval = approval_repo.create_approval(
            db,
            org_id=org.id,
            trace_id=trace_id,
            event_id=policy_event_id,
        )
        approval_id = str(approval.id)

    return {
        "trace_id": str(trace_id),
        "tier": effective_tier,
        "policy_tier": output.tier,
        "decision": output.decision,
        "allowed": allowed,
        "reasons": list(output.reasons),
        "policy_version": policy.version,
        "policy_decision_seq": event_result.seq,
        "policy_decision_hash": event_result.hash,
        "approval_id": approval_id,
        "rule_id": output.rule_id,
        "regulatory_refs": list(output.regulatory_refs),
        "risk_score": output.risk_score,
        "layer_results": [layer.to_dict() for layer in output.layer_results],
        "mitigations": list(output.mitigations),
        "jurisdictions": jurisdictions_touched(findings),
        "regulatory_findings": finding_dicts,
        "remediation_plan": remediation_plan,
        "remediation_of": remediation_of,
    }


def _fail_closed_response(
    db: Session,
    *,
    org: Org,
    trace_id: uuid.UUID,
    seq: int,
    action: str,
    policy_version: str,
    detail: str,
) -> dict[str, Any]:
    event_repo.get_or_create_trace(db, org.id, trace_id, policy_version)
    decision_payload = {
        "action": action,
        "tier": "red",
        "decision": "deny",
        "allowed": False,
        "reasons": [detail],
        "policy_version": policy_version,
        "fail_mode": org.fail_mode,
        "engine_error": True,
        "risk_score": 90,
    }
    try:
        event_result = record_event(
            db,
            org_id=org.id,
            trace_id=trace_id,
            seq=seq,
            event_type="policy_decision",
            payload=decision_payload,
            policy_version=policy_version,
        )
    except EventSequenceError:
        raise

    policy_event_id = uuid.UUID(event_result.event_id) if event_result.event_id else None
    approval = approval_repo.create_approval(
        db, org_id=org.id, trace_id=trace_id, event_id=policy_event_id
    )
    return {
        "trace_id": str(trace_id),
        "tier": "red",
        "decision": "deny",
        "allowed": False,
        "reasons": [detail],
        "policy_version": policy_version,
        "policy_decision_seq": event_result.seq,
        "policy_decision_hash": event_result.hash,
        "approval_id": str(approval.id),
        "rule_id": None,
        "regulatory_refs": [],
        "risk_score": 90,
        "layer_results": [],
        "mitigations": [],
    }
