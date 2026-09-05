"""Policy dry-run — judge a sample output against a policy, recording NOTHING.

Lets an officer answer "what would this rule do?" before activating it, and
"why did that get flagged?" after the fact — using the EXACT deterministic
pipeline the gate uses (features -> customer policy -> packs -> derive_status
-> remediation plan), so a preview never disagrees with the real verdict.

Nothing here writes an event, a summary row, or a trace. It is safe to call
as often as an officer clicks, and it never mutates the active policy: a
candidate ruleset can be passed in to test an edit before it goes live.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Org
from app.domain.policy_contract import PolicyInput
from app.services import remediation
from app.services.policy.evaluator import evaluate_policy_input
from app.services.policy.features import extract_features
from app.services.policy.packs import combined_tier, evaluate_packs, jurisdictions_touched
from app.services.policy.rules import PolicyEngineError
from app.services.precheck import tier_allows_action
from app.services.verdict import STATUS_BLOCKED, STATUS_FLAGGED, derive_status


def preview(
    db: Session,
    *,
    org: Org,
    action: str,
    payload: dict[str, Any],
    policy_version: str,
    rules: dict[str, Any],
) -> dict[str, Any]:
    """Full verdict for (action, payload) under `rules`, nothing recorded.

    `rules` is the ruleset to test — the active policy's, or a candidate edit
    the officer has not yet activated. Errors are reported, never raised: a
    malformed candidate returns status "error" with the reason, so the console
    can show it instead of a stack trace.
    """
    features = extract_features(action, payload)
    try:
        output = evaluate_policy_input(
            PolicyInput(
                org_id=org.id, action=action, payload=payload,
                fail_mode=org.fail_mode, policy_version=policy_version,
                features=features,
            ),
            rules,
        )
    except PolicyEngineError as exc:
        return {
            "status": "error",
            "error": str(exc),
            "tier": None, "decision": None, "allowed": None,
            "reasons": [], "findings": [], "jurisdictions": [],
            "remediation_preview": None, "recorded": False,
        }

    findings = evaluate_packs(
        db, org_id=org.id, action=action, payload=payload, features=features
    )
    finding_dicts = [f.to_dict() for f in findings]
    effective_tier = combined_tier(output.tier, findings)
    allowed = tier_allows_action(
        output.tier, fail_mode=org.fail_mode, allowed=output.allowed
    )
    status = derive_status(allowed=allowed, tier=effective_tier, findings=finding_dicts)

    remediation_preview: dict[str, Any] | None = None
    if status in (STATUS_FLAGGED, STATUS_BLOCKED):
        # SHAPE only — the console shows what the fix would touch, not content.
        plan = remediation.plan(
            payload=payload, features=features, findings=finding_dicts,
            policy_reasons=list(output.reasons), blocked=not allowed,
        )
        remediation_preview = remediation.chain_summary(plan)

    return {
        "status": status,
        "error": None,
        "tier": effective_tier,
        "policy_tier": output.tier,
        "decision": output.decision,
        "allowed": allowed,
        "reasons": list(output.reasons),
        "rule_id": output.rule_id,
        "findings": finding_dicts,
        "jurisdictions": jurisdictions_touched(findings),
        "remediation_preview": remediation_preview,
        "recorded": False,
    }
