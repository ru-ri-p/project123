"""Evaluate an action against the institution's policy AND its jurisdictions.

Composition model
=================
An action is judged by several rulebooks at once:

  * the institution's OWN policy (authored by the institution) — decisive; it
    can allow, flag, or deny; and
  * every enabled regulation pack for the jurisdictions the institution sits in
    — ADVISORY in the MVP: a pack can raise the risk tier and attach a cited
    finding, but cannot by itself deny an action.

The strictest tier wins. Advisory is the deliberate MVP posture: pack content
has not been through legal review, and a wrong rule that blocks would stop a
customer's business. Findings are loud; the brake stays with the institution.

Every finding carries its citation and the pack's verification status, so the
customer (and later a regulator) can see not just "this was flagged" but "under
which instrument, from which source, and how well checked".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy.orm import Session

from app.db.models import OrgRegulationPack, RegulationPack
from app.domain.policy_contract import FeatureVector
from app.services.policy.rules import rule_matches
from app.services.policy.tiers import TIER_RANK, TIERS, RiskTier, max_tier


@dataclass(frozen=True)
class PackFinding:
    """One cited observation from one regulation pack."""

    pack_code: str
    jurisdiction: str
    instrument: str
    rule_id: str
    tier: str
    reason: str
    topic: str | None
    provision: str | None
    guidance: str | None
    source_url: str | None
    verification_status: str
    enforcement: str
    # Which structural signal the rule matched on (has_pii, classifier, action,
    # cross_border, prohibited_phrases, ...). Lets the remediation planner tie
    # each suggested edit to the findings it cures, without re-deriving rule
    # internals downstream.
    matched_on: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_code": self.pack_code,
            "jurisdiction": self.jurisdiction,
            "instrument": self.instrument,
            "rule_id": self.rule_id,
            "tier": self.tier,
            "reason": self.reason,
            "topic": self.topic,
            "provision": self.provision,
            "guidance": self.guidance,
            "source_url": self.source_url,
            "verification_status": self.verification_status,
            "enforcement": self.enforcement,
            "matched_on": self.matched_on,
            # Spelled out on every finding so it cannot be quoted out of context.
            "advisory_only": self.enforcement != "blocking",
        }


def active_packs_for_org(db: Session, org_id: str) -> list[tuple[RegulationPack, str]]:
    """Enabled (pack, enforcement) pairs for an org."""
    rows = (
        db.query(RegulationPack, OrgRegulationPack.enforcement)
        .join(OrgRegulationPack, OrgRegulationPack.pack_id == RegulationPack.id)
        .filter(OrgRegulationPack.org_id == org_id, OrgRegulationPack.enabled.is_(True))
        .all()
    )
    return [(pack, enforcement) for pack, enforcement in rows]


def _matched_on(match: dict[str, Any]) -> str | None:
    """Name the structural signal a rule's match keys point at."""
    if match.get("has_pii") is True:
        return "has_pii"
    if "action" in match:
        return "action"
    feature = match.get("feature")
    if isinstance(feature, str):
        return feature  # classifier, cross_border, prohibited_phrases, ...
    if "payload_key" in match:
        return "payload_key"
    return None


def evaluate_packs(
    db: Session,
    *,
    org_id: str,
    action: str,
    payload: dict[str, Any],
    features: FeatureVector,
) -> list[PackFinding]:
    """Run every applicable pack. Returns findings ordered strictest-first.

    A malformed rule is skipped rather than raising: a broken advisory rule must
    never take down the customer's action path. The institution's own policy is
    evaluated elsewhere and keeps its strict error handling.
    """
    findings: list[PackFinding] = []
    for pack, enforcement in active_packs_for_org(db, org_id):
        doc = pack.rules if isinstance(pack.rules, dict) else {}
        raw_rules = doc.get("rules")
        if not isinstance(raw_rules, list):
            continue
        for rule in raw_rules:
            if not isinstance(rule, dict):
                continue
            tier = rule.get("tier", "yellow")
            if tier not in TIERS:
                continue
            try:
                hit = rule_matches(action, payload, features, rule)
            except Exception:  # noqa: BLE001 — advisory path must not break the caller
                continue
            if not hit:
                continue
            raw_match = rule.get("match")
            match: dict[str, Any] = raw_match if isinstance(raw_match, dict) else {}
            findings.append(
                PackFinding(
                    pack_code=pack.code,
                    jurisdiction=pack.jurisdiction,
                    instrument=pack.instrument,
                    rule_id=str(rule.get("id", "unnamed")),
                    tier=tier,
                    reason=str(rule.get("reason", "")),
                    topic=rule.get("topic"),
                    provision=rule.get("provision"),
                    guidance=rule.get("guidance"),
                    source_url=pack.source_url,
                    verification_status=pack.verification_status,
                    enforcement=enforcement,
                    matched_on=_matched_on(match),
                )
            )

    findings.sort(key=lambda f: TIER_RANK.get(f.tier, 0), reverse=True)
    return findings


def combined_tier(base_tier: RiskTier, findings: list[PackFinding]) -> RiskTier:
    """Strictest wins: advisory findings may raise the tier, never lower it."""
    tier: RiskTier = base_tier
    for f in findings:
        if f.tier in TIER_RANK:
            tier = max_tier(tier, cast(RiskTier, f.tier))
    return tier


def jurisdictions_touched(findings: list[PackFinding]) -> list[str]:
    seen: list[str] = []
    for f in findings:
        if f.jurisdiction not in seen:
            seen.append(f.jurisdiction)
    return seen
