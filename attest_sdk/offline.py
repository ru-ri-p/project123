"""Reaching the same verdict locally when Attest is unreachable.

The bundle carries the institution's own policy AND the jurisdiction packs it has
adopted, cached to disk so it survives a restart mid-outage. Both are evaluated
here, by the same rules and in the same order as the server, so an output does
not get one answer when Attest is up and a different one when it is down.

The local verdict is provisional. When the buffered event is grafted in, the
server re-evaluates against the live rulebooks and reports whether the verdict
changed — a stale bundle is possible and is surfaced rather than hidden.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .policy.evaluator import evaluate_local
from .policy.features import extract_features
from .policy.rules import rule_matches
from .policy.tiers import TIER_RANK

_BUNDLE_FILE = "bundle.json"

COMPLIANT = "compliant"
FLAGGED = "flagged"
BLOCKED = "blocked"
UNEVALUATED = "unevaluated"
FLAGGING_TIERS = frozenset({"orange", "red"})


class OfflineBundle:
    """Cached rules for local evaluation."""

    def __init__(self, data: dict[str, Any], state_dir: Path) -> None:
        self.data = data
        self.dir = Path(state_dir)

    # --- persistence -------------------------------------------------------

    @classmethod
    def load(cls, state_dir: Path) -> OfflineBundle:
        path = Path(state_dir) / _BUNDLE_FILE
        if path.exists():
            try:
                return cls(json.loads(path.read_text()), state_dir)
            except (OSError, ValueError):
                pass
        return cls({}, state_dir)

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / _BUNDLE_FILE).write_text(json.dumps(self.data))

    @property
    def is_empty(self) -> bool:
        return not self.data.get("policy_rules") and not self.data.get("packs")

    @property
    def policy_version(self) -> str | None:
        version = self.data.get("policy_version")
        return str(version) if version else None

    # --- evaluation --------------------------------------------------------

    def evaluate(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Local mirror of the server's composition: own policy decides, packs advise."""
        if self.is_empty:
            return {
                "status": UNEVALUATED,
                "allowed": True,
                "tier": None,
                "reasons": ["No cached rules available offline; output recorded only."],
                "findings": [],
                "jurisdictions": [],
                "policy_version": None,
            }

        fail_mode = str(self.data.get("fail_mode", "deny_on_error"))
        own = evaluate_local(
            action=action,
            payload=payload,
            rules_doc=self.data.get("policy_rules") or {},
            fail_mode=fail_mode,
        )
        findings = self._pack_findings(action, payload)

        tier = own.tier
        for finding in findings:
            if TIER_RANK.get(finding["tier"], 0) > TIER_RANK.get(tier, 0):
                tier = finding["tier"]

        # Same rule as the server: only the institution's OWN policy can deny.
        allowed = own.allowed
        if not allowed:
            status = BLOCKED
        elif tier in FLAGGING_TIERS or findings:
            status = FLAGGED
        else:
            status = COMPLIANT

        jurisdictions: list[str] = []
        for finding in findings:
            if finding["jurisdiction"] not in jurisdictions:
                jurisdictions.append(finding["jurisdiction"])

        return {
            "status": status,
            "allowed": allowed,
            "tier": tier,
            "reasons": list(own.reasons),
            "findings": findings,
            "jurisdictions": jurisdictions,
            "policy_version": self.policy_version,
        }

    def _pack_findings(self, action: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
        features = extract_features(action, payload)
        findings: list[dict[str, Any]] = []
        for pack in self.data.get("packs", []):
            for rule in pack.get("rules", []):
                if not isinstance(rule, dict):
                    continue
                tier = rule.get("tier", "yellow")
                if tier not in TIER_RANK:
                    continue
                try:
                    hit = rule_matches(action, payload, features, rule)
                except Exception:  # noqa: BLE001 — advisory must never break the caller
                    continue
                if not hit:
                    continue
                findings.append(
                    {
                        "pack_code": pack.get("code"),
                        "jurisdiction": pack.get("jurisdiction"),
                        "instrument": pack.get("instrument"),
                        "rule_id": rule.get("id"),
                        "tier": tier,
                        "reason": rule.get("reason", ""),
                        "topic": rule.get("topic"),
                        "provision": rule.get("provision"),
                        "guidance": rule.get("guidance"),
                        "source_url": pack.get("source_url"),
                        "verification_status": pack.get("verification_status"),
                        "enforcement": "advisory",
                        "advisory_only": True,
                    }
                )
        findings.sort(key=lambda f: TIER_RANK.get(f["tier"], 0), reverse=True)
        return findings
