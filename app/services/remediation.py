"""What a flagged output can become — deterministic suggestions, tied to findings.

THE PRODUCT CLAIM THIS SERVES
=============================
"We flagged it, here is the fix, here is proof the fix shipped, and nobody can
doctor that history." The planner supplies the middle of that sentence. The
proof comes from the gate recording the plan's hash in the signed decision event
and the customer re-gating the revised output with a `remediates` reference —
the chain then reads flagged → fix suggested → revised output compliant.

RULES THIS MODULE LIVES BY
==========================
1. SUGGEST, NEVER APPLY. The revised output goes back to the caller; Attest
   never changes the customer's behaviour. Applying it is their code's visible,
   deliberate act.
2. DETERMINISTIC ONLY. Every edit is producible by a regex or a fixed
   substitution the customer can read. No model in this path; if a semantic
   planner is ever added it stands behind this same interface and is labelled.
3. NO INVENTION. The planner may remove or substitute exactly what a detector
   found — nothing else. A test asserts the revised text differs from the
   original only where an edit says it does.
4. HONEST ABOUT ITS LIMITS. What it cannot mechanically cure — a discriminatory
   classification, a denied high-risk action — lands in `unresolved` with a
   note, not in a pretend fix. And it re-checks its own work: if redaction
   leaves any PII behind, that goes to `unresolved` too, rather than being
   presented as cured.
5. NO PII IN THE PLAN'S METADATA. Edits name the *label* found (email,
   phone_ae), never the matched text: the plan travels in API responses and its
   hash into the chain, and neither may leak what the fix removes.

The planner runs on flagged AND blocked verdicts — orange included, which is
where the most remediable finding (personal data) lives. It costs microseconds,
so there is no tier gating; that lever is reserved for a future semantic
planner, which would cost real money per call.
"""

from __future__ import annotations

from typing import Any

from app.crypto.canonical import sha256_hex
from app.domain.policy_contract import FeatureVector
from app.services.mitigation import apply_mitigation_ids
from app.services.policy.pii_layer import detect_pii_labels

# Finding signals the planner can mechanically cure with a text edit.
_TEXTUAL_SIGNALS = frozenset({"has_pii", "prohibited_phrases"})
# Signals cured by supplying evidence rather than editing text.
_REQUIREMENT_SIGNALS = frozenset({"cross_border"})


def plan(
    *,
    payload: dict[str, Any],
    features: FeatureVector,
    findings: list[dict[str, Any]],
    policy_reasons: list[str] | None = None,
    blocked: bool = False,
) -> dict[str, Any] | None:
    """Build a remediation plan for one non-compliant output.

    Returns None when there is nothing to say — which must never happen for a
    flagged verdict in practice, because every flag has a cause; if it does,
    the caller records no plan rather than an empty one.
    """
    edits: list[dict[str, Any]] = []
    requirements: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    mitigation_ids: list[str] = []

    def citations(signal: str) -> list[dict[str, Any]]:
        return [
            {
                "pack_code": f.get("pack_code"),
                "rule_id": f.get("rule_id"),
                "instrument": f.get("instrument"),
                "provision": f.get("provision"),
            }
            for f in findings
            if f.get("matched_on") == signal
        ]

    if features.has_pii:
        mitigation_ids.append("redact_pii_before_send")
        edits.append(
            {
                "kind": "redact_pii",
                # Labels only — the matched text itself must not ride in the plan.
                "labels": sorted(features.pii_labels),
                "explanation": (
                    "Personal data detected in the output. The revision replaces "
                    "each occurrence with a [REDACTED:<label>] marker."
                ),
                "cures": citations("has_pii"),
            }
        )

    if features.prohibited_phrases:
        mitigation_ids.append("soften_absolute_claims")
        edits.append(
            {
                "kind": "soften_phrases",
                "phrases": sorted(features.prohibited_phrases),
                "explanation": (
                    "Absolute or guaranteed-outcome language detected. The "
                    "revision softens it to non-promissory wording."
                ),
                "cures": citations("prohibited_phrases"),
            }
        )

    if features.cross_border and not features.lawful_basis_present:
        requirements.append(
            {
                "kind": "add_field",
                "field": "lawful_basis",
                "explanation": (
                    "A cross-border transfer needs a documented lawful basis. "
                    "No text edit cures this — set `lawful_basis` on the payload "
                    "(e.g. 'contract', 'adequacy') once the basis exists."
                ),
                "cures": citations("cross_border"),
            }
        )

    # Findings the planner has no mechanical answer for: judgement calls.
    for f in findings:
        signal = f.get("matched_on")
        if signal in _TEXTUAL_SIGNALS or signal in _REQUIREMENT_SIGNALS:
            continue
        unresolved.append(
            {
                "finding": {
                    "pack_code": f.get("pack_code"),
                    "rule_id": f.get("rule_id"),
                    "instrument": f.get("instrument"),
                },
                "note": (
                    "No mechanical fix exists for this finding — it needs human "
                    "judgement or a workflow change, not a text edit."
                ),
            }
        )
    if blocked:
        unresolved.append(
            {
                "finding": {"rule_id": "own_policy", "pack_code": None,
                            "instrument": "your organisation's own policy"},
                "note": (
                    "Your own policy denied this action outright"
                    + (f": {policy_reasons[0]}" if policy_reasons else "")
                    + ". A denied action is a decision, not a wording problem — "
                    "route it through your approval workflow."
                ),
            }
        )

    revised: dict[str, Any] | None = None
    if mitigation_ids:
        revised, _applied = apply_mitigation_ids(payload, mitigation_ids)
        # Rule 4: verify our own work instead of presenting it as cured.
        leftover = detect_pii_labels(revised) if features.has_pii else []
        if leftover:
            revised = None
            edits[:] = [e for e in edits if e["kind"] != "redact_pii"]
            unresolved.append(
                {
                    "finding": {"rule_id": "pii_redaction", "pack_code": None,
                                "instrument": "Attest PII detector"},
                    "note": (
                        "Automatic redaction could not fully remove detected "
                        f"personal data (remaining: {', '.join(sorted(leftover))}). "
                        "Review and edit this output by hand."
                    ),
                }
            )

    if not edits and not requirements and not unresolved:
        return None

    body = {
        "revised_output": revised,
        "edits": edits,
        "requirements": requirements,
        "unresolved": unresolved,
    }
    # One canonicalisation function, everywhere (CLAUDE.md rule 2). This hash is
    # what the signed decision event carries: the full plan can be re-presented
    # later and checked against the chain without the chain storing content.
    return {**body, "plan_hash": sha256_hex(body)}


def chain_summary(remediation_plan: dict[str, Any]) -> dict[str, Any]:
    """What the signed decision event stores about a plan: shape, never content.

    The hash pins the exact plan; the counts and kinds let dashboards and
    auditors see that a fix was offered without the chain carrying any customer
    text (which, for a customer-key org, must stay dark to Attest).
    """
    return {
        "plan_hash": remediation_plan["plan_hash"],
        "edit_kinds": sorted({e["kind"] for e in remediation_plan["edits"]}),
        "requirement_kinds": sorted(
            {r["kind"] for r in remediation_plan["requirements"]}
        ),
        "unresolved_count": len(remediation_plan["unresolved"]),
        "has_revision": remediation_plan["revised_output"] is not None,
    }
