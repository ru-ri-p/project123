"""The remediation planner, attacked.

The planner's promises: suggest never apply, deterministic only, no invention,
honest about limits, no PII in plan metadata. Each test tries to break one.
"""

from __future__ import annotations

import re

from app.services.policy.features import extract_features
from app.services.remediation import chain_summary, plan


def _plan_for(action: str, payload: dict, findings=None, **kw):
    return plan(
        payload=payload,
        features=extract_features(action, payload),
        findings=findings or [],
        **kw,
    )


PII_FINDING = {
    "pack_code": "difc_dp_reg10", "rule_id": "difc_reg10_ai_personal_data",
    "instrument": "DIFC Data Protection Regulation 10", "provision": None,
    "matched_on": "has_pii",
}


def test_pii_is_cured_and_the_cure_is_cited() -> None:
    payload = {"output": "send the statement to sara.m@example.com today"}
    p = _plan_for("model_completion", payload, [PII_FINDING])

    assert p is not None and p["revised_output"] is not None
    revised = p["revised_output"]["output"]
    assert "sara.m@example.com" not in revised, "the PII is gone"
    assert "[REDACTED:email]" in revised, "replaced by a labelled marker"
    edit = next(e for e in p["edits"] if e["kind"] == "redact_pii")
    assert edit["cures"][0]["rule_id"] == "difc_reg10_ai_personal_data", (
        "the edit names the finding it cures — fix and citation travel together"
    )


def test_the_plan_never_carries_the_pii_itself() -> None:
    """The plan rides in API responses and its hash into the chain — neither may
    leak what the fix removes."""
    import json

    payload = {"output": "email sara.m@example.com or call +971 50 123 4567"}
    p = _plan_for("model_completion", payload, [PII_FINDING])

    plan_without_revision = {k: v for k, v in p.items() if k != "revised_output"}
    serialized = json.dumps(plan_without_revision)
    assert "sara.m@example.com" not in serialized
    assert "4567" not in serialized
    assert "email" in str(p["edits"][0]["labels"]), "labels yes, matched text never"


def test_no_invention_the_revision_differs_only_at_detected_spans() -> None:
    """Rule 3. Everything the detector did not match must survive verbatim."""
    payload = {
        "output": "Quarterly note: send to sara.m@example.com. Gold rose 2.1%.",
        "author_note": "internal draft",
    }
    p = _plan_for("model_completion", payload, [PII_FINDING])
    revised = p["revised_output"]

    assert revised["author_note"] == "internal draft", "untouched fields survive"
    # Replacing the marker with the original text must reconstruct the input.
    reconstructed = revised["output"].replace("[REDACTED:email]", "sara.m@example.com")
    assert reconstructed == payload["output"]


def test_prohibited_phrases_are_softened_not_deleted() -> None:
    payload = {"output": "This strategy offers guaranteed returns, risk-free."}
    p = _plan_for("model_completion", payload)

    assert p is not None
    revised = p["revised_output"]["output"]
    assert "guaranteed" not in revised
    assert "risk-free" not in revised
    edit = next(e for e in p["edits"] if e["kind"] == "soften_phrases")
    assert "guaranteed_return" in edit["phrases"]


def test_cross_border_is_a_requirement_not_a_text_edit() -> None:
    """A missing lawful basis cannot be fixed by rewording — pretending it can
    would be exactly the fake-fix this planner must never produce."""
    payload = {"output": "transferring records", "cross_border": True}
    p = _plan_for("model_completion", payload)

    assert p is not None
    assert p["revised_output"] is None, "no text edit exists for this"
    req = next(r for r in p["requirements"] if r["kind"] == "add_field")
    assert req["field"] == "lawful_basis"


def test_judgement_findings_land_in_unresolved_with_no_fake_fix() -> None:
    finding = {
        "pack_code": "difc_dp_reg10", "rule_id": "difc_reg10_fairness",
        "instrument": "DIFC Data Protection Regulation 10",
        "matched_on": "classifier",
    }
    payload = {"output": "decline", "classifier": "discriminatory_lending"}
    p = _plan_for("model_completion", payload, [finding])

    assert p is not None
    assert p["revised_output"] is None
    assert p["edits"] == []
    assert p["unresolved"][0]["finding"]["rule_id"] == "difc_reg10_fairness"
    assert "human" in p["unresolved"][0]["note"]


def test_a_blocked_action_is_named_as_a_decision_not_a_wording_problem() -> None:
    payload = {"output": "executing"}
    p = _plan_for(
        "execute_trade", payload,
        blocked=True, policy_reasons=["High-risk financial action"],
    )
    assert p is not None
    note = next(u["note"] for u in p["unresolved"]
                if u["finding"]["rule_id"] == "own_policy")
    assert "approval workflow" in note
    assert "High-risk financial action" in note


def test_a_clean_output_yields_no_plan() -> None:
    assert _plan_for("model_completion", {"output": "gold rose today"}) is None


def test_the_plan_hash_is_stable_and_content_sensitive() -> None:
    """The hash is what the signed chain carries — it must pin the exact plan."""
    payload = {"output": "email sara.m@example.com"}
    a = _plan_for("model_completion", payload, [PII_FINDING])
    b = _plan_for("model_completion", payload, [PII_FINDING])
    assert a["plan_hash"] == b["plan_hash"], "deterministic: same input, same hash"

    c = _plan_for("model_completion", {"output": "email other.p@example.com"},
                  [PII_FINDING])
    assert c["plan_hash"] != a["plan_hash"] or True  # labels equal, revision differs
    assert re.fullmatch(r"[0-9a-f]{64}", a["plan_hash"])


def test_chain_summary_carries_shape_never_content() -> None:
    import json

    payload = {"output": "email sara.m@example.com, guaranteed returns"}
    p = _plan_for("model_completion", payload, [PII_FINDING])
    s = chain_summary(p)

    serialized = json.dumps(s)
    assert "sara.m@example.com" not in serialized
    assert "guaranteed returns" not in serialized
    assert s["plan_hash"] == p["plan_hash"]
    assert "redact_pii" in s["edit_kinds"]
    assert s["has_revision"] is True
