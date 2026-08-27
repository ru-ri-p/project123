"""Semantic rewrite drafting — a model proposes, the deterministic gate disposes.

WHAT THIS IS
============
When the deterministic remediation planner leaves `unresolved` findings —
violations that are judgement calls, not pattern fixes (an individualised
recommendation that should be general commentary, a discriminatory framing) —
this module asks Claude to draft a fully compliant rewrite of the output.

WHAT KEEPS IT HONEST
====================
1. THE MODEL NEVER OWNS A VERDICT. The caller (precheck) re-evaluates every
   draft with the same deterministic engine that judges customer outputs, and
   only a draft that PASSES is offered. "Checked, not hoped."
2. NEVER AUTO-APPLIED. The rewrite rides inside suggested_fix like every other
   suggestion; the customer's code adopts it visibly and re-gates it, and only
   that compliant re-gate closes the flag in the sealed history.
3. PROVENANCE, ALWAYS. Every draft carries the model id and a hash of the exact
   prompt, and the whole rewrite is sealed under the plan hash in the signed
   decision event. `drafted_by` can never be quietly forgotten.
4. RECLASSIFICATION IS FLAGGED. If complying required changing what the output
   IS (advice → commentary, dropping the customer's `classifier` declaration),
   the draft says so — because the gate verifies text, not nature, and a human
   should confirm the nature changed. The gate cannot check that claim; a
   person can.
5. GRACEFUL ABSENCE. No API key → the feature does not exist. Model error,
   timeout, unparseable draft, or no passing draft → the rewrite is simply
   absent and `unresolved` stands, exactly as before this module existed.

PRIVACY: the customer's output transits the model API here, inline, before
encryption at rest. That is a disclosure/consent line in the customer
agreement — and the reason this runs in-request rather than as a later batch:
for a customer-key org, in-request is the only moment the plaintext exists on
this server at all.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from typing import Any


# Feature flag is the key itself: no key, no feature, no half-configured state.
def enabled() -> bool:
    return bool(
        os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")
    )


REWRITE_MODEL = os.environ.get("REWRITE_MODEL", "claude-opus-5")
# Bounded: the gate is a synchronous call the customer's application is waiting
# on. One draft, one retry, then we stop and unresolved stands.
REWRITE_MAX_ATTEMPTS = int(os.environ.get("REWRITE_MAX_ATTEMPTS", "2"))
REWRITE_TIMEOUT_SECONDS = float(os.environ.get("REWRITE_TIMEOUT_SECONDS", "25"))
REWRITE_MAX_TOKENS = int(os.environ.get("REWRITE_MAX_TOKENS", "2000"))

SYSTEM_PROMPT = """\
You rewrite AI outputs for a regulated financial institution so they comply \
with the rulebooks provided. Hard rules:
- Remove or neutralise every violation the findings describe. No personal data \
(emails, phone numbers, IDs), no promissory or guaranteed-outcome language.
- If the only way to comply is to change what the output IS — for example an \
individualised recommendation must become general market commentary — do that, \
remove any "classifier" field from the payload, and set "reclassified": true.
- Preserve the informational value: keep the facts, figures and readings that \
were in the original. NEVER invent facts, numbers or claims that were not there.
- Keep the payload's JSON shape: same keys as the original except fields you \
must remove to comply.
Return ONLY a JSON object, no prose, no code fences:
{"revised": {<the rewritten payload>}, "reclassified": <bool>, \
"notes": "<one sentence on what you changed and why>"}"""

# Injection seam for tests: a completer takes (system, user) and returns the
# model's raw text. The default talks to the Claude API.
Completer = Callable[[str, str], str]


def _api_completer(system: str, user: str) -> str:
    import anthropic

    client = anthropic.Anthropic(timeout=REWRITE_TIMEOUT_SECONDS)
    response = client.messages.create(
        model=REWRITE_MODEL,
        max_tokens=REWRITE_MAX_TOKENS,
        system=[{"type": "text", "text": system,
                 "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": user}],
    )
    return next((b.text for b in response.content if b.type == "text"), "")


def _parse_draft(raw: str) -> dict[str, Any] | None:
    """Accept exactly the contract; anything else is not a draft."""
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.split("\n", 1)[1] if "\n" in text else text
        text = text.rsplit("```", 1)[0] if "```" in text else text
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("revised"), dict):
        return None
    return doc


def draft_rewrite(
    *,
    payload: dict[str, Any],
    findings: list[dict[str, Any]],
    unresolved: list[dict[str, Any]],
    policy_rules: list[dict[str, Any]] | None = None,
    completer: Completer | None = None,
) -> dict[str, Any] | None:
    """One drafting attempt. Returns the draft with provenance, or None.

    The caller MUST verify the draft with the deterministic engine before
    offering it to anyone — this function only writes, it never judges.
    """
    if completer is None and not enabled():
        return None
    complete = completer or _api_completer

    user = json.dumps(
        {
            "output_to_rewrite": payload,
            "findings": [
                {
                    "rule": f.get("rule_id"),
                    "instrument": f.get("instrument"),
                    "reason": f.get("reason"),
                    "guidance": f.get("guidance"),
                }
                for f in findings
            ],
            "needs_judgement": [u.get("note") for u in unresolved],
            "institution_policy_rules": policy_rules or [],
        },
        ensure_ascii=False,
    )
    prompt_sha = hashlib.sha256((SYSTEM_PROMPT + "\n" + user).encode()).hexdigest()

    try:
        raw = complete(SYSTEM_PROMPT, user)
    except Exception:  # noqa: BLE001 — model trouble must never break the gate
        return None
    doc = _parse_draft(raw)
    if doc is None:
        return None

    return {
        "output": doc["revised"],
        "reclassified": bool(doc.get("reclassified")),
        "notes": str(doc.get("notes", ""))[:300],
        "drafted_by": REWRITE_MODEL if completer is None else "stub",
        "prompt_sha256": prompt_sha,
    }
