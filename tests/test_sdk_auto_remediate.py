"""Per-tier auto-remediation in the SDK, attacked.

The contract: the CUSTOMER configures which tiers this client may cure
unattended (`auto_remediate={"yellow": "auto", ...}`). When a flagged verdict
at an "auto" tier carries a COMPLETE, gate-verified cure, the client applies
it and re-gates it in the same call — original flag still sealed in the chain.
Three lines are never crossed: blocked verdicts, rewrites needing human
confirmation, and incomplete cures. Each test tries to cross one.

No server here: `requests.post` is replaced with a canned-response sequence so
every wire call the client makes is captured and asserted on.
"""

from __future__ import annotations

import pytest

from attest_sdk import AttestClient


class _Resp:
    def __init__(self, body: dict) -> None:
        self._body = body
        self.status_code = 200

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._body


def _client(monkeypatch, responses: list[dict], **kw) -> tuple[AttestClient, list[dict]]:
    """An AttestClient whose POSTs get canned bodies, in order; returns calls."""
    calls: list[dict] = []

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append({"url": url, "json": json})
        return _Resp(responses[min(len(calls) - 1, len(responses) - 1)])

    monkeypatch.setattr("attest_sdk.attest.requests.post", fake_post)
    client = AttestClient(api_key="k", base_url="http://attest.test",
                          offline_enabled=False, **kw)
    return client, calls


def _flagged(tier: str, *, fix: dict | None, seq: int = 3) -> dict:
    return {
        "status": "flagged", "allowed": True, "tier": tier,
        "trace_id": "11111111-1111-1111-1111-111111111111",
        "decision_seq": seq, "output_seq": seq + 1,
        "suggested_fix": fix,
    }


COMPLIANT_SECOND = {
    "status": "compliant", "allowed": True, "tier": "green",
    "trace_id": "11111111-1111-1111-1111-111111111111",
    "decision_seq": 5, "output_seq": 6, "remediation_of": 3,
}

COMPLETE_FIX = {
    "revised_output": {"output": "call [REDACTED:phone_ae]"},
    "edits": [{"kind": "redact"}], "requirements": [], "unresolved": [],
    "plan_hash": "ab" * 32,
}

VERIFIED_REWRITE_FIX = {
    "revised_output": None, "edits": [], "requirements": [],
    "unresolved": [{"note": "individualised advice"}],
    "plan_hash": "cd" * 32,
    "rewrite": {"output": {"output": "General commentary."},
                "evaluation": "compliant", "requires_human_confirmation": False,
                "drafted_by": "stub", "prompt_sha256": "ef" * 32},
}


def test_auto_tier_applies_the_fix_and_returns_the_closed_loop(monkeypatch) -> None:
    client, calls = _client(
        monkeypatch, [_flagged("orange", fix=COMPLETE_FIX), COMPLIANT_SECOND],
        auto_remediate={"orange": "auto"},
    )
    r = client.gate({"output": "call 0501234567"})

    assert len(calls) == 2, "flag, then the cure — one SDK call, two gates"
    second = calls[1]["json"]
    assert second["remediates"] == 3, "the cure names the flagged decision"
    assert second["trace_id"] == "11111111-1111-1111-1111-111111111111", (
        "and lands in the SAME sealed story"
    )
    assert second["output"] == {"output": "call [REDACTED:phone_ae]"}

    assert r.compliant
    assert r.remediation_of == 3
    assert r.auto_remediation == {
        "applied": True, "cure": "deterministic", "remediated_seq": 3,
        "original_tier": "orange", "original_status": "flagged",
    }


def test_human_tier_never_auto_applies(monkeypatch) -> None:
    """Red configured "human" (the recommended path): suggest only."""
    client, calls = _client(
        monkeypatch, [_flagged("red", fix=COMPLETE_FIX)],
        auto_remediate={"yellow": "auto", "orange": "auto", "red": "human"},
    )
    r = client.gate({"output": "risky"})
    assert len(calls) == 1, "exactly one gate — no second POST"
    assert r.flagged and r.has_fix and r.auto_remediation is None


def test_default_config_is_byte_identical_to_before(monkeypatch) -> None:
    """No auto_remediate argument -> every tier is human -> old behaviour."""
    client, calls = _client(monkeypatch, [_flagged("yellow", fix=COMPLETE_FIX)])
    r = client.gate({"output": "x"})
    assert len(calls) == 1
    assert r.flagged and r.auto_remediation is None


def test_verified_rewrite_is_preferred_and_applied(monkeypatch) -> None:
    client, calls = _client(
        monkeypatch, [_flagged("orange", fix=VERIFIED_REWRITE_FIX), COMPLIANT_SECOND],
        auto_remediate={"orange": "auto"},
    )
    r = client.gate({"output": "You should buy gold."})
    assert len(calls) == 2
    assert calls[1]["json"]["output"] == {"output": "General commentary."}
    assert r.auto_remediation["cure"] == "rewrite"


def test_human_confirmation_rewrite_is_never_auto_applied(monkeypatch) -> None:
    """The draft changed what the output IS — no tier setting overrides the
    human-confirmation mark."""
    fix = {**VERIFIED_REWRITE_FIX,
           "rewrite": {**VERIFIED_REWRITE_FIX["rewrite"],
                       "requires_human_confirmation": True}}
    client, calls = _client(
        monkeypatch, [_flagged("orange", fix=fix)],
        auto_remediate={"orange": "auto"},
    )
    r = client.gate({"output": "You should buy gold."})
    assert len(calls) == 1, "reclassification stays a human decision"
    assert r.flagged and r.rewrite is not None and r.auto_remediation is None


def test_incomplete_cure_is_never_auto_applied(monkeypatch) -> None:
    """A revision that leaves unresolved findings (or evidence requirements)
    would just re-flag; auto mode must decline and leave it to a person."""
    partial = {**COMPLETE_FIX, "unresolved": [{"note": "advice needs judgement"}]}
    client, calls = _client(
        monkeypatch, [_flagged("orange", fix=partial)],
        auto_remediate={"orange": "auto"},
    )
    r = client.gate({"output": "x"})
    assert len(calls) == 1
    assert r.flagged and r.auto_remediation is None

    needs_evidence = {**COMPLETE_FIX,
                      "requirements": [{"kind": "lawful_basis"}]}
    client, calls = _client(
        monkeypatch, [_flagged("orange", fix=needs_evidence)],
        auto_remediate={"orange": "auto"},
    )
    r = client.gate({"output": "x"})
    assert len(calls) == 1 and r.auto_remediation is None


def test_blocked_is_never_auto_remediated(monkeypatch) -> None:
    """Your own policy denied the ACTION; no client setting re-opens that."""
    body = {"status": "blocked", "allowed": False, "tier": "red",
            "trace_id": "t", "decision_seq": 3, "approval_id": "ap_1",
            "suggested_fix": COMPLETE_FIX}
    client, calls = _client(
        monkeypatch, [body],
        auto_remediate={"yellow": "auto", "orange": "auto", "red": "auto"},
    )
    r = client.gate({"output": "wire it"}, action="wire_transfer")
    assert len(calls) == 1
    assert r.blocked and r.auto_remediation is None


def test_a_cure_that_still_flags_comes_back_honestly(monkeypatch) -> None:
    """If the re-gate still flags, the second verdict is returned as-is —
    annotated, and never looped (remediates= suppresses further auto)."""
    still_flagged = {**_flagged("orange", fix=None, seq=5), "remediation_of": 3}
    client, calls = _client(
        monkeypatch, [_flagged("orange", fix=COMPLETE_FIX), still_flagged],
        auto_remediate={"orange": "auto"},
    )
    r = client.gate({"output": "x"})
    assert len(calls) == 2, "one attempt, no retry loop"
    assert r.flagged
    assert r.auto_remediation["applied"] is True, (
        "the attempt is on record even though the cure did not close the flag"
    )


def test_regate_outage_returns_the_sealed_flag_with_the_attempt_visible(
    monkeypatch,
) -> None:
    """First gate lands, then the network dies mid-loop: the caller gets the
    recorded flag back (not a phantom error), with the failed attempt noted."""
    import requests as rq

    calls: list[dict] = []
    first_body = _flagged("orange", fix=COMPLETE_FIX)

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append({"url": url, "json": json})
        if len(calls) == 1:
            return _Resp(first_body)
        raise rq.ConnectionError("network died")

    monkeypatch.setattr("attest_sdk.attest.requests.post", fake_post)
    client = AttestClient(api_key="k", base_url="http://attest.test",
                          offline_enabled=False,
                          auto_remediate={"orange": "auto"})
    r = client.gate({"output": "x"})

    assert len(calls) == 2
    assert r.flagged and r.recorded, "the flag itself IS recorded"
    assert r.auto_remediation["applied"] is False
    assert r.auto_remediation["error"], "and the failed attempt says why"


def test_invalid_config_is_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="auto_remediate"):
        AttestClient(api_key="k", auto_remediate={"orange": "always"})
    with pytest.raises(ValueError, match="auto_remediate"):
        AttestClient(api_key="k", auto_remediate={"purple": "auto"})
