"""The SDK side of the remediation loop.

The SDK's contract: expose the fix, never apply it silently, and refuse to
queue an unverifiable remediation claim while Attest is unreachable.
"""

from __future__ import annotations

import pytest

from attest_sdk.gate import GateResult


def test_apply_suggestion_is_explicit_and_returns_a_copy() -> None:
    fix = {"revised_output": {"output": "send to [REDACTED:email]"},
           "edits": [], "requirements": [], "unresolved": [], "plan_hash": "ab" * 32}
    r = GateResult(status="flagged", allowed=True, trace_id="t",
                   decision_seq=4, suggested_fix=fix)

    assert r.has_fix
    revised = r.apply_suggestion()
    assert revised == {"output": "send to [REDACTED:email]"}
    revised["output"] = "mutated"
    assert fix["revised_output"]["output"] != "mutated", (
        "apply_suggestion hands back a copy — the plan itself is immutable"
    )


def test_apply_suggestion_refuses_when_there_is_no_mechanical_fix() -> None:
    """A blocked action has no revision; pretending otherwise would let code
    'apply' nothing and re-gate the same output as if it were a fix."""
    fix = {"revised_output": None, "edits": [], "requirements": [],
           "unresolved": [{"note": "needs human review"}], "plan_hash": "cd" * 32}
    r = GateResult(status="blocked", allowed=False, trace_id="t",
                   suggested_fix=fix)

    assert not r.has_fix
    with pytest.raises(ValueError, match="no revised output"):
        r.apply_suggestion()


def test_old_server_responses_without_the_field_still_parse() -> None:
    """Additive change: a response from a pre-remediation server must not break
    a new SDK — and vice-versa the server ignores nothing it needs."""
    r = GateResult.from_response({
        "status": "flagged", "allowed": True, "trace_id": "t",
        "output_seq": 2, "output_hash": "h", "signature": "s",
    })
    assert r.suggested_fix is None and r.remediation_of is None


def test_a_remediation_is_never_buffered_offline(monkeypatch, tmp_path) -> None:
    """Queueing an unvalidated 'this fixes decision N' claim while the server
    is unreachable would let a dead network mint remediation links nobody
    checked. The SDK must return unreachable instead, so the caller retries."""
    import requests as rq

    from attest_sdk import AttestClient

    client = AttestClient(
        api_key="k",
        base_url="https://127.0.0.1:9",  # nothing listens here
        state_dir=tmp_path,
        server_timeout=0.2,
    )
    # Avoid the (network-touching) offline preparation — cached bundle absent
    # is fine for this test; a plain gate would still buffer.
    client._prepared = True  # noqa: SLF001 — test reaches into the client deliberately

    plain = client.gate({"output": "during outage"}, trace="0" * 32)
    assert plain.buffered or plain.status == "error", "sanity: outages buffer plain gates"

    fixed = client.gate(
        {"output": "revised"}, trace="0" * 32, remediates=4,
    )
    assert fixed.buffered is False, "the remediation claim was NOT queued"
    assert fixed.recorded is False
    assert fixed.status == "error"
    assert isinstance(fixed.error, str) and fixed.error

    # And on_error="raise" still raises rather than swallowing.
    with pytest.raises(rq.RequestException):
        client.gate({"output": "revised"}, trace="0" * 32, remediates=4,
                    on_error="raise")
