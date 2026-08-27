# Attest × TradeEasy — Engineering Integration Guide

**Audience:** the engineer wiring Attest into TradeEasy's serving path.
**Time to first working integration:** ~15 minutes.
**Companion document:** the *TradeEasy Pilot Guide* covers testing, policy
authoring, and verification exercises; this document covers the production
wiring.

---

## 1. What you are integrating, in one paragraph

Attest is a compliance gate + tamper-evident audit trail for AI outputs. You
route each AI-generated output through **one function call** before it reaches
a user. Attest evaluates it against your institution's own policy plus the
DIFC / capital-markets rulebooks you have adopted, records both the decision
and the output as cryptographically signed, hash-chained events (anchored to
an external timestamp authority — nobody, including Attest, can rewrite the
history afterwards), and hands you a verdict. **Attest reports; your code
decides** — the gate never alters your application's behaviour by itself.
New in SDK 0.2.0: you can configure, per risk tier, whether the SDK applies a
verified fix automatically or leaves it to a human.

## 2. Install and configure

```bash
pip install attest_sdk-0.2.0-py3-none-any.whl   # provided by your Attest contact
```

Only runtime dependency: `requests`.

Create the client **once at startup** (module-level singleton or your DI
container — it holds a small local cache and an offline queue):

```python
# compliance.py
import os
from attest_sdk import AttestClient

attest = AttestClient(
    api_key=os.environ["ATTEST_API_KEY"],          # never hardcode
    base_url="https://attest-api-ipvl.onrender.com",
    # Per-tier remediation policy — YOUR choice (see §5). Recommended:
    auto_remediate={"yellow": "auto", "orange": "auto", "red": "human"},
)
attest.prepare_offline()   # optional: be outage-ready before the first request
```

Configuration your ops team sets:

| Env var | Value |
|---|---|
| `ATTEST_API_KEY` | The org API key from your Attest contact. Store it in your secrets manager; it is shown once at issuance. |
| `ATTEST_STATE_DIR` | (optional) Where the offline queue + device key live. Default `~/.attest`. Must persist across restarts and be writable by the service user. |

## 3. Where the call goes in your flow

Immediately after your model produces an output, before you serve it:

```
user query ──▶ your model ──▶ attest.gate(...) ──▶ verdict ──▶ your code serves / holds / queues
```

```python
result = attest.gate(
    {
        "output": text,                      # the AI-generated text (required convention)
        "classifier": "individualised_advice",  # include WHEN you know the output
                                                # is a recommendation, not commentary
        # any other context you want sealed into the record is fine here
    },
    action="model_completion",               # your vocabulary; this is the default
)
```

Payload conventions that make the evaluation sharper:

- Put the user-facing text under the key `"output"`.
- If your own pipeline classifies an output as individualised advice, say so
  with `"classifier": "individualised_advice"` — Attest's advice rules key on
  it, and a compliant rewrite will *remove* it (that removal is exactly what a
  human confirms, see §6).
- Use `action=` for what the AI is doing in your own vocabulary
  (`"model_completion"` for generated briefs and answers; if you ever automate
  actions like `"execute_trade"`, gate those too — your policy can hard-deny
  them).

## 4. Reading the verdict

```python
if result.blocked:
    # YOUR OWN policy denied this (only your policy can block — jurisdiction
    # rulebooks never do). Withhold the output; result.approval_id routes it
    # to your approval workflow (§6).
    serve(FALLBACK_MESSAGE)

elif result.auto_remediation and result.auto_remediation["applied"]:
    # The SDK already applied a verified fix and re-gated it (§5). `result`
    # is the verdict ON THE CURED TEXT — serve that, not the original.
    serve(result.auto_remediation["output"]["output"])

elif result.flagged:
    # Allowed, but something was raised. Your call: serve as-is, serve the
    # suggested fix after review, or hold. See §6 for the human path.
    review_queue.put(result)
    serve(text)          # flagged ≠ forbidden; your policy decides

else:                    # result.compliant (or unevaluated/error — see below)
    serve(text)
```

| `result.status` | Meaning | Typical handling |
|---|---|---|
| `compliant` | Evaluated, nothing raised. | Serve. |
| `flagged` | Allowed, but raised risk or a cited rulebook finding. Carries `suggested_fix` and sometimes a verified `rewrite`. | Auto-cure (§5) or human review (§6). |
| `blocked` | **Your own** policy denied it. | Withhold; approval workflow. |
| `unevaluated` | Recorded, but no active policy yet. | Serve; finish onboarding. |
| `error` | Attest unreachable; `recorded=False`, or the event was buffered locally (`buffered=True`). | Serve; nothing else to do — see §8. |

Every verdict also carries `result.tier` (green/yellow/orange/red),
`result.findings` (each citing the regulatory instrument), `result.trace_id`,
and `result.summary()` for a one-line log entry. Log `result.summary()` on
every call — it makes support conversations trivial.

## 5. Per-tier auto-remediation — your configuration

`auto_remediate` is **your** dial, applied by **your** process. Attest's
server only ever suggests and records; this setting decides who presses the
button.

```python
auto_remediate={"yellow": "auto", "orange": "auto", "red": "human"}
```

- **`"auto"`** — when a flagged verdict at that tier carries a *complete,
  gate-verified* cure, the SDK applies it and re-gates it **inside the same
  `gate()` call**. You get back the second verdict (usually `compliant`),
  annotated with `result.auto_remediation`:

  ```python
  {
      "applied": True,
      "cure": "deterministic",        # or "rewrite"
      "output": {"output": "..."},    # the cured payload — serve this
      "remediated_seq": 3,            # the flagged decision it closed
      "original_tier": "orange",
      "original_status": "flagged",
  }
  ```

  Cures come in two kinds. **Deterministic**: mechanical edits (personal data
  redacted to `[REDACTED:email]`-style tokens, promissory phrasing softened),
  each edit citing the finding it cures. **Rewrite**: for judgement-call
  violations, a model-drafted revision that Attest's *deterministic* engine
  already re-judged compliant before offering it — checked, not hoped (§7).

- **`"human"`** (the default for every tier) — fixes are suggested only;
  nothing is applied. Omitting `auto_remediate` entirely keeps every tier
  human: identical to pre-0.2.0 behaviour.

**Three lines auto mode never crosses**, whatever you configure:

1. **Blocked verdicts.** Your policy denied the *action*; no client setting
   re-opens that.
2. **Rewrites marked `requires_human_confirmation`.** The draft changed what
   the output *is* (advice → commentary) — only a person can confirm that.
3. **Incomplete cures.** Anything `unresolved`, or evidence still required →
   auto-applying would just re-flag, so the case stays with a human.

Also guaranteed: no loops (one attempt per flag; a cure that still flags comes
back honestly with `auto_remediation["applied"] = True` but `status =
"flagged"`), and if the network dies between the flag and the cure you get the
recorded flag back with the failed attempt visible
(`applied: False, "error": ...` — the cure text rides along so you can retry
it explicitly).

**The audit story is identical either way.** The original flag, the fix, and
the compliant re-check are all sealed in the chain: *flagged → fix offered →
revised output compliant*. Auto mode changes latency, not the record.

## 6. The human path

Three situations put a person in the loop:

**(a) A flagged verdict you chose not to auto-cure** (e.g. red, or an
incomplete fix). The fix travels with the flag:

```python
if result.flagged and result.has_fix:
    fixed = result.apply_suggestion()        # a copy of the revised payload
    proof = attest.gate(fixed, trace=result.trace_id,
                        remediates=result.decision_seq)
    # proof.compliant → the loop is closed in the sealed history.
```

`result.suggested_fix["unresolved"]` lists honestly what no mechanical edit
could cure — that list is your reviewer's worksheet.

**(b) A verified rewrite that needs confirmation.** When
`result.rewrite is not None` and
`result.rewrite["requires_human_confirmation"]` is true, the draft
reclassified the output (e.g. removed your `classifier` declaration and turned
advice into commentary). Show the reviewer the original and
`result.rewrite["output"]`; on their approval:

```python
proof = attest.gate(result.apply_rewrite(), trace=result.trace_id,
                    remediates=result.decision_seq)
```

The rewrite's provenance (drafting model, prompt hash) is already sealed in
the signed decision — nobody can later swap the text and claim it was the
suggestion.

**(c) A blocked verdict.** `result.approval_id` names a pending approval.
Your compliance officer resolves it:

```python
attest.resolve_approval(result.approval_id, status="approved",   # or "denied"
                        approver_id="officer_1", comment="reviewed")
```

The approval action itself becomes a signed event in the same chain.

## 7. Multi-step traces (optional)

Each `gate()` call is its own record by default. To tell one story across
steps (retrieval → draft → final), pass the trace forward:

```python
step1 = attest.gate({"draft": draft})
attest.gate({"tool": "price_lookup", "result": price},
            action="tool_call", trace=step1.trace_id)
```

Remediation *requires* the same trace — the fix must land in the same sealed
story as the flag (the SDK handles this automatically in auto mode).

## 8. If Attest goes down

Nothing for you to build. `gate()` never raises on an outage (pass
`on_error="raise"` if you prefer exceptions). The SDK evaluates locally
against cached rules (`result.offline=True`, provisional), queues the signed
event durably under `ATTEST_STATE_DIR`, and hands the backlog over on the next
successful call — verified signature-by-signature before anything is recorded.
The only claim never queued is a remediation link (it must be validated
against the live chain); those return `error` and you retry.

Check `attest.pending_offline` in your health endpoint — it should be 0 in
steady state.

## 9. Proving it afterwards

Everything above lands in a tamper-evident history you can check without
trusting Attest:

- **Replay** (integrity check of a trace):
  `GET /v1/trace/{trace_id}/replay` → `all_verified: true`.
- **Evidence export** (for a regulator or auditor):
  `GET /v1/evidence/{trace_id}/export?format=zip` — a self-contained bundle
  with a standalone `verify.py` that re-checks every hash, signature, chain
  link, and external anchor **offline**.

The Pilot Guide walks through both, including deliberately tampering with a
record to watch verification fail.

## 10. Drop-in reference implementation

A complete, minimal integration — adapt names to your codebase:

```python
# compliance.py — TradeEasy × Attest
import logging
import os

from attest_sdk import AttestClient

log = logging.getLogger("attest")

attest = AttestClient(
    api_key=os.environ["ATTEST_API_KEY"],
    base_url="https://attest-api-ipvl.onrender.com",
    auto_remediate={"yellow": "auto", "orange": "auto", "red": "human"},
)

FALLBACK = "This response is being reviewed before release."


def gate_output(text: str, *, classifier: str | None = None) -> tuple[str, bool]:
    """Returns (text_to_serve, needs_human). Call on every AI output."""
    payload = {"output": text}
    if classifier:
        payload["classifier"] = classifier

    result = attest.gate(payload)
    log.info(result.summary())

    if result.blocked:
        return FALLBACK, True                      # approval_id already queued

    ar = result.auto_remediation
    if ar and ar["applied"]:
        return ar["output"]["output"], not result.compliant

    if result.flagged:
        # Not auto-curable: red tier, human-confirmation rewrite, or an
        # incomplete fix. Serve per your policy; queue for review either way.
        enqueue_for_review(result)                 # your queue
        return text, True

    return text, False                             # compliant / unevaluated / outage
```

```python
# review_worker.py — close flags a human approved
def approve_fix(result, reviewer: str) -> None:
    if result.rewrite:                             # human confirmed the rewrite
        cured = result.apply_rewrite()
    else:
        cured = result.apply_suggestion()          # raises if there is none
    proof = attest.gate(cured, trace=result.trace_id,
                        remediates=result.decision_seq)
    assert proof.compliant, proof.summary()
```

## 11. Sixty-second smoke test

Run once after wiring, with your real key:

```python
from compliance import gate_output

# Should auto-cure at orange (PII) and hand back redacted text:
text, needs_human = gate_output("For details call 0501234567.")
assert "[REDACTED" in text and not needs_human

# Should flag for review (advice) rather than silently pass:
text, needs_human = gate_output(
    "You should increase your gold position before the Fed minutes.",
    classifier="individualised_advice",
)
assert needs_human
```

Questions → your Attest contact. Everything the SDK records is inspectable in
your compliance console and exportable as an evidence bundle at any time.
