# attest-sdk

The Python client for **Attest** — record tamper-evident, cryptographically
signed provenance events for your AI workflow. It is a thin client: it sends
each event to your Attest service, which signs, hash-chains, and stores it.

Only dependency: `requests`.

## Install

```bash
# From a wheel your Attest contact gives you:
pip install attest_sdk-0.2.0-py3-none-any.whl

# ...or directly from the repo:
pip install "git+https://github.com/shaundytradesfx/govproject01.git@claude/zealous-archimedes-8i4x3i"
```

## Use it (the gate: one call)

Route each AI output through `gate()`. Attest evaluates it against your policy
and any jurisdiction rulebooks you have adopted, records both the decision and
the output as signed, chained events, and returns a verdict.

```python
from attest_sdk import AttestClient

attest = AttestClient(api_key="YOUR_API_KEY", base_url="YOUR_SERVICE_URL")

result = attest.gate({"output": answer})

if result.blocked:            # YOUR policy denied it
    answer = "This response needs review before release."
elif result.flagged:          # raised risk, or a cited jurisdiction finding
    log.warning(result.summary())
```

That is the whole integration. No trace ids, no sequence numbers, no separate
check-then-log — one call per output.

**Attest reports; your code decides.** The gate never alters what your
application does. Verdicts:

| `result.status` | Meaning |
|---|---|
| `compliant` | Evaluated, nothing raised. Logged as clean on your dashboard. |
| `flagged` | Allowed, but raised risk or drew a cited jurisdiction finding. |
| `blocked` | **Your own** policy denied it. Jurisdiction rulebooks never block. |
| `unevaluated` | Recorded, but you have no active policy yet. |
| `error` | Attest was unreachable. `recorded` is False; your app keeps serving. |

Useful fields: `result.findings` (each with the instrument cited),
`result.jurisdictions`, `result.tier`, `result.trace_id`, `result.output_hash`,
and `result.summary()` for a one-line log entry.

**When something is flagged: the fix comes with the flag.** A non-compliant
verdict carries `result.suggested_fix` — a deterministic revision (personal
data redacted, promissory phrasing softened), each edit citing the finding it
cures, plus an honest `unresolved` list for what needs a human. Attest never
applies it; your code adopts it visibly, then re-gates it naming the flag it
fixes:

```python
result = attest.gate({"output": answer}, trace=t)
if result.flagged and result.has_fix:
    fixed = result.apply_suggestion()               # your code's explicit act
    proof = attest.gate(fixed, trace=result.trace_id,
                        remediates=result.decision_seq)
    # proof.status == "compliant" closes the loop: the sealed history now
    # reads flagged -> fix suggested -> revised output compliant, and nobody
    # (including Attest) can doctor that story afterwards.
```

A "fix" that still flags leaves the original flag open — the attempt is never
the cure. Remediation calls are never queued during an outage: the link must be
validated against the real chain, so retry when Attest is back.

**Verified rewrites.** When the violation is a judgement call the mechanical
planner can't cure (individualised advice that should be general commentary),
the verdict may also carry `result.rewrite` — a model-drafted revision that
Attest's *deterministic* engine already re-judged compliant before offering
("checked, not hoped"), with the drafting model and prompt hash sealed into the
signed decision. Apply it with `result.apply_rewrite()` and re-gate with
`remediates=`, exactly like any fix. If `requires_human_confirmation` is true,
the draft changed what the output *is* — have a person confirm that first.

### Choosing per tier: auto-fix or human? (`auto_remediate`)

You decide, per risk tier, whether this client applies a verified cure itself
or leaves every fix to a person. The recommended shape for most institutions —
routine tiers self-heal, serious ones need clearance:

```python
attest = AttestClient(
    api_key="YOUR_API_KEY", base_url="YOUR_SERVICE_URL",
    auto_remediate={"yellow": "auto", "orange": "auto", "red": "human"},
)

result = attest.gate({"output": answer})
if result.auto_remediation and result.auto_remediation["applied"]:
    # The flag AND its cure are already sealed in the chain; result is the
    # final verdict on the fixed output (usually compliant), and the cured
    # payload rides with it — serve that, not the original.
    answer = result.auto_remediation["output"]["output"]
```

With a tier set to `"auto"`, a flagged verdict at that tier whose fix is
**complete and gate-verified** is applied and re-gated inside the same
`gate()` call. You get back the *second* verdict, annotated with
`result.auto_remediation` (`cure` is `"deterministic"` or `"rewrite"`, and
`remediated_seq` names the flagged decision it closed). The original flag is
still in the sealed history — auto mode changes who presses the button, never
what gets recorded. The default (no `auto_remediate`) is `"human"` for every
tier: suggest-only, exactly as above.

Three lines auto mode never crosses, whatever you configure:

- **Blocked verdicts.** Your own policy denied the action; no client setting
  re-opens that. (Red flags route through your approval workflow as usual.)
- **Rewrites marked `requires_human_confirmation`.** The draft changed what
  the output *is* — only a person can confirm that.
- **Incomplete cures.** If anything is `unresolved` or evidence is still
  required, auto-applying would just re-flag; the case stays with a human.

**Grouping steps.** By default each call is its own record. To tell one story
across several steps, pass the trace from the first call:

```python
step1 = attest.gate({"draft": draft})
attest.gate({"tool": "price_lookup", "result": price}, action="tool_call", trace=step1.trace_id)
```

## If Attest goes down

An outage on our side must not take down your application **or** put a hole in
your audit trail. Both are handled, with no configuration:

- **You keep serving.** `gate()` never raises on an outage (pass
  `on_error="raise"` if you would rather it did).
- **You still get a verdict.** The SDK caches your policy *and* your adopted
  jurisdiction rulebooks, and evaluates locally — so the same output gets the
  same answer whether or not we are reachable. `result.offline` marks it as
  provisional.
- **Nothing is lost.** The event is queued in an encrypted file under
  `~/.attest`, signed by a key this SDK generated for itself on first run. It
  survives process restarts. `result.buffered` is True.
- **It heals itself.** The next successful `gate()` hands the backlog over
  automatically; Attest verifies each signature and the local chain before
  recording anything. Force it with `attest.flush_offline()`, and check
  `attest.pending_offline` (0 in steady state).

Grafted events are marked **deferred** and carry both your system's claimed time
and the time Attest recorded them — the gap is evidenced, never presented as
real-time. The device signature means an event cannot be edited or quietly
dropped from a submitted segment; it does not (and cannot) prove your clock.

Call `attest.prepare_offline()` at startup to be ready before your first
request. Point the state elsewhere with `state_dir=` or `ATTEST_STATE_DIR`.

## Lower-level API (provenance: 2 calls)

The original calls remain available if you want to record without evaluating, or
need to control sequencing yourself.

You need two things from your Attest contact: the **service URL** and your
**API key**.

```python
from attest_sdk import AttestClient

attest = AttestClient(
    api_key="YOUR_API_KEY",
    base_url="https://your-attest-service.example.com",
    enable_local_precheck=False,   # provenance-only
)

# One AI-synthesized output = one trace. One step = one event.
trace = attest.new_trace()
attest.record_event(trace, 1, "model_completion", {"prompt": "...", "output": "..."})
attest.record_event(trace, 2, "tool_call",        {"tool": "price_lookup", "result": "AED 199"})
attest.record_event(trace, 3, "model_completion", {"action": "finalize", "output": "published"})
```

Rules:
- `seq` is **strictly monotonic per trace, starting at 1** (out-of-order is rejected).
- `event_type` is any non-empty label. These standard values are recommended
  (some trigger special server behaviour):
  `model_completion | tool_call | policy_decision | approval_action | mitigation | erasure`
  — but custom labels (e.g. `risk_assessment`) are accepted too.
- The `payload` is any JSON-serializable dict describing what happened.
- Recording is meant to run alongside your workflow; it does not change your
  output. (Set `enable_buffer=True` to send in a background thread so it never
  blocks the request.)

## 60-second self-test

Confirms your key + URL work end to end:

```python
from attest_sdk import AttestClient
import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://your-attest-service.example.com"

attest = AttestClient(api_key=API_KEY, base_url=BASE_URL, enable_local_precheck=False)
trace = attest.new_trace()
attest.record_event(trace, 1, "model_completion", {"output": "hello"})
attest.record_event(trace, 2, "tool_call", {"result": "ok"})

# Replay it: the service re-checks every hash, signature, and chain link.
r = requests.get(f"{BASE_URL}/v1/trace/{trace}/replay", headers={"x-api-key": API_KEY}, timeout=30)
print(r.json()["all_verified"])   # -> True  (your events are recorded and verifiable)
```

## Keeping your content dark to Attest (customer-key mode)

By default Attest can read the payloads it stores for you. If you'd rather Attest
hold your content but **not be able to open it**, switch to *customer-key mode*:
you generate a wrapping keypair, keep the private key, and give Attest only the
public key. From then on every payload is encrypted under a key Attest can lock
but not unlock — dark at rest.

If Attest ever needs to see a specific record (a dispute, an audit), it files a
**scoped access request**. Nothing is visible until *you* approve, and approving
releases only the exact records in that request — never your master key, never
anything else. This is the consent ceremony, and the SDK ships both a client and
a CLI for the org side of it.

Install the crypto extra (adds `cryptography`; the base client stays `requests`-only):

```bash
pip install "attest-sdk[consent]"
```

### CLI (no code)

```bash
export ATTEST_BASE_URL="https://your-attest-service.example.com"
export ATTEST_API_KEY="YOUR_API_KEY"

# 1. Generate a keypair (private key is written 0600 — keep it secret).
python -m attest_sdk.consent_cli keygen --out-private org_priv.pem --out-public org_pub.pem

# 2. Go dark: register the PUBLIC key only.
python -m attest_sdk.consent_cli enable --public org_pub.pem

# 3. See what Attest is asking to view.
python -m attest_sdk.consent_cli list --status pending
python -m attest_sdk.consent_cli show --request-id <REQUEST_ID>

# 4. Approve — re-wraps only the in-scope keys, locally, using the private key.
python -m attest_sdk.consent_cli approve --request-id <REQUEST_ID> \
    --approver officer_1 --private org_priv.pem

# ...or refuse.
python -m attest_sdk.consent_cli deny --request-id <REQUEST_ID>
```

### Client (in code)

```python
from attest_sdk import ConsentClient
from attest_sdk.orgcrypto import generate_wrapping_keypair

org = ConsentClient(api_key="YOUR_API_KEY", base_url="https://your-attest-service.example.com")

private_pem, public_pem = generate_wrapping_keypair()   # keep private_pem secret
org.enable_customer_key(public_pem)                     # now dark at rest

# When Attest files a request, approve exactly its scope:
for req in org.list_requests(status="pending"):
    org.approve(req["request_id"], approver_id="officer_1", org_private_pem=private_pem)
```

The private key is used only inside `approve()` / the `approve` CLI command, on
your machine. It is never sent to Attest.

## Not using Python?

Call the HTTP API directly — same contract:

```
POST {BASE_URL}/v1/event
Headers: x-api-key: YOUR_API_KEY
Body:    {"trace_id": "...", "seq": 1, "type": "model_completion", "payload": {...}}
```

## What this does and doesn't do

It proves an AI action **happened and has not been altered**, with independent
third-party time-stamping. It does **not** make outputs legally compliant. The
service-side details (signing, anchoring, evidence export, offline verification)
live in the Attest service repository.
