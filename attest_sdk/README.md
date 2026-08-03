# attest-sdk

The Python client for **Attest** — record tamper-evident, cryptographically
signed provenance events for your AI workflow. It is a thin client: it sends
each event to your Attest service, which signs, hash-chains, and stores it.

Only dependency: `requests`.

## Install

```bash
# From a wheel your Attest contact gives you:
pip install attest_sdk-0.1.0-py3-none-any.whl

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

**Grouping steps.** By default each call is its own record. To tell one story
across several steps, pass the trace from the first call:

```python
step1 = attest.gate({"draft": draft})
attest.gate({"tool": "price_lookup", "result": price}, action="tool_call", trace=step1.trace_id)
```

**If Attest is down**, `gate()` returns a result with `recorded=False` rather
than raising, so an outage on our side cannot take down your application. Pass
`on_error="raise"` if you would rather handle it yourself.

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
