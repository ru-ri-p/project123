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

## Use it (provenance: 2 calls)

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
- `event_type` is one of:
  `model_completion | tool_call | policy_decision | approval_action | mitigation | erasure`.
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
