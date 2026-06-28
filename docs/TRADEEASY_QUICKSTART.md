# TradeEasy Quickstart — Attest SDK

You'll receive three things from the Attest team:

1. **The SDK** — a wheel file (`attest_sdk-0.1.0-py3-none-any.whl`) or a git URL.
2. **A service URL** — e.g. `https://attest-api-xxxx.onrender.com`.
3. **An API key**.

That's all you need. There is nothing to deploy on your side.

## 1. Install (1 line)

```bash
pip install attest_sdk-0.1.0-py3-none-any.whl
# or: pip install "git+https://github.com/shaundytradesfx/govproject01.git@claude/zealous-archimedes-8i4x3i"
```

(Only dependency is `requests`.)

## 2. Add two calls to your AI workflow

One **trace** per transaction (one AI-synthesized output); one **event** per step.

```python
from attest_sdk import AttestClient

attest = AttestClient(
    api_key="YOUR_API_KEY",
    base_url="YOUR_SERVICE_URL",
    enable_local_precheck=False,
)

def on_ai_transaction(txn):
    trace = attest.new_trace()
    attest.record_event(trace, 1, "model_completion", {"output": txn.output})
    attest.record_event(trace, 2, "tool_call",        {"tool": txn.tool, "result": txn.result})
    attest.record_event(trace, 3, "model_completion", {"action": "finalize", "output": txn.final})
```

Rules: `seq` starts at 1 and is strictly increasing per trace; `event_type` is one
of `model_completion | tool_call | policy_decision | approval_action | mitigation
| erasure`; `payload` is any JSON dict.

Not using Python? Call the API directly:
`POST {URL}/v1/event` with header `x-api-key` and body
`{"trace_id","seq","type","payload"}`.

## 3. Confirm it works (60 seconds)

```python
import requests
from attest_sdk import AttestClient

API_KEY = "YOUR_API_KEY"
URL = "YOUR_SERVICE_URL"

attest = AttestClient(api_key=API_KEY, base_url=URL, enable_local_precheck=False)
t = attest.new_trace()
attest.record_event(t, 1, "model_completion", {"output": "hello"})
attest.record_event(t, 2, "tool_call", {"result": "ok"})

r = requests.get(f"{URL}/v1/trace/{t}/replay", headers={"x-api-key": API_KEY}, timeout=30)
print("all_verified:", r.json()["all_verified"])   # -> True
```

If it prints `all_verified: True`, you're recording tamper-evident, signed
provenance. Done.

See `attest_sdk/README.md` for full details.
