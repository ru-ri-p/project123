# TradeEasy — Pilot test plan

Seven tests, ~30 minutes. Each says what to run and exactly what you should see.
Setup (console onboarding, SDK install) is in the Quickstart you already have —
do that first. Run everything with synthetic data.

Throughout: `URL = https://attest-api-ipvl.onrender.com`, key as provided.

```python
from attest_sdk import AttestClient
attest = AttestClient(api_key="YOUR_KEY", base_url="URL")
```

---

## Test 1 — A clean output records as compliant

```python
r = attest.gate({"output": "Gold closed higher today on softer dollar."})
print(r.status, r.recorded, r.trace_id)
```

**Expect:** `compliant True <uuid>`. Console → **Audit Records**: the trace is
there with two events (the decision and the output), both hashed and signed.

## Test 2 — Personal data flags, with a citation — and is NOT blocked

```python
r = attest.gate({"output": "Client update: send the statement to fatima.k@example.com"})
print(r.status, r.blocked)
for f in r.findings: print(" -", f.get("pack_code") or f.get("rule_id"), "|", f.get("reason", "")[:70])
```

**Expect:** `flagged False`. At least one finding citing a DIFC data-protection
rulebook (personal data through an AI system), naming the instrument it comes
from. Console → **Compliance** shows the flag. The key assertion: **`blocked` is
False** — jurisdiction rulebooks flag and cite, they never stop your business.

## Test 3 — Only YOUR policy can block

```python
r = attest.gate({"output": "executing"}, action="execute_trade")
print(r.status, r.blocked)
```

**Expect:** `blocked True` — because *your* starter policy denies
`execute_trade`, not because ours does. Now edit that rule in Console →
Compliance (change its decision to `flag`), republish, and run it again:
**Expect** `flagged`, not blocked. Same action, your rule, your call — that's
the design.

## Test 4 — Multi-step transactions chain into one story

```python
t = attest.new_trace()
attest.gate({"query": "client risk profile"}, action="retrieval", trace=t)
attest.gate({"output": "draft summary"}, action="model_completion", trace=t)
attest.gate({"output": "final summary"}, action="finalize", trace=t)
```

**Expect:** one trace in Audit Records with the steps in order, sequence numbers
assigned server-side.

## Test 5 — The record is independently verifiable

```python
import requests
rep = requests.get(f"{URL}/v1/trace/{t}/replay", headers={"x-api-key": KEY}, timeout=30).json()
print(rep["all_verified"])
```

**Expect:** `True` — every hash, signature and chain link re-checked. For the
full offline version, export the evidence bundle for a trace and run the
included `verify.py` on your own machine, with no access to our servers.

## Test 6 — Consent: decline us, and confirm we get nothing

The one worth doing carefully, because it tests the claim that matters.

1. Console → **Keys & Custody** → generate a keypair. The private key stays in
   your browser; from then on we hold ciphertext.
2. Record a few outputs, tell us one trace id.
3. We file an access request. It appears under **Consent Requests** with who is
   asking and why. **Decline it.**
4. We will confirm in writing that we could not read the content. *Then* we file
   a second request; approve that one, and we can read **only that record** —
   approval re-wraps a single record's key, nothing else.

Every step of this — request, decline, approval, each read — lands in your audit
trail as signed events.

## Test 7 — Attest goes down; you don't

Point a client at a dead URL and gate something:

```python
broken = AttestClient(api_key="YOUR_KEY", base_url="https://127.0.0.1:9")
r = broken.gate({"output": "recorded during outage"})
print(r.status, r.recorded, r.offline)
```

**Expect:** a verdict anyway (`recorded False`, `offline True`) — evaluated
locally against cached rules, signed by a device key, queued in an encrypted
local store. Your application never waits on us. Use your real client again and
gate anything: the queue drains, and the outage-era records appear in Audit
Records marked **deferred**, carrying both when they happened and when we
received them — the gap is evidenced, not hidden.

(Note: the offline cache is per `state_dir`; the `broken` client above shares
the default one, so it will have your real policy cached from earlier tests.)

---

## Results

| # | Test | Pass? | Notes |
|---|---|---|---|
| 1 | Clean output → compliant | | |
| 2 | PII → flagged with citation, NOT blocked | | |
| 3 | Only your policy blocks | | |
| 4 | Multi-step trace | | |
| 5 | Replay verifies | | |
| 6 | Declined consent → we read nothing | | |
| 7 | Outage → local verdict, deferred graft | | |

Send this back filled in, plus anything that surprised you.

## What this does and doesn't prove

Attest records and checks **every output you route through `gate()`** — and for
those, the record is tamper-evident, signed, externally anchored, and
independently verifiable. It cannot see AI actions your systems never send us;
coverage of your AI estate is an integration decision on your side, and the
pilot's scope is the workflows you wire in. Our regulation packs are drafted
from public sources and not yet counsel-reviewed — flags are pilot signal, not
legal advice, and Attest proves records are *unaltered*, never that outputs are
*lawful*.
