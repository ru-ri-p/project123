# Attest × TradeEasy — Complete pilot testing guide

This is everything, end to end: setup, seven tests, and what to send back.
Budget about an hour. Use **synthetic data only** throughout.

In the committed copy of this document the API key is a placeholder; the copy
you received by email has it filled in.

**You need from us (all included with this document):**

| | |
|---|---|
| Service URL | `https://attest-api-ipvl.onrender.com` |
| API key | `[YOUR_API_KEY]` |
| SDK | `attest_sdk-0.1.0-py3-none-any.whl` (file attached to the email) |

Nothing to deploy on your side. Any machine with Python 3.11+ and internet
access works — a laptop is fine.

**What this pilot proves:** every AI output you route through Attest is checked
against the rulebooks that apply to you, recorded as a hash-chained,
Ed25519-signed event, anchored to an independent timestamp authority, and
verifiable by an outsider with no access to our servers. Altering any stored
record is detected, and the exact record is named.

**What it does not prove:** that an output is lawful. Attest proves records are
*unaltered* — a speed camera, not the speed limit. Our regulation packs are
drafted from public sources and not yet reviewed by counsel; the console labels
them accordingly, and no such pack can ever block your business. Treat flags as
pilot signal, not legal advice.

---

# Part A — Setup (~15 minutes, once)

## A1. Install the SDK

Save the attached wheel file anywhere and run:

```bash
pip install attest_sdk-0.1.0-py3-none-any.whl
```

(Python 3.11+. If you prefer no SDK at all, see the last section — everything
here is also a plain HTTP call.)

## A2. Open your console and connect

In a browser: **https://attest-api-ipvl.onrender.com/console**

Paste the API key and click Connect. First connection takes you into a short
onboarding — two steps:

**Step 1 — who you are.** Select your jurisdictions (**DIFC**) and your sectors
(capital markets, plus anything else that applies). Attest derives every
applicable rulebook from this. One thing to know: you cannot pick and choose
among the resulting rulebooks — obligations follow from what you are, not from
what you tick. A rulebook you could decline would prove nothing.

**Step 2 — your own policy.** Click **Create starter policy**. This publishes a
small rulebook of *your own* (it denies high-risk actions like `execute_trade`
and flags personal data). You can edit it at any time under **Compliance** — and
one of the tests below has you do exactly that. This matters because **only your
own policy can ever block an output**; our jurisdiction rulebooks flag and cite,
never block.

## A3. Generate your encryption keys

Console → **Keys & Custody** → generate a keypair. The private key is created in
your browser and never leaves it. From this point on, the content you record is
encrypted so that **we cannot read it** — we hold ciphertext, and only you can
approve a specific read. Test 6 stress-tests this claim.

Setup done.

---

# Part B — The scripted tests (Tests 1–5 and 7)

Create a file called `attest_tests.py`, paste in everything below, fill in the
key at the top, and run it:

```bash
python attest_tests.py
```

It prints each test's result next to what you should expect. Nothing here
touches your real systems — it just sends synthetic outputs to Attest and prints
the verdicts back.

```python
"""Attest pilot — scripted tests. Synthetic data only."""
import requests
from attest_sdk import AttestClient

URL = "https://attest-api-ipvl.onrender.com"
KEY = "[YOUR_API_KEY]"

attest = AttestClient(api_key=KEY, base_url=URL)

print("\n=== Test 1 — a clean output records as compliant =====================")
r = attest.gate({"output": "Gold closed higher today on softer dollar."})
print("got   :", r.status, "| recorded:", r.recorded, "| trace:", r.trace_id)
print("expect: compliant | recorded: True | trace: <some id>")

print("\n=== Test 2 — personal data FLAGS with a citation, is NOT blocked ====")
r = attest.gate({"output": "Client update: send the statement to fatima.k@example.com"})
print("got   :", r.status, "| blocked:", r.blocked)
for f in r.findings:
    print("   finding:", f.get("pack_code") or f.get("rule_id"), "|",
          str(f.get("reason", ""))[:70])
print("expect: flagged | blocked: False | at least one finding citing a DIFC")
print("        data-protection rulebook. Flags never stop your business.")

print("\n=== Test 3a — only YOUR policy can block =============================")
r = attest.gate({"output": "executing"}, action="execute_trade")
print("got   :", r.status, "| blocked:", r.blocked)
print("expect: blocked | blocked: True — denied by YOUR starter policy,")
print("        not by ours. Part C below proves that by editing your rule.")

print("\n=== Test 4 — multi-step transactions chain into one story ============")
t = attest.new_trace()
attest.gate({"query": "client risk profile"}, action="retrieval", trace=t)
attest.gate({"output": "draft summary"}, action="model_completion", trace=t)
attest.gate({"output": "final summary"}, action="finalize", trace=t)
print("got   : one trace id:", t)
print("expect: open the console -> Audit Records -> this trace shows the steps")
print("        in order; sequence numbers were assigned server-side.")

print("\n=== Test 5 — the record is independently verifiable ==================")
rep = requests.get(f"{URL}/v1/trace/{t}/replay",
                   headers={"x-api-key": KEY}, timeout=30).json()
print("got   : all_verified =", rep["all_verified"])
print("expect: True — every hash, signature and chain link re-checked.")

print("\n=== Test 7 — Attest goes down; you don't =============================")
broken = AttestClient(api_key=KEY, base_url="https://127.0.0.1:9")
r = broken.gate({"output": "recorded during outage"})
print("got   :", r.status, "| recorded:", r.recorded, "| offline:", r.offline)
print("expect: a verdict anyway, recorded: False, offline: True — evaluated")
print("        locally against cached rules, signed by a device key, queued")
print("        in an encrypted local store. Your app never waits on us.")

r = attest.gate({"output": "back online"})
print("recovery gate:", r.status, "| recorded:", r.recorded)
print("expect: the queued outage record is handed over and grafted into your")
print("        chain. In Audit Records it appears marked DEFERRED, carrying")
print("        both when it happened and when we received it — the gap is")
print("        evidenced, not hidden.")

print("\nDone. Fill in the results table and continue with Parts C and D.")
```

(Test 6 is deliberately absent from the script — it is browser clicks and a
conversation with us, not code. Part D.)

---

# Part C — Test 3b: change your rule, watch the behaviour change

1. Console → **Compliance** → your policy editor. Find the rule
   `high_risk_financial_action` and change its `"decision"` from `"deny"` to
   `"flag"`. Republish.
2. Run just this again (python interpreter or re-run the script and read Test 3a):

```python
r = attest.gate({"output": "executing"}, action="execute_trade")
print(r.status, r.blocked)
```

**Expect:** `flagged False` now — same action, different verdict, because *your*
rule changed. That is the design: what is acceptable for TradeEasy is written by
TradeEasy; Attest applies it without exception and proves it did. Feel free to
change the rule back afterwards.

---

# Part D — Test 6: decline us, and confirm we get nothing

This is the test that matters most, because it checks the claim vendors usually
ask you to take on faith. It is a short choreography between you and us:

1. **You:** make sure A3 (keypair) is done, and note any one `trace_id` from
   Part B. Send it to us.
2. **We** file an access request against that trace. It appears in your console
   under **Consent Requests**, showing who is asking and the stated reason.
3. **You: DECLINE it.**
4. **We** reply in writing confirming what we could read: **nothing.** Content
   stayed ciphertext on our side.
5. **We** file a second request. **You: approve this one.** We confirm we can
   now read *that single record* — approval releases exactly one record's key,
   nothing else.
6. **You:** look at Audit Records. The whole ceremony — request, decline,
   second request, approval, our read — was itself recorded as signed, chained
   events in your trail. Consent isn't a checkbox; it's evidence.

---

# Results — send this back

| # | Test | Pass? | Notes |
|---|---|---|---|
| 1 | Clean output → compliant | | |
| 2 | PII → flagged with DIFC citation, NOT blocked | | |
| 3a | `execute_trade` → blocked by your own policy | | |
| 3b | Rule edited → same action now flags | | |
| 4 | Multi-step trace, in order | | |
| 5 | Replay verifies (`all_verified: True`) | | |
| 6 | Declined consent → we read nothing; approval → one record only | | |
| 7 | Outage → local verdict, then deferred graft on recovery | | |

Plus: anything that surprised you, anything that felt like friction, and roughly
how long the whole thing took. Friction reports are as valuable to us as
failures.

---

# If you'd rather not use Python

Every scripted call above is a plain HTTP request. The core one:

```
POST https://attest-api-ipvl.onrender.com/v1/gate
Header: x-api-key: [YOUR_API_KEY]
Body:   {"action": "model_completion", "output": {"output": "..."}}
```

Optional fields: `"trace_id"` to group steps into one trace. Replay is
`GET /v1/trace/{trace_id}/replay` with the same header. Works from any language,
curl included. What the SDK adds over raw HTTP is Test 7 — the offline
evaluation and encrypted local queue during an outage.

---

# After the tests: what going live means

The test script is not the integration. Going live is the same few lines placed
inside your application, at each point an AI-generated result leaves the model:

```python
result = attest.gate({"output": answer})
if result.blocked:
    answer = "This response needs review before release."
```

One honest note on scope: Attest covers every output you route through
`gate()` — completely and provably. It cannot see AI actions your systems never
send it. Which of your AI workflows get wired in is your decision, and for the
pilot the scope is whatever you choose to connect.

Questions or anything unexpected: reply to the email this came with.
