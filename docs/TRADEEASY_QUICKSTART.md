# TradeEasy — Attest pilot, start here

You need three things from us, and nothing else:

1. **A service URL** — `https://attest-api-xxxx.onrender.com`
2. **Your API key**
3. **The SDK** — `pip install "git+https://github.com/shaundytradesfx/govproject01.git@claude/zealous-archimedes-8i4x3i"`

There is nothing to deploy on your side, and no dashboard for you to build. The
last pilot asked you to construct your own tooling just to see what was going on;
that is fixed — the console below is yours.

---

## Step 1 — Set up your profile (about a minute, in a browser)

Open **`{SERVICE_URL}/console`**, paste your API key, and connect.

You'll be taken through two steps before anything can be recorded:

**Where you are licensed, and what you do.** Pick your jurisdictions (DIFC, for
you) and your sectors. Attest then assigns every rulebook that follows from that
answer.

> You cannot pick and choose among the resulting rulebooks. That is deliberate,
> and it is the point: a rulebook you could decline is a rulebook that proves
> nothing. If your profile says DIFC financial services, the DIFC obligations
> apply, and the record shows they applied from the moment you said so.

**Your own policy.** Click *Create starter policy* to get a small scaffold you can
edit later under **Compliance**.

This matters more than it looks: **only your own policy can block an output.**
Jurisdiction rulebooks raise flags and cite the instrument they come from; they
never stop your business. What is or is not acceptable for TradeEasy is your call,
written by you, and Attest applies it without exception and proves it did.

Until both steps are done, recording is refused with a clear error rather than
silently accepted — a record measured against no rules is worse than no record.

## Step 2 — One call in your code

This is the whole integration.

```python
from attest_sdk import AttestClient

attest = AttestClient(api_key="YOUR_API_KEY", base_url="YOUR_SERVICE_URL")

result = attest.gate({"output": answer})   # checks AND records, one round trip

if result.blocked:
    answer = "This response needs review before release."
```

`gate()` evaluates the output against your policy and your assigned rulebooks,
records **both the decision and the output** as signed, hash-chained events, and
hands back a verdict. Sequence numbers are assigned server-side, so there is no
bookkeeping for you to get wrong.

Reading the verdict:

| | Meaning |
|---|---|
| `result.compliant` | Evaluated, nothing raised. Logged as clean. |
| `result.flagged` | Something was raised. Appears on your Compliance screen with the instrument it came from. **Not** blocked. |
| `result.blocked` | Your own policy denied it. Only your policy can do this. |
| `result.findings` | What was raised, each with its citation |
| `result.trace_id` | The record's id — look it up under Audit Records |

**Attest never changes what your application does.** It reports; you decide. The
`if result.blocked:` line above is your choice, not ours.

Multi-step transactions: pass `trace=` to group several `gate()` calls into one
chained story.

```python
t = attest.new_trace()
attest.gate({"query": q},        action="retrieval",        trace=t)
attest.gate({"output": draft},   action="model_completion", trace=t)
attest.gate({"output": final},   action="finalize",         trace=t)
```

## Step 3 — Confirm it works (60 seconds)

```python
from attest_sdk import AttestClient

attest = AttestClient(api_key="YOUR_API_KEY", base_url="YOUR_SERVICE_URL")
r = attest.gate({"output": "hello from TradeEasy"})
print(r.status, r.trace_id, r.recorded)
```

Then open the console → **Audit Records** and find that trace. You should see the
decision and the output, chained and signed.

---

## What happens if Attest goes down

Your application keeps serving. That is not a promise about our uptime — it is how
the SDK is built.

When Attest is unreachable, `gate()` evaluates the output **locally** against a
cached copy of your rules, signs the result with a device key that lives on your
machine, and queues it in an encrypted local store. When we come back, the queue
is handed over and grafted into your chain, and each recovered record carries
`deferred` plus the time it actually happened — so the trail shows the outage
rather than hiding it.

```python
if not result.recorded:
    log.info("attest queued locally: %s", result.trace_id)   # keep serving
```

`result.offline` tells you the verdict was provisional (computed against cached
rules); the server re-evaluates on recovery.

One distinction worth knowing: **an incomplete profile is not an outage.** If
Step 1 isn't finished you get `result.status == "misconfigured"` immediately,
never a queued record — otherwise the queue would fill with events that can never
be replayed, and the real problem would hide behind an apparent network fault.

## Your content stays yours

Under **Keys & Custody** in the console you can generate a keypair in your
browser. The private key never leaves it. After that, event content is encrypted
to your public key and **Attest cannot read it** — we hold ciphertext and can
still prove it is unaltered.

When we need to look at something (support, an investigation, a demo), we file an
access request. It appears under **Consent Requests** with who asked, what for,
and which trace. Nothing is readable until you approve, approval re-wraps exactly
that one record's key to the requester, and the whole ceremony — request,
approval, grant — is itself recorded as signed, chained events.

That is the part worth testing hardest: **decline one**, and confirm we still
can't read it.

---

## What this proves, and what it does not

**Proves:** every AI action is recorded, hash-chained, Ed25519-signed at
ingestion, batched into a Merkle tree and timestamped by an independent RFC 3161
authority — so no one, including Attest, can rewrite history before an anchor. Any
alteration is detected on replay, and the exact offending event is named. An
auditor can verify all of it on their own machine with no access to our servers.

**Does not prove:** that an output is lawful, or true. Attest shows *which
rulebook was live when a decision was made, that it was applied, and that nobody
edited the record afterwards.* It is a speed camera, not the speed limit.

**Pilot status of the rulebooks:** every regulation pack currently ships marked
`unverified` — drafted from public sources and **not yet checked line by line
against the official instrument by a lawyer.** The console labels them as such,
and no unverified pack is ever allowed to block anything. Treat the flags as
signal for the pilot, not as legal advice. Rule content is versioned, so when the
packs are reviewed you will still be able to show exactly which version was live
on any given day.

Use synthetic data for the pilot.

Full API details: `attest_sdk/README.md`.
