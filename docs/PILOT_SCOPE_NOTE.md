# TradeEasy × Attest pilot — what it will, and won't, prove

*A short note to align on scope before we kick off. Please read the second
section carefully — it's the one that matters.*

## What this pilot demonstrates

We instrument TradeEasy's AI workflow so that every transaction (each AI-
synthesized output) is recorded as a tamper-evident, cryptographically signed
event. The pilot then proves four things, end to end:

1. **A complete, signed audit trail** — every step (model output, tool call) is
   hash-chained and signed at the moment it happens.
2. **Tamper-evidence** — if anyone alters a stored record after the fact, replay
   detects it and points at the exact event.
3. **Independent third-party anchoring** — each batch is timestamped by an
   external timestamp authority we don't control, so history can't be rewritten
   after the fact, even by us or by TradeEasy.
4. **Independent verification** — your auditor runs our verifier on their own
   machine, with no access to our servers, and sees "ALL EVENTS VERIFIED."

Success for this pilot = those four hold on TradeEasy's real workflow.

## What this pilot does NOT do (please note)

Attest proves that an AI action **happened and has not been altered**. It does
**not** make an output "comply" with any law or jurisdiction, and it cannot
certify that an output is legal, correct, or true. Cryptography proves the
**record is unchanged** — never that the **content is lawful**.

So the goal of "every output complies with the jurisdictions TradeEasy is bound
by" is **not** what this pilot delivers, and we shouldn't position it that way to
anyone. That distinction protects both of us: over-claiming compliance is exactly
the kind of statement a regulator pushes back on.

## What comes after the pilot (the part you're thinking of)

The compliance-checking you have in mind is a real, planned next phase. Once
provenance is proven, Attest can run each output through a policy engine that
encodes **TradeEasy's own documented rules** for its jurisdictions, and produce a
signed, provable record of that check — allow / flag / block, with a named human
approving the high-risk cases. Crucially, the rules and the legal judgment stay
**TradeEasy's**; Attest is the control-and-evidence layer that proves the
institution enforced its own policy — not an autonomous arbiter of legality.

That phase needs your documented rules and a bit more setup, so we're keeping it
out of the first pilot to prove the core technology fast.

## What we need from TradeEasy to start

- A Render deployment (we provide the blueprint; it runs internal-only).
- Outbound network access from that environment to the timestamp authority.
- A technical contact to add ~two SDK calls into the Python backend (about a day).
- Whoever will act as the independent auditor running the verifier.

No customer data is used in the pilot, and nothing runs on our infrastructure.
