# TradeEasy Live Test — Customer-Key Confidentiality & Consent

This test proves two things end to end:

1. **Dark at rest** — once you switch on customer-key mode, the content you record
   is stored by Attest but **Attest cannot read it**. It is encrypted under a key
   only you hold.
2. **Consent-gated access** — if Attest ever needs to see a specific record, it
   files a *scoped* request. Nothing is visible until **you approve**, and
   approving releases **only** the exact records in that request — never your key,
   never anything else.

> ⚠️ Use **synthetic data only** for this pilot. Do not put real customer or
> market data through the test.

You'll receive three things from the Attest team:

- **A service URL** — e.g. `https://attest-api-xxxx.onrender.com`
- **An API key** (your org key)
- Confirmation that your org is enabled for this test

Everything below runs on **your** machine. Your private key never leaves it.

---

## Fastest path: the web console (no install)

Open **`{SERVICE_URL}/console`** in a browser. It walks you through the whole
ceremony with buttons — connect with your API key, generate your keypair (created
*in your browser* via WebCrypto; download and keep the private key), enable
customer-key mode, review and approve/deny access requests, and verify your
recorded traces. The approve step reads your private-key file locally in the
browser; the key is never uploaded.

The only step that still involves code is recording events (step 4 below) —
that's your app's SDK integration, unchanged.

Prefer a terminal, or want to audit exactly what runs? The CLI below is the
equivalent flow and remains fully supported.

---

## 1. Install (with the consent extra)

```bash
pip install "attest-sdk[consent] @ git+https://github.com/shaundytradesfx/govproject01.git@claude/zealous-archimedes-8i4x3i"
# or, from a wheel we send you:
pip install "attest_sdk-0.1.0-py3-none-any.whl[consent]"
```

The `[consent]` extra adds `cryptography` (needed for the key operations). The
plain provenance client stays `requests`-only.

Set your connection details once:

```bash
export ATTEST_BASE_URL="YOUR_SERVICE_URL"
export ATTEST_API_KEY="YOUR_API_KEY"
```

---

## 2. Generate your wrapping keypair

```bash
python -m attest_sdk.consent_cli keygen \
    --out-private org_private.pem \
    --out-public  org_public.pem
```

- `org_private.pem` is your secret. It is written with `0600` permissions. **Keep
  it safe and never send it to anyone**, including Attest. (In production this
  lives in your KMS/HSM.)
- `org_public.pem` is the half you give Attest — it can only *lock* content, never
  open it.

---

## 3. Go dark (enable customer-key mode)

```bash
python -m attest_sdk.consent_cli enable --public org_public.pem
# -> {"org_id": "...", "confidentiality_mode": "customer_key"}
```

From this moment, everything you record is encrypted under a key Attest cannot
open.

---

## 4. Record some events (now dark)

Use the normal provenance client. Nothing changes in how you record — the
darkness is handled server-side by the mode you just set.

```python
import os, uuid
from attest_sdk import AttestClient

attest = AttestClient(
    api_key=os.environ["ATTEST_API_KEY"],
    base_url=os.environ["ATTEST_BASE_URL"],
    enable_local_precheck=False,
)

trace = attest.new_trace()
attest.record_event(trace, 1, "model_completion", {"secret": "synthetic-A"})
attest.record_event(trace, 2, "tool_call",        {"secret": "synthetic-B"})
print("trace:", trace)
```

Tell the Attest team this `trace` id (and/or the two record hashes if you have
them) so they know what to file a request against. **Send only the ids — not the
content.**

---

## 5. Attest files a scoped request → you review it

The Attest team files a request for **one** of those records. You then see it:

```bash
python -m attest_sdk.consent_cli list --status pending
# note the "request_id" for the one you want to inspect

python -m attest_sdk.consent_cli show --request-id <REQUEST_ID>
```

`show` displays the request's **scope** — exactly which records Attest is asking
for, and the reason. Confirm it matches what you expect (one record, the one you
were told about).

---

## 6. Approve — release only that record's key

```bash
python -m attest_sdk.consent_cli approve \
    --request-id <REQUEST_ID> \
    --approver officer_1 \
    --private org_private.pem
# -> {"status": "approved", ...}
```

What happened under the hood: the CLI used your private key **locally** to
unwrap just the in-scope record's content key and re-wrap it to Attest's
one-time access key. Only that one key was released. Your private key never left
your machine.

(If instead you want to refuse: `deny --request-id <REQUEST_ID>`. To pull access
you previously granted: `revoke --request-id <REQUEST_ID>`.)

---

## 7. Confirm the boundary held

The Attest team will now confirm from their side that they can read **exactly**
the approved record — and that the second, out-of-scope record is still **403
(unavailable)**. That contrast is the whole point of the test:

| Record | In the request? | Approved? | Attest can read? |
|--------|:---------------:|:---------:|:----------------:|
| #1     | ✅              | ✅        | ✅ yes           |
| #2     | ❌              | —         | ❌ no (403)       |

---

## What this proves for you

- Attest hosted your content but **could not read it** until you said so.
- When you said so, you released **one record**, not your key and not the rest.
- Every step (request, approval, read) is itself recorded on Attest's side, so
  the access is auditable after the fact.

## What it does **not** claim

Attest proves records are **unaltered and independently time-stamped**. It does
**not** judge whether an AI action was lawful or compliant — that stays with your
own policies and reviewers.

Questions or anything unexpected → send us the `request_id` and the CLI output
(never the private key or the plaintext content).
