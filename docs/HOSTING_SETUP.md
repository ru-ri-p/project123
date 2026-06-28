# Hosting Attest yourself (so TradeEasy only needs the SDK)

This is the **recommended pilot model**: you (Attest) run the service once on
**your** Render account, and hand TradeEasy three things — the **SDK**, a
**service URL**, and an **API key**. TradeEasy installs the SDK and adds two
calls. They never deploy anything.

You do this **once**, in ~30–45 minutes. Everything below is on your side.

---

## Prerequisites

- A Render account (yours). https://render.com
- This repo connected to that Render account (push it to a GitHub repo Render can
  see, or connect the existing one).
- A local machine with Python 3.11+, git, and openssl.

Local setup (used for key generation + creating TradeEasy's API key):

```bash
git clone <repo-url> attest && cd attest
git checkout claude/zealous-archimedes-8i4x3i
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

---

## Step 1 — Generate the signing key (local, secret)

```bash
python scripts/generate_keys.py
# -> keys/ed25519_private.pem  and  keys/ed25519_public.pem
```

Keep the private key safe. It never goes into git — it goes into Render as a
Secret File (Step 3).

## Step 2 — Deploy the hosted blueprint

In Render: **New + → Blueprint**, point it at the repo, and choose
**`render.yaml`** (the default, public variant). It creates:

- `attest-db` — managed PostgreSQL 16.
- `attest-api` — the API as a **public web service** with an automatic HTTPS URL.
- `attest-seal-anchor` — the cron that anchors batches to the TSA.

(If Render rejects a blueprint field, create the three resources by hand with the
env vars shown in `render.yaml`.)

## Step 3 — Add the signing key as Secret Files

On **both** `attest-api` and `attest-seal-anchor` → **Environment → Secret Files**,
add two files mounted at `/etc/secrets/`:

| Filename | Contents |
|----------|----------|
| `ed25519_private.pem` | the private PEM from Step 1 |
| `ed25519_public.pem`  | the public PEM from Step 1 |

Redeploy `attest-api`.

## Step 4 — Confirm it's healthy

`attest-api` shows a public URL like `https://attest-api-xxxx.onrender.com`. Check:

```bash
curl -s https://attest-api-xxxx.onrender.com/health
# -> {"status":"ok","service":"attest","signing_backend":"local"}
```

✅ That URL is the **base_url** you give TradeEasy.

## Step 5 — Confirm anchoring works

Look at `attest-seal-anchor` logs after it runs (or trigger it). You want
`Anchored batch ... at ...`. If you see `TSA request failed`, Render egress to
`freetsa.org` is blocked — allowlist it. (Render normally allows outbound, so this
should just work.)

## Step 6 — Create TradeEasy's API key

Run locally against the database's **External Connection String** (copy it from
`attest-db` in Render):

```bash
DATABASE_URL="<attest-db EXTERNAL connection string>" \
  python scripts/create_org.py --id tradeeasy --name "TradeEasy"
# -> API key (store securely — shown once): <THE_KEY>
```

## Step 7 — Build the SDK to hand over (optional)

TradeEasy can install straight from the repo (Step 8), or you can give them a
single wheel file:

```bash
pip install build
python -m build --wheel
# -> dist/attest_sdk-0.1.0-py3-none-any.whl   (send them this file)
```

## Step 8 — Hand TradeEasy three things

1. **The SDK** — either the wheel from Step 7, or tell them to
   `pip install "git+<repo-url>@claude/zealous-archimedes-8i4x3i"`.
2. **The service URL** — from Step 4.
3. **Their API key** — from Step 6.

Then point them at `docs/TRADEEASY_QUICKSTART.md`. Their entire job is install +
two calls + a self-test.

---

## Notes

- **Security of a public endpoint:** the API requires the `x-api-key` header,
  rate-limits per key, and runs over Render's HTTPS. Fine for a pilot with no
  customer data. Rotate or revoke a key by creating a new org / disabling the old.
- **Cost:** Render's free tiers can run the whole thing (the free web service
  sleeps when idle → first request is slow); `starter` (~$7/mo) avoids cold
  starts. Postgres has a free tier too.
- **Trust model:** in this hosted model you hold the keys and data (standard
  SaaS). The external TSA anchor still provides independent time. Moving keys to
  non-extractable custody (KMS/HSM) is the post-pilot hardening step.
- **Your own verification:** you can run the acceptance test (record → tamper →
  `verify.py`) exactly as in `docs/PILOT_RUNBOOK.md` against the public URL.
