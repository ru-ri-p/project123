# Attest Provenance Pilot — A-to-Z Implementation Runbook (TradeEasy)

> **Two ways to run this pilot:**
> - **(A) Hosted (recommended, lightest for TradeEasy)** — the Attest team runs
>   the service; TradeEasy installs only the SDK and adds two calls. See
>   [HOSTING_SETUP.md](HOSTING_SETUP.md) (provider side) and
>   [TRADEEASY_QUICKSTART.md](TRADEEASY_QUICKSTART.md) (TradeEasy side).
> - **(B) Full self-host (this runbook)** — TradeEasy runs the whole service on
>   their own Render account. Use this only if they must hold the keys/data.

Follow these steps in order. Each step lists **who** does it, the **action**, the
**commands**, and the **expected result** so you know it worked. Everything runs
on TradeEasy's Render account; no AWS, no customer data, nothing on Attest's
servers.

**Owners:** `[TE]` TradeEasy engineer · `[Render]` Render dashboard ·
`[Audit]` whoever acts as independent auditor.

**Time:** ~half a day of hands-on work, most of it one-time setup.

---

## 0. What you are building and what "done" means

You will stand up the Attest service inside TradeEasy's Render network, wire two
SDK calls into the TradeEasy backend, and then prove three things:

1. **Record** — every AI transaction is captured as a signed, hash-chained event.
2. **Tamper** — altering any stored record is caught on replay, at the exact event.
3. **Verify** — an auditor runs `verify.py` on their own machine, with no server
   access, and sees `ALL EVENTS VERIFIED`, including the external TSA anchor.

When steps 1–3 pass on TradeEasy's real workflow, the pilot is a success.

> Scope note: this pilot proves *integrity and provenance*. It does **not** make
> outputs legally compliant. See `docs/PILOT_SCOPE_NOTE.md`.

---

## 1. Prerequisites `[TE]`

- A **Render** account/team for TradeEasy (https://render.com).
- The Attest repository connected to that Render account (fork it, or have Shaun
  grant access). Use branch `claude/zealous-archimedes-8i4x3i` (or merge it to
  `main` first).
- A local machine with **Python 3.11+**, **git**, and **openssl**.

Set up a local environment once (used for key generation, org creation, and the
auditor's verification):

```bash
git clone <repo-url> attest && cd attest
git checkout claude/zealous-archimedes-8i4x3i
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

✅ `python -c "import app"` runs without error.

---

## 2. Generate the signing key (local, secret) `[TE]`

The pilot signs events with an Ed25519 key. Generate it once and keep it secret —
it is **never** committed to git.

```bash
python scripts/generate_keys.py
# -> Keys written to keys/
#      private: ed25519_private.pem
#      public:  ed25519_public.pem
```

✅ `keys/ed25519_private.pem` and `keys/ed25519_public.pem` exist. Keep the
private key somewhere safe (a password manager / secret store) — you will paste
both into Render in step 5.

---

## 3. Create the Render resources from the Blueprint `[Render]`

In Render: **New + → Blueprint**, point it at the repo. Render reads `render.yaml`
and creates:

- `attest-db` — managed PostgreSQL 16.
- `attest-api` — the Attest API as a **Private Service** (internal-only, no public URL).
- `attest-seal-anchor` — a cron job that seals and anchors batches.

If Render rejects a blueprint field (the schema evolves), create the same three
resources manually (New + → Private Service / PostgreSQL / Cron Job) using the
Docker runtime and the env vars listed in `render.yaml`.

✅ Three resources appear in the Render dashboard. `attest-api` will fail to start
until step 5 (no key yet) — that's expected.

---

## 4. Wire the database URL `[Render]`

If you used the Blueprint, `DATABASE_URL` is already injected into `attest-api`
and `attest-seal-anchor` from `attest-db`. If you created resources manually, add
an env var `DATABASE_URL` to both, set to `attest-db`'s **Internal Connection
String**.

✅ Both services show `DATABASE_URL` in their Environment tab.

---

## 5. Add the signing key as Secret Files `[Render]`

On **both** `attest-api` and `attest-seal-anchor`, open **Environment → Secret
Files** and add two files (Render mounts them at `/etc/secrets/<filename>`):

| Filename | Contents |
|----------|----------|
| `ed25519_private.pem` | paste the full private PEM from step 2 |
| `ed25519_public.pem`  | paste the full public PEM from step 2 |

(The `render.yaml` env vars already point `SIGNING_PRIVATE_KEY_PATH` /
`SIGNING_PUBLIC_KEY_PATH` at `/etc/secrets/...`.)

✅ Both services list the two secret files. Trigger a redeploy of `attest-api`.

---

## 6. Confirm the API is healthy `[Render]`

On `attest-api`, watch the deploy logs. On boot it runs `alembic upgrade head`
(creates all tables) then starts uvicorn.

- Logs show `Running upgrade ... ` migrations, then `Uvicorn running`.
- Open a **Shell** on `attest-api` and run:
  ```bash
  curl -s http://localhost:$PORT/health
  # -> {"status":"ok","service":"attest","signing_backend":"local"}
  ```

✅ Health returns `signing_backend: local`. Note the service's **Internal
Address** (e.g. `attest-api:10000`) shown in the dashboard — the TradeEasy app
uses it in step 8.

---

## 7. Confirm the external anchor works `[Render]`

The `attest-seal-anchor` cron seals batches and timestamps their root at the TSA.
After it runs once (or trigger it manually), check its logs:

- `Sealed batch ... root=...` then `Anchored batch ... at ...` → egress to the TSA
  is allowed.
- A `TSA request failed` error → the environment is blocking outbound HTTPS to
  `TSA_URL` (`https://freetsa.org/tsr`). Allowlist that host, then re-run.

✅ Cron logs show `Anchored batch ...`.

---

## 8. Create TradeEasy's org + API key `[TE]`

Run this **locally** against the database's **External Connection String** (the
API is internal-only, but the DB external URL is reachable):

```bash
DATABASE_URL="<attest-db EXTERNAL connection string>" \
  python scripts/create_org.py --id tradeeasy --name "TradeEasy"
# -> API key (store securely — shown once): <THE_KEY>
```

✅ Save `<THE_KEY>` in your secret store. The TradeEasy app sends it as the
`x-api-key` header.

---

## 9. Integrate the SDK into the TradeEasy backend `[TE]`

The SDK is an installable package (only needs `requests`):

```bash
pip install attest_sdk-0.1.0-py3-none-any.whl     # wheel from `python -m build`
# or: pip install "git+<repo-url>@claude/zealous-archimedes-8i4x3i"
```

Instrument the AI workflow — **one trace per transaction** (one AI-synthesized
output), one `record_event` per step:

```python
from attest_sdk import AttestClient

attest = AttestClient(
    api_key="<THE_KEY>",                 # from step 8
    base_url="http://attest-api:10000",  # Internal Address from step 6
    enable_local_precheck=False,         # provenance-only
)

def on_transaction(txn):
    trace = attest.new_trace()
    attest.record_event(trace, 1, "model_completion", {"action": "classify", "output": txn.category})
    attest.record_event(trace, 2, "tool_call",        {"tool": "price_lookup", "result": txn.price})
    attest.record_event(trace, 3, "model_completion", {"action": "finalize",  "output": txn.final})
    # recording is asynchronous to the user outcome; it never blocks the transaction
```

Rules:
- `seq` is **strictly monotonic per trace, starting at 1** (out-of-order is rejected).
- `event_type` ∈ `model_completion | tool_call | policy_decision | approval_action | mitigation | erasure`.
- Non-Python services call the HTTP API directly: `POST /v1/event` with header
  `x-api-key` and body `{trace_id, seq, type, payload}`.

✅ A real transaction produces events; `GET /v1/trace/<id>/replay` returns
`all_verified: true`.

---

## 10. Smoke test (125 events) `[TE]`

From a **Shell on `attest-api`** (it has the code and env, and can reach the API
on localhost):

```bash
pip install rfc3161-client                     # for the anchor check
python scripts/demo_pilot_provenance.py \
    --base-url http://localhost:$PORT \
    --api-key <THE_KEY> --transactions 25 \
    --out /tmp/pilot_bundle.json --verify
```

Expected:
- `Recorded 25 transactions, 125 events total`
- `Replay of 25 traces: all_verified=True`
- `Fetched TSA root ... sha256 fingerprint: ...`
- `ALL EVENTS VERIFIED` (and `ANCHOR trusted: ...` once the batch from step 7 is anchored)

> If the burst hits a `429`, raise `RATE_LIMIT_MAX_REQUESTS` on `attest-api`
> (real traffic of 100+/day never approaches the limit).

✅ The demo prints `ALL EVENTS VERIFIED`.

---

## 11. Acceptance test: record → tamper → verify `[TE]` `[Audit]`

This is the deliverable demonstration.

1. **Record** real (or demo) transactions (steps 9–10).
2. **Tamper** — connect to `attest-db` and corrupt one event, then replay:
   ```sql
   UPDATE events SET hash = repeat('0',64) WHERE seq = 2 AND trace_id = '<id>';
   ```
   ```bash
   curl -s http://localhost:$PORT/v1/trace/<id>/replay -H "x-api-key: <THE_KEY>"
   # -> all_verified: false, and event seq 2 is flagged
   ```
   (Re-record afterward; this only proves detection.)
3. **Export** a bundle for a clean trace:
   ```bash
   curl -s http://localhost:$PORT/v1/evidence/<id>/export -H "x-api-key: <THE_KEY>" -o bundle.json
   ```

✅ Tampering is detected and pinpointed; `bundle.json` is produced.

---

## 12. Independent verification by the auditor `[Audit]`

Give the auditor only `bundle.json` and `app/bundle/verify.py` (no server access).
On their own machine:

```bash
pip install cryptography rfc3161-client
curl -o freetsa_root.pem https://freetsa.org/files/cacert.pem   # the TSA's published root
python verify.py bundle.json --tsa-roots freetsa_root.pem
# -> ALL EVENTS VERIFIED
# -> ANCHOR trusted: TSA=... genTime=...   (for an anchored trace)
```

The auditor should confirm the printed TSA root **fingerprint** matches FreeTSA's
published value.

✅ The auditor, independently, sees `ALL EVENTS VERIFIED`. **Pilot complete.**

---

## Appendix A — Environment variables

| Var | Pilot value |
|-----|-------------|
| `DATABASE_URL` | from `attest-db` (internal) |
| `SIGNING_BACKEND` | `local` |
| `SIGNING_PRIVATE_KEY_PATH` | `/etc/secrets/ed25519_private.pem` |
| `SIGNING_PUBLIC_KEY_PATH` | `/etc/secrets/ed25519_public.pem` |
| `TSA_URL` | `https://freetsa.org/tsr` |
| `BATCH_INTERVAL_SECONDS` | `300` |
| `RATE_LIMIT_MAX_REQUESTS` | `120` (raise for bulk loads) |

## Appendix B — Troubleshooting

- **`attest-api` won't start / signing key error** → Secret Files missing or wrong
  path (step 5).
- **`429 Too Many Requests`** → raise `RATE_LIMIT_MAX_REQUESTS`.
- **Cron `TSA request failed`** → outbound egress to `TSA_URL` blocked; allowlist it.
- **SDK `Connection refused`** → wrong `base_url`; use the Internal Address (step 6).
- **`verify.py` says `ANCHOR not checked`** → `pip install rfc3161-client`.
- **`verify.py` says `ALL EVENTS VERIFIED` but no `ANCHOR` line** → that trace
  isn't anchored yet; wait for the cron, then re-export.

## Appendix C — Out of scope (next phase)

Policy/enforcement (checking outputs against TradeEasy's documented jurisdiction
rules, allow/flag/block, human approval) and non-extractable key custody (KMS/HSM)
are deliberately deferred. See `docs/PILOT_SCOPE_NOTE.md` and
`docs/PILOT_TRADEEASY.md`.

## Appendix D — Operations

- **Backups:** Render manages Postgres backups; confirm the retention you need.
- **Key:** the pilot key lives in Render Secret Files. Rotating it invalidates
  signatures on prior events — for the pilot, don't rotate mid-run.
- **Scaling:** `attest-api` is single-instance for the pilot (migrations run on
  boot). For multiple instances, move migrations to a release step.
