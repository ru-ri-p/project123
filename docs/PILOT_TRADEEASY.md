# Attest × TradeEasy — Provenance Pilot Guide

A self-hosted, provenance-only pilot that runs entirely on TradeEasy's Render
account. No AWS, no external cloud account, no customer data.

## What this pilot proves — and what it does not

**Proves (cryptographically, today):**
- Every AI transaction TradeEasy records is hash-chained and Ed25519-signed at
  ingestion — a complete, ordered, signed audit trail.
- **Tamper-evidence:** altering any stored record is detected on replay, and the
  exact offending event is identified.
- **Independent external anchoring:** each batch's Merkle root is timestamped by a
  third-party RFC 3161 TSA, so history cannot be rewritten before an anchor — and
  an auditor can verify that token offline with `verify.py --tsa-roots`.
- **Independent verifiability:** an auditor runs `verify.py` on their own machine,
  with zero access to the Attest server, and sees `ALL EVENTS VERIFIED`.

**Does NOT prove (important — set expectations):**
- It does **not** make outputs "comply with" any jurisdiction, and cannot certify
  an output as legal or compliant. Attest proves the record is *unaltered*, never
  that the output is *true* or *lawful*.
- Checking outputs against TradeEasy's *own documented* jurisdictional rules
  (pass/flag/block, human approval on RED) is the **enforcement phase** — out of
  scope for this provenance pilot, and a clearly-scoped follow-on.

## Architecture on Render

```
TradeEasy app (Python backend)
   │  Attest SDK: new_trace() + record_event()
   ▼
attest-api  (Render PRIVATE service — internal only, no public URL)
   │
   ├── attest-db          (Render managed PostgreSQL 16)
   └── attest-seal-anchor  (Render Cron) ── outbound HTTPS ──▶ external TSA
```

Everything is inside TradeEasy's Render network. The only thing leaving it is the
outbound timestamp request to the TSA.

## Deploy (one-time)

1. **Generate the signing key** locally and keep it safe (never commit it):
   ```bash
   python scripts/generate_keys.py     # writes keys/ed25519_private.pem + public
   ```
2. **Create the Render resources** from the blueprint (`render.yaml`): a private
   `attest-api`, managed `attest-db`, and the `attest-seal-anchor` cron. If a
   blueprint field is rejected by Render's current schema, create the same three
   resources via the dashboard with the env vars listed in `render.yaml`.
3. **Add the keys as Secret Files** on BOTH `attest-api` and `attest-seal-anchor`,
   mounted at:
   ```
   /etc/secrets/ed25519_private.pem
   /etc/secrets/ed25519_public.pem
   ```
   (Render wipes the ephemeral disk on redeploy, so the key must be a Secret File,
   not generated on the host.)
4. **Confirm outbound egress** to the TSA is allowed — after first deploy, the
   cron's logs should show `Anchored batch ...`. If they show a TSA error, the
   environment is blocking egress to `TSA_URL` (allowlist it).
5. **Create TradeEasy's org + API key** (one-off, via a Render shell/job):
   ```bash
   python scripts/create_org.py --id tradeeasy --name "TradeEasy"
   ```
   Save the printed API key — TradeEasy's app uses it as `x-api-key`.

## Integrate (TradeEasy's Python backend)

Install the SDK (it ships in this repo as `sdk/`), point it at the private API,
and record one trace per transaction:

```python
from sdk.attest import AttestClient

attest = AttestClient(
    api_key="<tradeeasy_api_key>",
    base_url="http://attest-api:10000",   # Render private hostname:port
    enable_local_precheck=False,          # provenance-only: no policy engine
)

# One AI-synthesized output = one trace.
trace = attest.new_trace()
attest.record_event(trace, 1, "model_completion", {"action": "classify", "output": "..."})
attest.record_event(trace, 2, "tool_call", {"tool": "price_lookup", "result": "AED 199"})
attest.record_event(trace, 3, "model_completion", {"action": "finalize", "output": "published"})
```

Rules that matter:
- `seq` is **strictly monotonic per trace, starting at 1**. Out-of-order is rejected.
- `event_type` ∈ `model_completion | tool_call | policy_decision | approval_action | mitigation | erasure`.
- Recording is asynchronous to your product's outcome — it never blocks the user.

**Non-Python services (Node/React):** call the HTTP API directly — same contract:
`POST /v1/event` with header `x-api-key`, body `{trace_id, seq, type, payload}`.

## Validate (the acceptance test)

With the API running, generate a realistic load and verify it:

```bash
# 1. Record 125 events across 25 transactions, replay them, export a bundle
python scripts/demo_pilot_provenance.py --base-url http://attest-api:10000 \
    --api-key <tradeeasy_api_key> --transactions 25 --out pilot_bundle.json
#    -> "Replay of 25 traces: all_verified=True"

# 2. Tamper-evidence: change one stored event, then replay
#    UPDATE events SET hash='0...0' WHERE seq=2 AND trace_id='<id>';
#    GET /v1/trace/<id>/replay  -> all_verified=false, points at seq 2

# 3. Independent offline verification (auditor's machine, no server access)
pip install cryptography rfc3161-client
curl -o freetsa_root.pem https://freetsa.org/files/cacert.pem   # the TSA's published root
python app/bundle/verify.py pilot_bundle.json --tsa-roots freetsa_root.pem
#    -> ALL EVENTS VERIFIED
#    -> ANCHOR trusted: TSA=... genTime=...     (once the batch is anchored)
```

The pilot is a success when steps 1–3 pass: data records, tampering is caught, and
an independent party verifies the bundle — including the third-party anchor.

## Configuration reference (env vars)

| Var | Pilot value | Notes |
|-----|-------------|-------|
| `DATABASE_URL` | from Render Postgres | injected by the blueprint |
| `SIGNING_BACKEND` | `local` | PEM key via Secret File (pilot custody) |
| `SIGNING_PRIVATE_KEY_PATH` | `/etc/secrets/ed25519_private.pem` | Render Secret File |
| `SIGNING_PUBLIC_KEY_PATH` | `/etc/secrets/ed25519_public.pem` | Render Secret File |
| `TSA_URL` | `https://freetsa.org/tsr` | swappable to a UAE-qualified TSA later |
| `BATCH_INTERVAL_SECONDS` | `300` | align with the cron schedule |
| `RATE_LIMIT_MAX_REQUESTS` | `120` | per API key per window; raise for bulk loads |

## Key custody note (be precise with stakeholders)

Render is a PaaS with no HSM/KMS, so the pilot signing key is a **local PEM stored
as a Render Secret File**. This is acceptable here *only because the pilot uses no
customer data* (synthetic/non-production). It means an operator with Render access
could read the key — so the pilot proves the technology works and produces
independently-verifiable evidence; it does not yet defend against an insider with
deployment access forging *new* events. Moving the key to non-exportable custody
(a KMS/HSM — not necessarily AWS) is the post-pilot hardening step.
