# Attest

Runtime governance and tamper-evident provenance control plane for AI workflows — built for UAE & MENA regulated industries.

## Phase 1 — Provenance MVP

### Prerequisites

- Python 3.11+
- Docker (PostgreSQL)

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
python scripts/generate_keys.py
docker compose up -d
alembic upgrade head
python scripts/seed_dev_org.py
```

Dev API key: `org_demo_key` (see seed script output).

### Run the API

```bash
uvicorn app.main:app --reload
```

- Health: http://127.0.0.1:8000/health
- Docs: http://127.0.0.1:8000/docs
- Record event: `POST /v1/event` with header `x-api-key: org_demo_key`

### SDK usage

```python
from sdk.attest import AttestClient

w = AttestClient(api_key="org_demo_key")
t = w.new_trace()
w.record_event(t, 1, "model_completion", {"prompt": "Summarise Q1 market", "output": "..."})
```

### Run tests

```bash
pytest
ruff check .
mypy app scripts tests sdk
```

### Seal and anchor batches (Week 3)

Periodically seal unbatched events into a Merkle batch and anchor the root via RFC 3161:

```bash
python scripts/seal_and_anchor.py
```

Options: `--seal-only`, `--anchor-only`

### Replay and evidence export (Week 4)

```bash
# Verify a trace (requires recorded events)
curl -H "x-api-key: org_demo_key" http://127.0.0.1:8000/v1/trace/{trace_id}/replay

# Export evidence bundle (JSON or zip with verify.py)
curl -H "x-api-key: org_demo_key" http://127.0.0.1:8000/v1/evidence/{trace_id}/export
curl -H "x-api-key: org_demo_key" "http://127.0.0.1:8000/v1/evidence/{trace_id}/export?format=zip" -o evidence.zip

# Demo workflow (API must be running)
python scripts/demo_workflow.py
python app/bundle/verify.py bundle.json   # offline verification
```

## Phase 2 — Multi-tenancy & compliance (Weeks 5–7)

### Multi-tenancy (Week 5)

```bash
python scripts/seed_dev_org.py          # org_demo + org_other
python scripts/create_org.py --id org_acme --name "ACME Bank"

curl -H "x-api-key: org_demo_key" http://127.0.0.1:8000/v1/org/me
curl -X PATCH -H "x-api-key: org_demo_key" -H "Content-Type: application/json" \
  http://127.0.0.1:8000/v1/org/settings -d '{"region":"uae","fail_mode":"deny_on_error"}'
```

Cross-tenant access to another org's trace returns **403**.

### PII redaction & erasure (Week 6)

PII is redacted before hashing and storage. Payloads are encrypted with AES-256-GCM using per-record keys (AAD-bound to the record); erasure crypto-shreds the key.

```bash
# Erasure crypto-shreds the target payload key and appends a signed erasure event
curl -X POST -H "x-api-key: org_demo_key" -H "Content-Type: application/json" \
  http://127.0.0.1:8000/v1/erasure \
  -d '{"trace_id":"<uuid>","target_seq":1,"approver_id":"officer_1","reason":"PDPL request"}'
```

### Dashboard (Week 7)

Separate Next.js app in `dashboard/` (not mixed into the Python API repo layout).

```bash
# API (from repo root)
uvicorn app.main:app --reload

# Dashboard
cd dashboard
cp .env.local.example .env.local
npm install
npm run dev
```

Open http://localhost:3000 — trace list, replay verification (green/red badges), evidence export, and pending approvals queue.

```bash
# List traces
curl -H "x-api-key: org_demo_key" http://127.0.0.1:8000/v1/traces

# Pending approvals + resolve
curl -H "x-api-key: org_demo_key" "http://127.0.0.1:8000/v1/approvals?status=pending"
curl -X POST -H "x-api-key: org_demo_key" -H "Content-Type: application/json" \
  http://127.0.0.1:8000/v1/approvals/{approval_id}/resolve \
  -d '{"status":"approved","approver_id":"risk_officer_1","comment":"Reviewed"}'

# Seed a pending approval for demo
python scripts/seed_pending_approval.py --trace-id <uuid>
```

## Phase 3 — Enforcement (Weeks 8–11)

### Policy precheck (Week 8)

Evaluate risk **before** recording a model/tool action. Returns tier, allow/deny, and opens an approval for orange/red.

```bash
python scripts/seed_dev_policy.py   # starter rules for org_demo

curl -X POST -H "x-api-key: org_demo_key" -H "Content-Type: application/json" \
  http://127.0.0.1:8000/v1/precheck \
  -d '{
    "trace_id": "<uuid>",
    "seq": 1,
    "action": "wire_transfer",
    "payload": {"amount_aed": 50000}
  }'
```

Tiers: **green** (ok) → **yellow** (flag) → **orange** (PII / elevated risk, approval queued) → **red** (blocked under `deny_on_error`, approval queued).

```python
from sdk.attest import AttestClient

w = AttestClient(api_key="org_demo_key")
t = w.new_trace()
decision = w.precheck(t, 1, "model_completion", {"prompt": "...", "citations": 2})
if decision["allowed"]:
    w.record_event(t, 2, "model_completion", {...})
```

### Policy engine (Week 9)

Appendix A reference rules with `regulatory_ref`, priority-ordered matching, and deterministic detection layers.

```bash
curl -H "x-api-key: org_demo_key" http://127.0.0.1:8000/v1/policies/active

# Cross-border without lawful basis → RED
curl -X POST -H "x-api-key: org_demo_key" -H "Content-Type: application/json" \
  http://127.0.0.1:8000/v1/precheck \
  -d '{"trace_id":"<uuid>","seq":1,"action":"model_completion","payload":{"cross_border":true,"citations":2}}'
```

Precheck response now includes: `decision`, `risk_score`, `rule_id`, `regulatory_refs`, `layer_results`, `mitigations`.

### Approvals end-to-end (Week 10)

```bash
# After RED precheck — gate blocks until approved
curl -H "x-api-key: org_demo_key" http://127.0.0.1:8000/v1/trace/{trace_id}/gate

# Resolve → resume_allowed true/false
curl -X POST .../v1/approvals/{id}/resolve -d '{"status":"approved","approver_id":"officer_1"}'

# Apply mitigations (yellow/orange) and record mitigation event
curl -X POST .../v1/mitigate -d '{"trace_id":"...","seq":2,"mitigation_ids":["append_verify_disclaimer"],"source_payload":{...}}'

python scripts/demo_enforcement_workflow.py --approve
```

### Thick SDK (Week 11)

Local policy evaluation for green/yellow (microseconds); server escalation for orange/red only.

```python
from sdk.attest import AttestClient

client = AttestClient(api_key="org_demo_key", enable_local_precheck=True, enable_buffer=True)
client.load_policy_bundle()

trace = client.new_trace()
decision = client.precheck_smart(trace, 1, "model_completion", {"prompt": "...", "citations": 2})
if decision["allowed"]:
    client.record_event(trace, client.next_seq(trace), "model_completion", {"output": "..."}, buffered=True)
    client.flush()
client.close()
```

```bash
python scripts/demo_thick_sdk.py
```

## Phase 4 — Hardening & design partner (Week 12)

### UAE KMS signing

Default: local PEM (`ATTEST_SIGNING_BACKEND=local`). Production: AWS KMS Ed25519 in `me-central-1`.

```bash
pip install -r requirements-kms.txt
# .env: ATTEST_SIGNING_BACKEND=kms, KMS_KEY_ID=alias/attest-prod, KMS_REGION=me-central-1
curl http://127.0.0.1:8000/health   # signing_backend: kms
```

See [docs/KMS_SETUP.md](docs/KMS_SETUP.md).

### Evidence bundle (polished)

Exports include `manifest.json` (schema, org, signing backend) and `compliance_summary.json` (policy decisions, approvals, workflow gate). ZIP adds standalone files for auditors.

`verify.py` prints **ALL EVENTS VERIFIED** plus trace/workflow summary.

### Design partner “done when” demo

```bash
python scripts/seed_dev_policy.py
python scripts/demo_design_partner.py --approve
```

Checklist: [docs/DESIGN_PARTNER_CHECKLIST.md](docs/DESIGN_PARTNER_CHECKLIST.md).
