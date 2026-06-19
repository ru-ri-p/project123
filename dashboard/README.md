# Attest Dashboard

Next.js operator dashboard for trace review, replay verification, evidence export, and the approvals queue (Phase 2 Week 7).

## Setup

```bash
cd dashboard
cp .env.local.example .env.local
npm install
```

Ensure the Attest API is running (`uvicorn app.main:app --reload` from repo root).

## Run

```bash
npm run dev
```

Open http://localhost:3000

## Pages

- **/** — trace list (`GET /v1/traces`)
- **/traces/[id]** — replay verification badges + evidence export
- **/approvals** — pending queue with Approve/Deny (`POST /v1/approvals/{id}/resolve`)

API key is read server-side from `ATTEST_API_KEY` (never exposed to the browser).
