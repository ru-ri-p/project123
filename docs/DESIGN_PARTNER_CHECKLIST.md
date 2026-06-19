# Design partner pilot checklist (Week 12)

Use this with a CBUAE-regulated LFI pilot. **Legal review is the bank’s counsel** — Attest provides technical evidence, not legal opinions.

## Technical readiness

- [ ] API deployed in UAE region (or bank VPC); Postgres + keys in-region
- [ ] `ATTEST_SIGNING_BACKEND=kms` with institutional KMS key (or local PEM for lab only)
- [ ] `seed_dev_policy.py` replaced with bank-approved policy JSON
- [ ] Dashboard reachable by risk/compliance users (approvals queue)
- [ ] Run `python scripts/demo_design_partner.py --approve` end-to-end
- [ ] Export ZIP → `python verify.py bundle.json` → **ALL EVENTS VERIFIED** on auditor laptop (no VPN to Attest)

## Governance story (supervisory, not statute)

- [ ] Bank documents AI policy; Attest enforces **their** rules (fail_mode, region)
- [ ] RED paths require named approver (`approval_action` events)
- [ ] Evidence bundle includes `compliance_summary.json` for internal audit
- [ ] Pitch brief reviewed: [PITCH_COMPLIANCE_BRIEF.md](./PITCH_COMPLIANCE_BRIEF.md)

## Integration

- [ ] SDK integrated in one production-like workflow (thick SDK optional for latency)
- [ ] Sequence numbers enforced; no silent dropped events before ingest
- [ ] PII redaction + erasure path tested if PDPL subject requests apply

## Success criteria (“done when”)

1. Live workflow triggers a **RED** policy decision.
2. Human approves in dashboard (or API).
3. Workflow resumes; follow-up events recorded.
4. Risk officer exports evidence and runs **verify.py offline**.
5. Output: `ALL EVENTS VERIFIED` + workflow summary.

## Out of scope for pilot

- Certifying legal compliance or model truthfulness
- Replacing bank GRC, DLP, or consent platforms
- Public transparency log (post-MVP)
