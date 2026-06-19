# Attest — Regulatory Alignment Brief

**One-page summary for investors, LFIs, and compliance stakeholders**  
**Version:** June 2026 | **Status:** Phase 1–2 complete; Phase 3 Week 8 (precheck) implemented

---

## Executive summary

**Attest** is a runtime governance and tamper-evident provenance control plane for AI workflows, built for UAE and MENA regulated industries (financial sector first).

**Core promise:** *You do not have to trust us, or our customer. Here is independent cryptographic proof that this exact AI action happened at this exact time, under these exact policies, and has not been altered since — and where required, proof that its content was provably destroyed.*

Attest **supports** PDPL-aligned technical controls and **aligns with** CBUAE AI supervisory expectations for Licensed Financial Institutions (LFIs). It does **not** certify legal compliance or judge whether AI outputs are true or fair — the institution’s board owns policy; Attest enforces and **proves** it was applied.

---

## Legal context (UAE, 2026)

| Fact | Implication for pitch |
|------|------------------------|
| **No standalone UAE AI law** | AI must comply with **existing** law: PDPL, sector rules, CBUAE supervision (banks). |
| **PDPL** (Federal Decree-Law No. 45 of 2021) | **Binding.** Effective 1 Jan 2026; full compliance due **1 Jan 2027**. |
| **CBUAE AI Guidance Note** (11 Feb 2026) | **Non-binding but supervisory** — shapes regulatory assessment of LFIs. Do **not** call it “the law.” |
| **DIFC / ADGM** | Separate data regimes — mainland PDPL framing may not apply. |

---

## PDPL — obligations Attest helps demonstrate

| PDPL theme | How Attest supports it | Product capability |
|------------|------------------------|-------------------|
| **Data minimisation & privacy by design** | Redacts PII before hashing and storage | PII detection/redaction at ingest |
| **Security of processing** | Encryption, signing, tenant isolation | AES-256-GCM payloads, Ed25519 chain, org-scoped API |
| **Right to erasure** | Crypto-shred content; retain proof erasure occurred | `POST /v1/erasure` + signed `erasure` events |
| **Accountability / demonstrability** | Offline verification without trusting vendor | Evidence export + standalone `verify.py` |
| **Records of processing (ROPA-style)** | Each AI workflow = auditable trace | Traces, events, dashboard |
| **DPIA / audit readiness** | Structured export for regulators and internal audit | Evidence bundle (JSON/ZIP) |
| **Cross-border / residency** | Org `region`, policy rules, UAE deployment path | Org settings; customer deploys in UAE region |

**Not in scope today:** consent management, subject access portals, breach notification workflows, full GRC suite, DIFC/ADGM-specific regimes.

**Pitch line:** *Attest strengthens the technical and evidentiary side of PDPL — minimisation, security, erasure proof, and audit-ready records — while your legal team retains lawful basis, notices, and data-subject rights processes.*

---

## CBUAE AI Guidance — supervisory themes Attest operationalises

| CBUAE expectation (LFIs) | How Attest supports it | Product capability |
|--------------------------|------------------------|-------------------|
| **Documented AI governance framework** | Versioned policies enforced at runtime | Policy engine + `policy_decision` events |
| **Inventory of AI activity** | Trace log per workflow/model use | Provenance ingest + trace list |
| **Board / senior accountability** | Named approver on high-risk paths | Approvals queue + `approval_action` events |
| **Fairness / non-discrimination** | Institution-defined RED rules (e.g. lending) | JSON policy rules, precheck tiers |
| **Transparency / explainability** | Reasons + policy version on every decision | Precheck `reasons`; citation rules |
| **Human oversight of automated outcomes** | RED blocked by default; approval required | Precheck + dashboard (orange/red) |
| **Risk assessment, validation, controls** | Tiered risk (green/yellow/orange/red) + immutable record | `POST /v1/precheck` |

**Pitch line:** *For CBUAE-regulated LFIs, Attest operationalises supervisory themes: documented policies, human oversight for high-risk paths, traceability, and evidence packs for supervisors and internal audit — without replacing the bank’s AI risk framework.*

---

## Proof narrative (60-second demo)

1. **Proposed AI action** → precheck assigns tier; signed `policy_decision` with reasons.  
2. **RED / orange** → human approves or denies in dashboard → `approval_action` on same trace.  
3. **Action runs** (if allowed) → model/tool events chained and signed.  
4. **Auditor** → export evidence ZIP → run `verify.py` offline → all events verified.  
5. **Erasure** → crypto-shred payload → chain proves erasure occurred.

---

## What Attest is / is not

| Attest **is** | Attest **is not** |
|---------------|-------------------|
| Control + evidence layer for AI governance | A replacement for legal/compliance counsel |
| Enforcer of **your** board-approved policies | An autonomous “compliance decider” |
| Tamper-evident audit trail with external anchoring | Proof that AI outputs are true or unbiased |
| UAE-region deployment path (KMS in Phase 4) | A full GRC, DLP, or consent platform |

---

## Build status & ask

**Delivered (Weeks 1–8):** Signed hash chains, Merkle batches, RFC 3161 anchoring, replay/export, multi-tenancy, PII redaction, erasure, operator dashboard, policy precheck with four risk tiers.

**Roadmap (Weeks 9–12):** Deeper enforcement, OPA-ready policy, UAE KMS, design partner pilot.

**Ask:** One CBUAE-regulated LFI design partner to pilot on a single AI workflow (e.g. research summarisation or internal copilot).

---

## Disclaimer

Attest supports technical and governance controls **aligned with** PDPL and CBUAE AI Guidance **themes**. Compliance remains an institutional obligation. Customers must align deployment, policies, and legal processes with qualified UAE counsel. CBUAE Guidance is supervisory guidance, not statute. Free-zone entities (DIFC, ADGM) may fall outside mainland PDPL scope.

**Contact / repo:** Attest — runtime governance for AI you can prove.

---

## Regenerating the Word document

```bash
pip install python-docx   # or: pip install -r requirements-dev.txt
python scripts/generate_pitch_docx.py
```

Output: `docs/PITCH_COMPLIANCE_BRIEF.docx`
