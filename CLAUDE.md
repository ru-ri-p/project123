# CLAUDE.md — operating rules for building Attest

## What Attest is
A tamper-evident AI audit layer: an SDK + API that records every AI action as a
hash-chained, Ed25519-signed, externally-anchored event, independently verifiable
by a third party. Proposed for UAE regulated-finance and government use.

## Threat model — we defend against
- External attackers, AND
- malicious/compromised insiders on BOTH the client side and our (vendor) side.
That is why records are anchored to an external timestamp authority: not even we
can forge history before an anchor.

## Non-negotiable rules
1. NEVER write secrets to code or commit them. keys/, .env, *.pem, *.key are gitignored.
2. ONE canonicalisation function (app/crypto/canonical.py), imported by both the
   write path and verify path. Never duplicate or fork its logic.
3. The break-and-detect tamper test must pass before every commit.
4. A verifier NEVER raises on bad input — it reports failure and continues.
5. Secrets and config come from environment variables, never hardcoded.
   The anchor endpoint is ANCHOR_TSA_URL (swappable to a UAE-qualified TSA).
6. Crypto primitives: SHA-256 (hashing), Ed25519 (signing), AES-256-GCM (content).
   Store a per-event algorithm id to allow future post-quantum migration.
7. Dev key custody is DISK for MVP/synthetic data ONLY. Production = KMS/HSM. Leave
   TODO(KMS) markers; never quietly treat dev custody as production-ready.

## Build order
Week 1 crypto core -> Week 2 DB+events+API+SDK+encryption -> Week 3 Merkle+anchor+
verify+tamper test -> Week 4 evidence export+verify.py+precheck+demo.

## How to work with me (the founder)
- One file or function per task. Explain security choices and failure modes.
- After writing crypto/auth code, summarise what an attacker could try and why it fails.
- Wait for my confirmation before large changes. Commit after every green test.
