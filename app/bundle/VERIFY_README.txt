Attest Evidence Bundle — Verification Instructions
==================================================

This bundle contains cryptographic proof that an AI workflow trace was recorded
and has not been altered since ingestion.

Contents (ZIP export)
---------------------
- bundle.json              Full evidence (events, Merkle proofs, anchor token)
- manifest.json            Schema version, org, signing backend metadata
- compliance_summary.json  Policy decisions, approvals, workflow gate (audit view)
- public_key.pem           Ed25519 public key used to sign events and batch roots
- verify.py                Standalone verification script (stdlib + cryptography only)
- VERIFY_README.txt        This file

Quick verify
------------
1. Unzip the evidence package (if needed).
2. Install cryptography:  pip install cryptography
3. Run:                 python verify.py bundle.json
4. Success prints:      ALL EVENTS VERIFIED
                         (plus trace summary: event count, workflow status)

Verify the external anchor (optional, recommended)
--------------------------------------------------
1. Install the RFC 3161 client:  pip install rfc3161-client
2. Obtain the trusted TSA's root certificate(s) INDEPENDENTLY (e.g. the TSA's
   published CA PEM) — do not rely on a copy supplied by the party you are
   auditing.
3. Run:  python verify.py bundle.json --tsa-roots trusted_tsa_roots.pem
   - "ANCHOR trusted: TSA=... genTime=..."  the token timestamps this exact
     batch root AND its TSA signature chains to a root you trust.
   - "ANCHOR bound: genTime=..."            (no --tsa-roots) the token
     timestamps this exact root; its TSA chain was not checked.
   - "FAIL anchor: ..."                     imprint mismatch or chain failure.

What is verified
----------------
- Each event envelope is re-hashed and matched to its stored hash
- Each event signature is validated with the bundled public key
- Hash chain links (prev_hash) are intact in sequence order
- Merkle proofs show each trace event belongs to the sealed batch root
- The batch root signature is valid
- With --tsa-roots: the RFC 3161 anchor token timestamps this batch root and
  its TSA signature chains to a TSA root you independently trust

What is NOT verified by this script
-----------------------------------
- That the customer sent every event before ingestion (integration boundary)
- That model output content is factually correct (integrity != truth)
- Legal or regulatory compliance (see compliance_summary.json pitch_note)

Signing backends
----------------
manifest.json → signing.backend:
  local  — development PEM keys (not for production)
  kms    — AWS KMS Ed25519 in UAE region (me-central-1); private key not exportable

Anchor token
------------
The anchor.token field (base64) is an RFC 3161 timestamp response over the
batch Merkle root, with the TSA signing certificate embedded. Verify it with
the --tsa-roots option above (preferred), or independently with:

  echo <root_hex> | xxd -r -p > root.bin
  openssl ts -verify -data root.bin -in token.tsr -CAfile trusted_tsa_roots.pem

Attest — tamper-evident provenance for regulated AI workflows.
