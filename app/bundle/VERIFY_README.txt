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

What is verified
----------------
- Each event envelope is re-hashed and matched to its stored hash
- Each event signature is validated with the bundled public key
- Hash chain links (prev_hash) are intact in sequence order
- Merkle proofs show each trace event belongs to the sealed batch root
- The batch root signature is valid

What is NOT verified by this script
-----------------------------------
- RFC 3161 TSA token validation (requires openssl ts or TSA CA certs)
- That the customer sent every event before ingestion (integration boundary)
- That model output content is factually correct (integrity ≠ truth)
- Legal or regulatory compliance (see compliance_summary.json pitch_note)

Signing backends
----------------
manifest.json → signing.backend:
  local  — development PEM keys (not for production)
  kms    — AWS KMS Ed25519 in UAE region (me-central-1); private key not exportable

Anchor token
------------
The anchor.token field (base64) is an RFC 3161 timestamp response over the
batch Merkle root. Verify offline with:

  echo <root_hex> | xxd -r -p > root.bin
  # use openssl ts -verify with the token and TSA certificates

Attest — tamper-evident provenance for regulated AI workflows.
