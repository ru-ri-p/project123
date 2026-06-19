# UAE KMS signing setup (Week 12 / Phase 4)

Production Attest instances should sign events and batch roots with an **Ed25519 key in AWS KMS** in the UAE region (`me-central-1`). The private key is not exportable.

## Prerequisites

- AWS account with KMS in `me-central-1`
- IAM role/user with `kms:Sign` and `kms:GetPublicKey` on the key
- `pip install -r requirements-kms.txt` on the API host

## Create the key

1. In AWS KMS (UAE region), create an **asymmetric** key:
   - Key spec: **ECC_Ed25519** (or Ed25519 where offered)
   - Key usage: **Sign and verify**
2. Note the key ARN or alias (e.g. `alias/attest-prod-signing`).

## Configure the API

```bash
# .env
ATTEST_SIGNING_BACKEND=kms
KMS_KEY_ID=alias/attest-prod-signing
KMS_REGION=me-central-1
# Optional: cache public key PEM locally (faster cold start)
# KMS_PUBLIC_KEY_PEM_PATH=keys/kms_public.pem
```

Restart the API and confirm:

```bash
curl http://127.0.0.1:8000/health
# signing_backend: kms, kms_key_id, kms_region
```

## Evidence bundles

Exported bundles include `manifest.json` → `signing.backend: kms` and `kms_key_id` so auditors know verification used the institutional KMS public key (bundled as `public_key.pem`).

## Development

Keep `ATTEST_SIGNING_BACKEND=local` (default) and PEM keys from `python scripts/generate_keys.py`.

## Other clouds

The `SigningProvider` interface is cloud-agnostic. Azure Key Vault or on-prem HSM can be added as additional backends without changing verification or `verify.py`.
