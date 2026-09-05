# Security & operations

This is the working security posture of Attest, written so a customer's
security reviewer can read it and so we answer the same questions the same way
every time. It is honest about what is done and what is still open.

## Reporting a vulnerability
Email security@ (set this alias up when the domain lands). Do not open a public
issue for a suspected vulnerability. We aim to acknowledge within 2 business
days.

## What is in place

### Cryptographic core
- Every recorded event is canonicalised by ONE function
  (`app/crypto/canonical.py`, imported by both write and verify paths),
  SHA-256 hashed, Ed25519 signed, hash-chained to its predecessor, Merkle
  batched, and anchored to an external RFC-3161 timestamp authority.
- A per-event algorithm id is stored, so a post-quantum migration never has to
  reinterpret old events.
- Evidence bundles verify offline with a standalone `verify.py`; a verifier
  never raises on bad input — it reports failure and continues.

### Authentication & sessions
- Human login is email + password. Passwords are stored only as Argon2id
  hashes (memory-hard); the password itself never touches a log, event, or
  column. Minimum length 12, no composition theatre (NIST 800-63B).
- One-time codes (invitation / reset) are stored as SHA-256, single-use,
  expiring, attempt-capped, issuance-capped, and never confirm whether an
  email has an account (no user enumeration). Timing is equalised so an
  unknown email is indistinguishable from a wrong password.
- Per-account lockout after repeated failures, stored durably in the database.
- Session tokens are 256-bit, stored hashed, expiring, and revocable
  server-side. Changing a password revokes every other session.
- Approvals record the resolver's VERIFIED identity (`approver_kind:
  authenticated`) vs a name merely asserted over the machine key
  (`asserted`) — the distinction is sealed in the signed event.
- Machine access is the org API key (shown once, stored only as a hash).

### Authorisation
- Roles: admin / officer / viewer. Viewer sessions are read-only, enforced
  server-side (not just hidden buttons).
- Only the customer's own policy can BLOCK an output; jurisdiction rulebooks
  are advisory and can never turn an allow into a deny. Cross-org access is
  refused (a signed-in user only ever resolves to their own org).

### Web tier
- Security headers on every response: CSP, HSTS (HTTPS only), X-Frame-Options
  DENY, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy
  (`app/middleware/security_headers.py`).
- Rate limiting per API key.
- Secrets come only from environment variables; `keys/`, `.env`, `*.pem`,
  `*.key` are gitignored and never committed.

### Testing
- 270+ tests, most written as attacks (cross-org reach, session theft, code
  brute-forcing, enumeration, tamper detection). The break-and-detect tamper
  test must pass before every commit.

## Data residency
The API and its PostgreSQL database run on Render. A customer using
`confidentiality_mode: customer_key` holds their own content-encryption key:
stored content is dark to Attest until they release a key through the consent
ceremony, so even our own operators — and our hosting provider — cannot read
it at rest. The signed metadata (hashes, decisions, tiers) is enough to run
the compliance dashboards and prove integrity without reading content.
For a customer requiring a specific region, Render offers regional
deployments; a UAE-region or on-premise deployment is a deliberate later step,
not automatic — raise it in contracting.

## Known gaps (tracked, not hidden)

| Gap | Plan |
|-----|------|
| `requirements.txt` uses `>=` ranges | Dependabot + `pip-audit` are wired now; move to a hash-pinned lockfile before customer #2. |
| CSP allows `'unsafe-inline'` for the console/login pages | The pages ship inline script/style + data: fonts today; tighten with nonces or hashes in a later pass. |
| No breached-password screening | Add a k-anonymity check (HaveIBeenPwned range API or a bundled offline corpus) at password-set time. |
| Email delivery not configured | Needs a sending domain with SPF/DKIM; until then codes are dev-mode only and production login uses admin-set passwords. |
| Dev key custody is on disk | MVP / synthetic data only. Production = KMS/HSM. `TODO(KMS)` markers are in the signing provider. |
| MFA / SSO (SAML) | Session infrastructure is ready; build when a procurement checklist requires it. |
| Backups not yet scheduled | Add a scheduled PostgreSQL backup with a tested restore. |
| Uptime / error monitoring | Add an uptime check + error tracking (e.g. Sentry) and a status page. |

## Dependency hygiene
- `.github/dependabot.yml` opens weekly update PRs for pip and GitHub Actions,
  and out-of-band security-alert PRs once Dependabot alerts are enabled in
  repo settings.
- Run `pip-audit` locally / in CI to fail on a dependency with a known CVE:
  ```
  pip install pip-audit && pip-audit -r requirements.txt
  ```
- Keep the runtime surface minimal — the SDK depends only on `requests`; the
  console is dependency-free static HTML. Adding a package means trusting its
  whole chain; do it deliberately.

## Incident runbook (first thirty minutes)

**Leaked org API key** — rotate it: `POST /v1/admin/orgs/{org_id}/rotate-key`
(admin key). The old key stops working immediately; the org updates its SDK
config. Record the rotation reason. Past events stay valid (they were signed
by the server key, not the API key).

**Leaked ADMIN_API_KEY** — change `ADMIN_API_KEY` on Render and redeploy. This
key gates org creation and access review; treat its leak as urgent.

**Suspected DB compromise** — passwords (Argon2id), session tokens and login
codes (SHA-256) are useless to a reader. Signed events cannot be forged
(server key is separate) and cannot be altered undetectably (anchored chain).
Rotate the server signing key (`scripts/generate_keys.py` + KMS in prod;
retired keys keep verifying what they signed), force-expire sessions, and run
a full `replay` over recent traces to confirm no tampering.

**Deploy served stale code** — the dev→main→mirror→Render pipeline can leave
Render behind. Check the Actions "Mirror" run is green, then Manual Deploy the
latest commit; confirm with the dress rehearsal (`scripts/dress_rehearsal.py`)
against the live URL. See `docs/DEPLOY_MIRROR.md`.

**Dependency CVE alert** — read the Dependabot PR, run the test suite against
it, merge, then deploy. Do not merge a major-version bump without reading its
changelog.
