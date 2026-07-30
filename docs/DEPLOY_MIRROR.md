# Deploy mirror — why it exists and how to set it up

## The problem it solves

Two repositories are in play:

| Repo | Role |
|------|------|
| `shaundytradesfx/govproject01` | **Development.** All work lands here. |
| `ru-ri-p/project123` | **Deploy target.** Render's `attest-api` service builds from this one. |

Nothing connected them, so pushes to the development repo never reached Render.
The live service kept serving an old commit while the dashboard reported a
perfectly healthy "Deploy live" — the most misleading kind of failure, because
nothing looks broken.

`.github/workflows/mirror-to-deploy-repo.yml` closes the gap: every push to
`main` here is mirrored to `main` there.

## One-time setup

### 1. Create a token that can write to the deploy repo

**You must be signed in as `ru-ri-p` for this step.** `ru-ri-p` is a *personal*
account, and there is no way around that from another account:

- a fine-grained token cannot select another personal account as Resource owner —
  it will not even be offered in the dropdown;
- adding a deploy key requires *admin* on the repository, which on a personal
  account only the owner holds (collaborators get write, never admin);
- a classic token is likewise bound to the account that issues it.

It is a one-time sign-in. Afterwards the mirror runs unattended until the token
expires.

Signed in as **`ru-ri-p`** (the owner of `project123`):

1. GitHub → your avatar → **Settings** → **Developer settings**
2. **Personal access tokens** → **Fine-grained tokens** → **Generate new token**
3. Fill in:
   - **Token name:** `attest-deploy-mirror`
   - **Expiration:** 1 year (calendar-reminder its renewal — an expired token
     makes the mirror fail, which fails loudly by design)
   - **Resource owner:** `ru-ri-p`
   - **Repository access:** *Only select repositories* → `project123`
   - **Permissions** → *Repository permissions* → **Contents: Read and write**
     (that is the only permission needed — do not grant more)
4. **Generate token** and copy it. It is shown once.

### 2. Store it as a secret in the development repo

In **`shaundytradesfx/govproject01`**:

1. **Settings** → **Secrets and variables** → **Actions**
2. **New repository secret**
   - **Name:** `MIRROR_TOKEN`
   - **Secret:** the token from step 1
3. **Add secret**

### 3. Run it once to catch up

**Actions** tab → **Mirror main to deploy repo** → **Run workflow** → run it on
`main`. This mirrors the current `main` immediately, without waiting for the next
push.

### 4. Deploy

Render has `autoDeploy: false`, so mirroring does not deploy by itself:

Render → **attest-api** → **Manual Deploy** → **Deploy latest commit**.

Confirm the Events entry now names a commit from *this* repo's `main`.

## Verifying a deploy actually took

`/health` responds even on stale code, so it proves the server is up — not that
your code shipped. Check a route that only exists in the new code:

```bash
curl -i https://attest-api-ipvl.onrender.com/v1/access-requests
# HTTP/2 401  -> consent endpoints are live (route exists, needs a key)
# HTTP/2 404  -> still an older build
```

## Failure modes

**`MIRROR_TOKEN secret is not set`** — step 2 was skipped, or the secret is named
something else. It must be exactly `MIRROR_TOKEN`, on the repository (not an
environment).

**`Repository not found` / `MIRROR_TOKEN cannot reach …`** — this is a *token
scope* problem, not a missing repository. GitHub deliberately answers `404 not
found` rather than `403 forbidden` for a private repo a token cannot see, so that
it does not leak which private repos exist. The usual cause:

> A **fine-grained** token can only reach repositories owned by its **Resource
> owner**. If `project123` belongs to a *different personal account* than the one
> you were signed in as when creating the token, that account will not even appear
> in the Resource owner dropdown — and the resulting token cannot see the repo,
> even if you are a collaborator on it.

Fixes, cheapest first:

1. **Create the token while signed in as the account that owns the repo**, with
   that account selected as Resource owner (step 1 above).
2. **Use a deploy key instead** — see *Alternative: deploy key* below. Scoped to
   exactly one repository and independent of which account issues it.
3. **Classic token** from the owning account with the `repo` scope. Works, but
   grants far more than this job needs; prefer 1 or 2.

Check a token's reach without running the workflow:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.github.com/repos/ru-ri-p/project123
# 200 -> the token can see the repo
# 404 -> it cannot (scope problem, per above)
```

**`403` / `Permission denied` on push** — the repo is reachable but the token
lacks *Contents: write*, or it has expired. Regenerate per step 1.

**Divergence — `Push rejected … has commits that are not in this repo`** — someone
committed directly to `project123`. The mirror deliberately does **not** force
push, so nothing is destroyed; it stops and tells you. Reconcile by fetching those
commits into `govproject01`, merging them into `main`, and re-running the mirror.
Only force push if you are certain the deploy repo holds nothing worth keeping —
it is purely a build target, so that is usually true, but make it a decision
rather than a default.

## Alternative: deploy key

An SSH **deploy key** attaches to the one repository rather than to a user, which
keeps its blast radius small and survives the token expiring. Note it does *not*
avoid the sign-in above: adding a deploy key needs admin on `project123`, so it
must still be done as `ru-ri-p`.

1. Generate a keypair (no passphrase, since CI must use it unattended):
   `ssh-keygen -t ed25519 -C attest-deploy-mirror -f mirror_key -N ""`
2. On `ru-ri-p/project123` → **Settings** → **Deploy keys** → **Add deploy key**:
   paste `mirror_key.pub`, and tick **Allow write access**.
3. On `shaundytradesfx/govproject01` → **Settings** → **Secrets and variables** →
   **Actions**: add the *private* key (`mirror_key`) as `MIRROR_SSH_KEY`.
4. The workflow needs a small change to load the SSH key and push over `git@`
   instead of `https://`. Ask and it can be switched over.

Then delete the local `mirror_key` files — the only copies that should persist are
the deploy key on GitHub and the secret.

## Longer term

The mirror is a workaround for having two repos. The cleaner fix is to point
Render's `attest-api` at `shaundytradesfx/govproject01` directly and retire
`project123` — then this workflow and its token can be deleted.
