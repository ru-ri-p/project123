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

**`403` / `Permission denied` on push** — the token lacks *Contents: write*, is
scoped to the wrong repository, or has expired. Regenerate per step 1.

**Divergence — `Push rejected … has commits that are not in this repo`** — someone
committed directly to `project123`. The mirror deliberately does **not** force
push, so nothing is destroyed; it stops and tells you. Reconcile by fetching those
commits into `govproject01`, merging them into `main`, and re-running the mirror.
Only force push if you are certain the deploy repo holds nothing worth keeping —
it is purely a build target, so that is usually true, but make it a decision
rather than a default.

## Longer term

The mirror is a workaround for having two repos. The cleaner fix is to point
Render's `attest-api` at `shaundytradesfx/govproject01` directly and retire
`project123` — then this workflow and its token can be deleted.
