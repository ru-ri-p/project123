# Turning the TradeEasy pilot on — Attest side

Ops-side only. Do **not** forward this; `docs/TRADEEASY_QUICKSTART.md` is the
document for TradeEasy.

Pilot facts: org `org_tradeeasy_ck`, API key `attest_pilot_2h7k9m`, service
`https://attest-api-ipvl.onrender.com`. Synthetic data only. All keys get rotated
before launch.

---

## 0. Confirm the deploy is actually live

`/health` answers on stale code, so probe a field that only exists in the new
build:

```bash
curl -s -H "x-admin-key: $ADMIN_KEY" \
  "$URL/v1/admin/regulation-watch/sources" | head -c 400
```

- `next_check_at` present → new code is live.
- Field missing → the deploy is stale.
- **500** → the code shipped but migration `c7d3e4f81a25` did not run. Every
  sweep touches that column, so fix this before anything else.

Then check the pacing works against the real regulator sites:

```bash
curl -s -X POST -H "x-admin-key: $ADMIN_KEY" \
  "$URL/v1/admin/regulation-watch/run?auto_publish=false"
```

Expect `sources_checked` well below `sources_total`, a non-zero
`sources_deferred`, a `next_due_at`, and — the point of the exercise — **no 429
from difc.com**. Run it twice; the second run should pick up the *next* few
sources, not repeat the first.

Expect `auto_published: 0` every time, and do not read that as a fault. Gate 2
only confirms `provision_candidate` values a human has written, and none of the
real packs carry any yet. Today the watcher is a drift-and-dead-link detector.

## 1. Order of operations — this matters

Turning the onboarding gate on **stops recording** for an org that has no
profile. TradeEasy is already integrated from the earlier test, so gating them
first would break a working integration. The safe order:

1. Send TradeEasy `docs/TRADEEASY_QUICKSTART.md`.
2. They complete the profile in the console. This works whether or not the gate
   is on — the gate only decides whether it is *compulsory*.
3. **Verify** they did it (below).
4. *Then* flip the gate. At that point it changes nothing for them; it just locks
   the profile in so it cannot be dropped later.

## 2. Verify their profile before flipping anything

Ops dashboard → **Organisations**. The row now carries a **PROFILE** column:
`PROFILE SET` with their jurisdictions and sector count, or `NO PROFILE`.

Or:

```bash
curl -s -H "x-admin-key: $ADMIN_KEY" \
  "$URL/v1/admin/orgs?q=org_tradeeasy_ck"
```

Look for `"profile_configured": true` and `"jurisdictions": ["difc"]`.

## 3. Flip the gate

Dashboard → Organisations → **Require onboarding** on their row. The confirm
dialog tells you which case you are in: if they have no profile it warns that
recording stops immediately.

Or:

```bash
curl -s -X POST -H "x-admin-key: $ADMIN_KEY" \
  "$URL/v1/admin/orgs/org_tradeeasy_ck/require-onboarding?required=true"
```

**Rollback** is the same call with `required=false`, and it takes effect on the
next request. If they report recording failures after the flip, un-gate first and
diagnose second.

## 4. What to watch during the pilot

| Where | What you are looking for |
|---|---|
| Ops → Overview | Their events/day. A flat line after the gate flip means something broke — un-gate. |
| Ops → Access Requests | Anything you file against their data, and whether they approved it |
| Ops → Regulation Watch | Quarantined changes. A `source_gone` means a pack cites a dead URL — a real find, worth fixing. |
| Their console → Compliance | The flags they are seeing, and whether the findings are sensible |

## 5. The consent test — the part worth doing properly

The strongest demo is the one where we fail to read their data:

1. They generate a keypair under **Keys & Custody** (private key stays in their
   browser).
2. File an access request against one of their traces (Ops → File a Request).
3. Ask them to **decline** it. Confirm we still cannot read the content.
4. Then have them approve a second one, and confirm we can read *only that one
   record* — the grant re-wraps a single record's key, nothing else.

The whole ceremony — request, approval, grant — is itself recorded as signed,
chained events, so the trail shows who asked, who approved, and when. Step 3 is
the one that proves the claim; do not skip it for the happier path.

## 6. Known limitations to state up front, not when asked

- Every regulation pack is `unverified` — drafted from public sources, not
  checked line by line against the official instrument by a lawyer. The console
  labels it, and no unverified pack can block anything.
- Attest proves a record is unaltered. It never proves an output is lawful.
- Events prove **which org** acted, not **which person**. Named user identity is
  the biggest remaining trust gap and is not in this pilot.
- Dev key custody is on disk (`TODO(KMS)`), which is why the pilot is synthetic
  data only.
