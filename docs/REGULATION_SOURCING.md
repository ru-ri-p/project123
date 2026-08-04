# Regulation packs — sourcing and verification

## The rule

**Attest enforces rules. Attest does not determine legality.**

A speed camera does not set the speed limit. The institution, advised by its
lawyers, writes down its interpretation of its obligations; Attest applies that
interpretation to every AI action without exception and proves it did. Nothing in
this system may be described to a customer or a regulator as a determination that
an action was lawful.

That framing is also what makes the feature valuable: because every rule carries
a citation and packs are versioned, you can show *which rulebook was live at the
moment of a decision, who adopted it, and that nobody edited it afterwards.*

## Verification status

Every pack carries one, and it travels with every finding it produces:

| Status | Meaning |
|---|---|
| `unverified` | Drafted from publicly reported summaries. **Not** checked against the official text. |
| `self_reviewed` | Checked in-house, line by line, against the official instrument. |
| `counsel_reviewed` | Signed off by a qualified lawyer, with the reviewer recorded. |

**Everything currently shipped is `unverified`.** The UI labels it as such, and
`subscribe_org` refuses `blocking` enforcement outright — an unreviewed rule that
could halt a customer's business is a liability, not a feature.

## Why the packs are thin, and what is missing

The build environment's egress policy blocks the primary sources:

```
connect_rejected - www.difc.com:443
connect_rejected - dfsaen.thomsonreuters.com:443
connect_rejected - www.adgm.com:443
```

So the official texts could not be read. Rather than invent article numbers to
fill the gap, rules cite the **instrument** (which is well attested across
multiple independent sources) and leave `provision` as `None` wherever an exact
article or section number could not be confirmed. A rules engine that cites
clauses it cannot evidence is worse than one that admits what it has not checked.

### What each pack still needs

| Pack | State | Needed |
|---|---|---|
| `difc_dp_reg10` | 3 rules, instrument-level citations | Exact provision numbers; the High-Risk System criteria; the Autonomous Systems Officer trigger; the precise notice wording duty |
| `difc_dp_law_5_2020` | 2 rules, instrument-level citations | Article numbers for High Risk Processing Activities, DPIA, and transfers out of the DIFC; the adequacy list |
| `adgm_dp_regs` | **stub, no rules** | Everything |
| `uae_onshore_core` | 2 rules carried over from the old reference policy | Verification against the federal PDPL and the CBUAE Rulebook; SCA coverage |

## Why DIFC first

DIFC Data Protection **Regulation 10** governs personal data processed through
autonomous and semi-autonomous systems — i.e. AI. It introduces a *Deployer* who
is treated as controller, an *Autonomous Systems Officer* for high-risk systems,
transparency duties toward data subjects, fairness/non-discrimination duties, and
**evidence-of-compliance record-keeping**. It came into force on 1 September 2023
and is reported to have moved to full enforcement from 1 January 2026.

That last duty — retained evidence that the obligations were met — is precisely
what Attest produces. It is the closest thing in the region to an AI-governance
rulebook, and the strongest reason to lead with DIFC.

## How the watcher paces itself

The first live sweep asked every registered source for its page at once. Two
packs cite `difc.com`, and difc.com answered **HTTP 429**. A rate limit tells us
nothing about the law, so the fix was to stop provoking one.

Spacing happens in two places, because "all at once" was true in two ways:

| Where | What | Env var (default) |
|---|---|---|
| Within a run | Minimum gap between requests to the **same host**. Per host, not global — the constraint belongs to the site. | `REGWATCH_HOST_DELAY_SECONDS` (6) |
| Within a run | Retry on 429/5xx, honouring `Retry-After`, capped so a cron never sleeps for an hour | `REGWATCH_MAX_RETRIES` (2) |
| Across runs | A run only checks sources that are **due**, and at most a few | `REGWATCH_MAX_SOURCES_PER_RUN` (3) |
| Across runs | How long a source stays fresh once checked | `REGWATCH_CHECK_INTERVAL_SECONDS` (86400) |

A source is scheduled **before** its fetch, so a source that fails — blocked,
gone, unreachable — is still put to the back of the queue rather than retried on
every run. A never-checked source sorts first, so a newly registered pack is
picked up on the very next run instead of waiting out an interval it was never
part of.

The dashboard's *Run sweep now* therefore checks a handful of due sources, not
everything, and says so: "Checked 3 of 8 source(s)… 5 still due. Next due …".
The scheduled job (`scripts/watch_regulations.py`) defaults to no cap, since a
cron has the wall clock to spare and the per-host pacing keeps it polite anyway.

## How to promote a pack

1. Obtain the official text from the source URL recorded on the pack.
2. Check every rule against it. Fill in `provision`. Correct or delete rules that
   do not hold.
3. Record the reviewer (`reviewed_by`, `reviewed_at`) and raise
   `verification_status`.
4. Publish as a **new version** — never edit a published version in place, or the
   record of what was live on a given date stops being true.
5. Only then consider `blocking` enforcement, and only per pack.

## Internal policy is the customer's

Regulation packs are Attest's. The institution's **own** policy is authored by the
institution via `PUT /v1/policies/internal` and is the only thing that can deny an
action. Attest supplies no template and takes no view on its content.
