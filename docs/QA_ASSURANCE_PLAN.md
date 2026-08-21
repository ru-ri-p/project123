# QA / assurance plan — how we know the record is complete and true

"Are ALL of a customer's AI actions evaluated and recorded, with proof?" splits
into two claims with two different proof methods. Conflating them is how audit
products end up overclaiming; keeping them apart is how this one stays
defensible.

| Claim | Proof method | Who can prove it |
|---|---|---|
| **Integrity** — everything that reached Attest was evaluated, recorded, and has not been altered since | Cryptography (hash chain, signatures, external anchors) | Anyone, independently |
| **Completeness** — everything the customer's AI did actually reached Attest | Reconciliation against an independent source + canaries | Only the customer and Attest *together* |

Attest can never prove completeness alone: no system can see events that were
never sent to it. The honest architecture is to make the integrity claim
absolute and the completeness claim *measurable* — which is what auditors do
with financial ledgers, and what this plan does here.

## The exact integrity guarantee (state it precisely)

- Within a trace, events are hash-chained with server-assigned sequence
  numbers: altering, deleting or reordering any event is detected on replay,
  and the offending event is named.
- Events are Merkle-batched and the roots anchored to an external RFC-3161
  authority: after anchoring, history cannot be rewritten **by anyone,
  including Attest**.
- The boundary: between an event's recording and its batch's anchoring there
  is a window in which a malicious Attest could in principle drop a whole
  unanchored trace. The window is measurable (see anchor lag below) and should
  be kept short. This is why anchor cadence is a QA metric, not a detail.
- Offline (outage) events are additionally signed by the customer's own device
  key with a per-device chain — a gap in a device chain is detectable, and the
  customer holds independent evidence of what they submitted.

## Completeness: the three mechanisms

**1. Architecture — one choke point.** Coverage by per-developer discipline
fails silently. Coverage by architecture cannot: route every model call through
a single internal gateway, and put the one `gate()` call inside it. Then a new
AI workflow is covered by construction, not by someone remembering. This is the
single strongest recommendation to make to any customer.

**2. Workflow tagging — make silence conspicuous.** The `action` field is
free-form. Have the customer tag each workflow (`chat_completion`,
`trade_summary`, `client_report`…). Then per-workflow counts exist on both
sides, and a wired-but-silent workflow shows up as a zero instead of vanishing
into an aggregate.

**3. Reconciliation — the completeness test itself.** The customer's model
usage is independently countable (LLM provider dashboard/invoice, gateway
logs). Attest's record count is queryable. Expected relationship:

    events ≈ 2 × gated outputs   (each gate() records a decision + an output)

Any shortfall is uncovered activity, quantified. Run weekly during a pilot.

## The test battery

Integrity tests (run on demand; the customer can run most themselves):

- **T1 Tamper-alter**: change one stored event's hash or payload in the
  database, replay → `all_verified: false`, exact seq named.
- **T2 Tamper-delete**: delete a mid-chain event → replay detects the broken
  chain.
- **T3 Tamper-reorder**: swap two events' seq → detected.
- **T4 Independent verify**: export the evidence bundle, run `verify.py` on a
  machine with no Attest access, including `--tsa-roots` for the anchor.
- **T5 Outage completeness**: sever connectivity, gate K outputs, restore →
  exactly K deferred events grafted, each carrying the device signature and
  both timestamps.
- **T6 Concurrency exactly-once**: N parallel gate() calls → exactly N
  decision+output pairs, no drops, no duplicates.

Completeness tests (require the customer's participation — by design):

- **T7 Reconciliation**: for one day, customer counts model invocations from
  their own logs/provider; compare with Attest's per-org event count ÷ 2.
  Target: 100% of *wired* workflows; the delta is the unwired estate,
  quantified.
- **T8 Canary sweep**: customer fires one marked synthetic output through
  *every workflow they claim is integrated*; verify every marker appears in
  Audit Records within minutes.
- **T9 Negative control**: fire one output through a path deliberately NOT
  wired; confirm it does NOT appear. This validates that T7/T8 can actually
  detect a gap — a completeness test that cannot fail is not a test.

## QA metrics (measure continuously, review weekly)

| Metric | Meaning | Where it lives today |
|---|---|---|
| Coverage ratio | recorded outputs ÷ independently counted outputs | T7, manual — build a screen later |
| Recording success rate | gate() answered vs errored | SDK/status codes; server logs |
| Deferred fraction | % of events arriving via outage queue | `deferred` flag on events |
| Anchor lag | events not yet externally anchored, and for how long | `/v1/admin/stats`: `unbatched_events`, `pending_batches`, `last_anchor_at` |
| Verification pass rate | % of traces that replay clean | per-trace replay — **no scheduled job yet, see gaps** |
| Gate latency p95 | customer-facing cost of the call | not yet surfaced |
| Unevaluated rate | outputs recorded with no policy to judge them | decision summaries |

Thresholds for a healthy pilot: coverage ≥ 99% of wired workflows, deferred
fraction near zero outside real outages, anchor lag under the batch cadence,
verification pass rate exactly 100% (a single failure is an incident, not a
statistic).

## Known gaps (build items, honestly stated)

1. **Nightly self-verification cron** — replay every trace and alert on any
   failure. Today verification is on-demand; continuous is better. Cheap to
   build.
2. **Reconciliation surface** — per-workflow (action-tag) daily counts on both
   dashboards, so T7 becomes a glance instead of a spreadsheet.
3. **Coverage attestation** — customer declares their AI workflows; Attest
   shows declared-vs-observed. Turns the completeness conversation into a
   standing report. Post-pilot.
