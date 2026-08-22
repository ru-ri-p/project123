#!/usr/bin/env python3
"""The law-firm demo: flagged → fix suggested → fix shipped → history sealed.

Runs one complete remediation story against a live Attest service and exports
the evidence bundle an outside party can verify with zero access to Attest.
That zip file IS the demo artifact: "we flagged it, here is the fix, here is
proof the fix shipped, and nobody can doctor that history."

Usage (creates its own throwaway org via the admin key):

    ATTEST_URL=https://attest-api-ipvl.onrender.com \\
    ADMIN_API_KEY=... \\
    python scripts/demo_remediation.py

Or against an existing org:  ATTEST_URL=... ATTEST_API_KEY=... python ...
Synthetic data only — the flagged 'client email' below is invented.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import requests as rq

URL = os.environ.get("ATTEST_URL", "http://127.0.0.1:8300").rstrip("/")
OUT = Path(os.environ.get("DEMO_OUT_DIR", "."))

STARTER = {
    "schema_version": 2, "engine": "json",
    "rules": [
        {"id": "personal_data_in_output", "priority": 800, "tier": "orange",
         "decision": "flag", "match": {"has_pii": True},
         "reason": "Personal data detected — review before release."},
    ],
}


def say(step: str, detail: str = "") -> None:
    print(f"\n=== {step}")
    if detail:
        print(detail)


def fail(msg: str) -> None:
    print(f"\nDEMO FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def make_org() -> dict[str, str]:
    admin = os.environ.get("ADMIN_API_KEY")
    if os.environ.get("ATTEST_API_KEY"):
        return {"x-api-key": os.environ["ATTEST_API_KEY"]}
    if not admin:
        fail("set ATTEST_API_KEY, or ADMIN_API_KEY to create a demo org")
    a = {"x-admin-key": admin}
    org_id = f"org_demo_rem_{uuid.uuid4().hex[:8]}"
    r = rq.post(f"{URL}/v1/admin/orgs", headers=a,
                json={"org_id": org_id, "name": "Remediation Demo"}, timeout=30)
    if r.status_code != 200:
        fail(f"could not create demo org: HTTP {r.status_code} {r.text[:200]}")
    key = r.json()["api_key"]
    h = {"x-api-key": key}
    rq.post(f"{URL}/v1/admin/regulation-packs/seed", headers=a, timeout=60)
    rq.put(f"{URL}/v1/policies/profile", headers=h, timeout=30,
           json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    rq.put(f"{URL}/v1/policies/internal", headers=h, timeout=30,
           json={"name": "Demo policy", "version": "v1",
                 "rules": STARTER, "activate": True})
    print(f"demo org: {org_id}")
    return h


def main() -> int:
    h = make_org()
    trace = str(uuid.uuid4())

    say("1 · An AI output containing personal data goes through the gate")
    bad = {"output": "Client update drafted by the model: send the quarterly "
                     "statement to sara.m@example.com before Thursday."}
    first = rq.post(f"{URL}/v1/gate", headers=h, timeout=30, json={
        "action": "model_completion", "output": bad, "trace_id": trace,
    }).json()
    if first.get("status") != "flagged":
        fail(f"expected flagged, got {first.get('status')}: {str(first)[:300]}")
    cites = sorted({f.get("pack_code") for f in first.get("findings", [])
                    if f.get("pack_code")})
    print(f"verdict: FLAGGED (decision seq {first['decision_seq']})")
    print(f"cited under: {', '.join(cites) if cites else 'own policy'}")

    say("2 · The flag arrived WITH its fix — deterministic, citations attached")
    fix = first.get("suggested_fix") or fail("no suggested_fix on the flag")
    revised = fix["revised_output"]
    if "sara.m@example.com" in str(revised):
        fail("fix did not remove the personal data")
    print(f"revised output: {revised['output'][:80]}...")
    print(f"plan hash (sealed in the signed decision): {fix['plan_hash'][:16]}…")

    say("3 · The customer's system applies the fix and re-gates it, naming "
        "the flag it cures")
    second = rq.post(f"{URL}/v1/gate", headers=h, timeout=30, json={
        "action": "model_completion", "output": revised, "trace_id": trace,
        "remediates": first["decision_seq"],
    }).json()
    if second.get("status") != "compliant":
        fail(f"expected compliant, got {second.get('status')}")
    print(f"verdict: COMPLIANT — remediation of seq {second['remediation_of']}")

    say("4 · The whole story replays clean — every hash, signature and link")
    rep = rq.get(f"{URL}/v1/trace/{trace}/replay", headers=h, timeout=30).json()
    if rep.get("all_verified") is not True:
        fail("replay failed")
    print(f"all_verified: True across {len(rep['events'])} events")

    say("5 · Exporting the evidence bundle — verifiable with zero Attest access")
    z = rq.get(f"{URL}/v1/evidence/{trace}/export?format=zip", headers=h,
               timeout=60)
    if z.status_code != 200:
        fail(f"export failed: HTTP {z.status_code}")
    out = OUT / f"attest-remediation-evidence-{trace[:8]}.zip"
    out.write_bytes(z.content)
    print(f"wrote {out}  ({len(z.content):,} bytes)")

    print(
        "\nDONE. Hand that zip to anyone: it contains the flagged decision "
        "(with the fix's sealed hash), the remediation link, the compliant "
        "re-check, and verify.py — they can prove the story unaltered on "
        "their own machine, trusting neither Attest nor the customer.\n\n"
        "What a reviewing law firm adds: the rules that flagged step 1 are "
        "drafted and labelled UNVERIFIED. Their review is what turns this "
        "demo's rulebook into a signed-off one; the machinery shown here "
        "does not change."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
