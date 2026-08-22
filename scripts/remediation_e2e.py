"""The remediation loop, end to end, through the customer console.

The claim on trial: "we flagged it, here is the fix, here is proof the fix
shipped" — visible to the customer, not just in the database.

Run with the API on 127.0.0.1:8300 and ADMIN_API_KEY=e2e-admin-key.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import requests as rq
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BASE = "http://127.0.0.1:8300"
A = {"x-admin-key": "e2e-admin-key"}

STARTER = {
    "schema_version": 2, "engine": "json",
    "rules": [
        {"id": "personal_data_in_output", "priority": 800, "tier": "orange",
         "decision": "flag", "match": {"has_pii": True},
         "reason": "Personal data detected — review before release."},
    ],
}


def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def main() -> None:
    org_id = f"org_rem_{uuid.uuid4().hex[:8]}"
    key = rq.post(f"{BASE}/v1/admin/orgs", headers=A,
                  json={"org_id": org_id, "name": "Remediation E2E"}).json()["api_key"]
    H = {"x-api-key": key}
    rq.post(f"{BASE}/v1/admin/regulation-packs/seed", headers=A)
    rq.put(f"{BASE}/v1/policies/profile", headers=H,
           json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    rq.put(f"{BASE}/v1/policies/internal", headers=H,
           json={"name": "Internal", "version": "v1", "rules": STARTER, "activate": True})

    trace = str(uuid.uuid4())
    first = rq.post(f"{BASE}/v1/gate", headers=H, json={
        "action": "model_completion",
        "output": {"output": "Send the statement to sara.m@example.com today."},
        "trace_id": trace,
    }).json()
    ok(first["status"] == "flagged", "the PII output flags")
    fix = first["suggested_fix"]
    ok(fix and fix["revised_output"], "and the flag carries its fix")
    ok("sara.m@example.com" not in fix["revised_output"]["output"],
       "the fix actually removes the personal data")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        page = browser.new_page(viewport={"width": 1500, "height": 1100})
        errs: list[str] = []
        page.on("pageerror", lambda e: errs.append(str(e)))

        page.goto(BASE + "/console")
        page.fill("#apikey", key)
        page.click("#btn-connect")
        page.wait_for_timeout(1500)
        # A fresh org lands in onboarding; profile+policy already exist, so the
        # console should let us through to the app. Navigate to Compliance.
        page.evaluate("document.querySelector('#onboarding').style.display='none';"
                      "document.querySelector('#appui').style.display='';")
        page.click('nav.screens button[data-k="compliance"]')
        page.click("#btn-decisions")
        page.wait_for_timeout(900)

        before = page.inner_text("#decisions")
        ok("AWAITING REMEDIATION" in before,
           "an open flag says so — silence is conspicuous")
        ok("fix offered at gate time" in before, "and names the fix's shape")
        ok("sara.m@example.com" not in before,
           "the console never shows the personal data (it does not have it)")

        # The customer's code applies the fix and re-gates it.
        second = rq.post(f"{BASE}/v1/gate", headers=H, json={
            "action": "model_completion",
            "output": fix["revised_output"],
            "trace_id": trace,
            "remediates": first["decision_seq"],
        }).json()
        ok(second["status"] == "compliant", "the revised output passes")

        page.click("#btn-decisions")
        page.wait_for_timeout(900)
        after = page.inner_text("#decisions")
        ok("REMEDIATED" in after and "compliant re-check" in after,
           "the flag now reads REMEDIATED, naming the re-check that closed it")
        ok(f"FIX FOR SEQ {first['decision_seq']}" in after,
           "and the curing decision names what it fixed")

        page.screenshot(path="/tmp/remediation.png")
        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()

    # The sealed story still verifies.
    rep = rq.get(f"{BASE}/v1/trace/{trace}/replay", headers=H).json()
    ok(rep["all_verified"] is True, "the whole flagged→fixed story replays clean")

    print("\nALL REMEDIATION E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
