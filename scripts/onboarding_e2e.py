"""The fresh-customer journey, exactly as TradeEasy would meet it.

A brand-new org with nothing set up: does the console TELL them what to do, and
can they finish setup themselves without a terminal?

  connect -> told they have no policy (on Overview and Compliance)
          -> one click creates a starter policy
          -> adopt DIFC Regulation 10 from the picker
          -> precheck now works and shows a cited DIFC finding

Also checks the failure they'd otherwise hit blind: precheck with no policy must
return an actionable message, not a bare 404.

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
ADMIN_KEY = "e2e-admin-key"


def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def main() -> None:
    # Attest publishes the rulebooks once (ops side). Nothing else is pre-set.
    rq.post(f"{BASE}/v1/admin/regulation-packs/seed", headers={"x-admin-key": ADMIN_KEY})

    org_id = f"org_onb_{uuid.uuid4().hex[:8]}"
    api_key = rq.post(
        f"{BASE}/v1/admin/orgs", headers={"x-admin-key": ADMIN_KEY},
        json={"org_id": org_id, "name": "TradeEasy DMCC"},
    ).json()["api_key"]

    # The dead end they must NOT hit silently.
    r = rq.post(f"{BASE}/v1/precheck", headers={"x-api-key": api_key}, json={
        "trace_id": str(uuid.uuid4()), "seq": 1, "action": "model_completion",
        "payload": {"output": "x"}})
    ok(r.status_code == 409, f"precheck with no policy -> 409 (got {r.status_code})")
    detail = r.json()["detail"]
    ok("Compliance screen" in detail and "starter policy" in detail,
       "the error tells them how to fix it")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        errs: list[str] = []
        page.on("pageerror", lambda e: errs.append(str(e)))

        page.goto(BASE + "/console")
        page.fill("#apikey", api_key)
        page.click("#btn-connect")
        page.wait_for_selector("#orgbadge", state="visible", timeout=6000)

        # Landing page tells them setup is incomplete.
        page.wait_for_selector("#ov-policybanner", state="visible", timeout=8000)
        ok(True, "overview warns that no policy is active")

        # Compliance screen says the same, prominently, with a way out.
        page.click("#ov-gotocompliance")
        page.wait_for_selector("#setup-needed", state="visible", timeout=8000)
        ok("no active policy" in page.inner_text("#setup-needed").lower(),
           "compliance screen explains the missing policy")
        page.wait_for_selector("#jurisdiction-nudge", state="visible", timeout=5000)
        ok("DIFC" in page.inner_text("#jurisdiction-nudge"),
           "compliance screen suggests DIFC when nothing is adopted")

        # One click creates their policy.
        page.click("#btn-starter-policy")
        page.wait_for_selector("#toast.ok >> text=Starter policy published", timeout=10000)
        page.wait_for_selector("#setup-needed", state="hidden", timeout=8000)
        ok(True, "one click published a starter policy; the prompt clears")

        # They adopt DIFC themselves from the picker.
        page.select_option("#avail-packs", "difc_dp_reg10")
        page.evaluate(
            "const t=document.querySelector('#toast'); t.className=''; t.style.display='none'")
        page.click("#btn-adopt")
        page.wait_for_selector("#toast.ok >> text=adopted", timeout=10000)
        page.wait_for_selector("#mypacks >> text=Regulation 10", timeout=10000)
        ok(True, "customer adopted DIFC Regulation 10 themselves")

        # Now their app's precheck works, and the finding is cited on screen.
        r = rq.post(f"{BASE}/v1/precheck", headers={"x-api-key": api_key}, json={
            "trace_id": str(uuid.uuid4()), "seq": 1, "action": "model_completion",
            "payload": {"output": "declined", "_classifier_tier": "discriminatory_lending"}})
        ok(r.status_code == 200, f"precheck now succeeds (got {r.status_code})")
        body = r.json()
        ok(body["jurisdictions"] == ["difc"], "decision attributed to DIFC")
        ok(body["allowed"] is True, "advisory finding did not block")

        page.click("#btn-decisions")
        page.wait_for_selector("#decisions >> text=Regulation 10", timeout=10000)
        dec = page.inner_text("#decisions")
        ok("ADVISORY — DID NOT BLOCK" in dec, "finding shown as advisory on their dashboard")

        # A wire transfer hits THEIR OWN rule, which is the only thing that blocks.
        r = rq.post(f"{BASE}/v1/precheck", headers={"x-api-key": api_key}, json={
            "trace_id": str(uuid.uuid4()), "seq": 1, "action": "wire_transfer",
            "payload": {"amount": 1000}})
        ok(r.status_code == 200 and r.json()["allowed"] is False,
           "their own starter policy DOES block a wire transfer")

        page.screenshot(path="/tmp/onboarding_after.png")
        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()
    print("\nALL ONBOARDING E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
