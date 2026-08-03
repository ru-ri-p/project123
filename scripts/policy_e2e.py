"""End-to-end: the jurisdiction layer, driven through both dashboards.

Admin UI: publish starter packs -> apply DIFC Regulation 10 to the customer.
Customer UI: see the applied rulebook with its citation and UNVERIFIED label,
author its own policy, then (via the precheck API, as its app would) trip a DIFC
fairness rule and see the finding — cited, advisory, and explicitly not blocking.

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
    org_id = f"org_pol_{uuid.uuid4().hex[:8]}"
    api_key = rq.post(
        f"{BASE}/v1/admin/orgs", headers={"x-admin-key": ADMIN_KEY},
        json={"org_id": org_id, "name": "Policy E2E DIFC"},
    ).json()["api_key"]

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        admin = browser.new_page()
        customer = browser.new_page()
        errs: list[str] = []
        admin.on("pageerror", lambda e: errs.append("admin: " + str(e)))
        customer.on("pageerror", lambda e: errs.append("customer: " + str(e)))

        # --- Admin: the console must be gated before anything is clickable ----
        admin.goto(BASE + "/admin")
        admin.wait_for_selector("#gate", state="visible", timeout=5000)
        ok(not admin.is_visible("#appui"), "admin: dashboard gated until a key is presented")
        ok(not admin.is_visible("#btn-seed"), "admin: actions unreachable while ungated")
        admin.fill("#gate-key", "wrong-key")
        admin.click("#gate-connect")
        admin.wait_for_selector("#gate-msg >> text=rejected", timeout=8000)
        ok(admin.is_visible("#gate"), "admin: a rejected key keeps the gate up with a clear message")

        # --- Admin: publish packs and apply DIFC Reg 10 to the customer --------
        admin.fill("#gate-key", ADMIN_KEY)
        admin.click("#gate-connect")
        admin.wait_for_selector("#appui", state="visible", timeout=8000)
        admin.wait_for_selector("#keybox.loaded", timeout=5000)
        admin.click('nav.screens button[data-k="packs"]')
        admin.click("#btn-seed")
        admin.wait_for_selector("#packlist >> text=DIFC", timeout=15000)
        ok(True, "admin: starter packs published")

        packs_text = admin.inner_text("#packlist")
        ok("UNVERIFIED" in packs_text, "admin: packs are labelled UNVERIFIED")
        for j in ("DIFC", "ADGM", "UAE ONSHORE"):
            ok(j in packs_text, f"admin: {j} jurisdiction listed")

        admin.select_option("#pack-org", org_id)
        admin.select_option("#pack-code", "difc_dp_reg10")
        admin.click("#btn-subscribe")
        admin.wait_for_selector("#orgpacks >> text=ADVISORY", timeout=10000)
        ok(True, "admin: DIFC Regulation 10 applied to the customer (advisory)")

        # --- Customer: sees the rulebook, authors its own policy --------------
        customer.goto(BASE + "/console")
        customer.fill("#apikey", api_key)
        customer.click("#btn-connect")
        customer.wait_for_selector("#orgbadge", state="visible", timeout=5000)
        customer.click('nav.screens button[data-k="compliance"]')
        customer.click("#btn-mypacks")
        customer.wait_for_selector("#mypacks >> text=Regulation 10", timeout=10000)
        mine = customer.inner_text("#mypacks")
        ok("UNVERIFIED" in mine, "customer: rulebook shows its UNVERIFIED status")
        ok("ADVISORY" in mine, "customer: rulebook shows it is advisory")

        customer.click("#btn-load-policy")
        customer.wait_for_selector("#toast", state="visible", timeout=10000)
        customer.fill("#pol-version", "v1")
        customer.fill("#pol-name", "TradeEasy internal AI policy")
        customer.fill(
            "#pol-rules",
            '{"schema_version":2,"engine":"json","rules":[]}',
        )
        customer.evaluate(
            "const t=document.querySelector('#toast'); t.className=''; t.style.display='none'")
        customer.click("#btn-save-policy")
        customer.wait_for_selector("#toast.ok >> text=published", timeout=10000)
        ok(True, "customer: authored and activated its own policy")

        # --- The customer's app calls precheck; a DIFC rule fires -------------
        trace = str(uuid.uuid4())
        r = rq.post(f"{BASE}/v1/precheck", headers={"x-api-key": api_key}, json={
            "trace_id": trace, "seq": 1, "action": "model_completion",
            "payload": {"output": "declined", "_classifier_tier": "discriminatory_lending"},
        })
        ok(r.status_code == 200, f"precheck accepted ({r.status_code})")
        body = r.json()
        ok(body["tier"] == "red", "precheck: DIFC fairness rule raised the tier to red")
        ok(body["allowed"] is True, "precheck: advisory finding did NOT block the action")
        ok(body["jurisdictions"] == ["difc"], "precheck: attributed to DIFC")

        # --- Customer sees the finding, cited, on the dashboard ---------------
        customer.click("#btn-decisions")
        customer.wait_for_selector("#decisions >> text=RED", timeout=10000)
        dec = customer.inner_text("#decisions")
        ok("DIFC" in dec, "customer: finding attributed to DIFC on screen")
        ok("Regulation 10" in dec, "customer: instrument cited on screen")
        ok("ADVISORY — DID NOT BLOCK" in dec, "customer: advisory nature shown on screen")
        ok("UNVERIFIED" in dec, "customer: verification status shown on screen")

        customer.click("#btn-mypacks")
        customer.wait_for_timeout(400)
        ok(True, "customer: compliance screen refreshes cleanly")

        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()
    print("\nALL POLICY E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
