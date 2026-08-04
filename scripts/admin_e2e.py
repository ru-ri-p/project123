"""End-to-end: the ops dashboard and customer console drive the full ceremony
against each other in two real Chromium pages (new light "ledger" design).

Admin UI: connect -> File a Request (org card, trace fetch, tick record, reason)
-> read shows the 403 boundary. Customer UI: connect -> keygen -> go dark ->
approve with local key. Admin UI: read approved record, open + verify the
consent trail.

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
    org_id = f"org_admui_{uuid.uuid4().hex[:8]}"
    api_key = (
        rq.post(f"{BASE}/v1/admin/orgs", headers={"x-admin-key": ADMIN_KEY},
                json={"org_id": org_id, "name": "Admin E2E"}).json()["api_key"]
    )

    rq.put(f"{BASE}/v1/policies/profile", headers={"x-api-key": api_key},
           json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        admin = browser.new_page()
        customer = browser.new_page()
        errs: list[str] = []
        admin.on("pageerror", lambda e: errs.append("admin: " + str(e)))
        customer.on("pageerror", lambda e: errs.append("customer: " + str(e)))

        # --- Customer: connect, keygen, go dark --------------------------------
        customer.goto(BASE + "/console")
        customer.fill("#apikey", api_key)
        customer.click("#btn-connect")
        customer.wait_for_selector("#orgbadge", state="visible", timeout=5000)
        customer.click('nav.screens button[data-k="keys"]')
        customer.click("#btn-keygen")
        customer.wait_for_selector("#keygenout", state="visible", timeout=30000)
        priv_pem = customer.evaluate("keypairPems.priv")
        customer.click("#btn-enable")
        # Going dark hides the setup card by design; assert the real end state.
        customer.wait_for_selector("#keycustody >> text=ACTIVE", timeout=10000)
        ok(True, "customer: connected, keygen, customer-key enabled")

        # --- Customer records two dark events (the SDK path) -------------------
        trace = str(uuid.uuid4())
        for seq in (1, 2):
            r = rq.post(f"{BASE}/v1/event", headers={"x-api-key": api_key}, json={
                "trace_id": trace, "seq": seq, "type": "model_completion",
                "payload": {"secret": f"synthetic-{seq}"}})
            assert r.status_code == 200, r.text
        ok(True, "customer: two dark events recorded")

        # --- Admin dashboard: connect (key state box goes 'loaded') ------------
        admin.goto(BASE + "/admin")
        admin.fill("#gate-key", ADMIN_KEY)
        admin.click("#gate-connect")
        admin.wait_for_selector("#appui", state="visible", timeout=8000)
        admin.wait_for_selector("#keybox.loaded", timeout=5000)
        ok(True, "admin: connected — key state loaded")

        # --- Admin: File a Request flow ---------------------------------------
        admin.click('nav.screens button[data-k="file"]')
        # The org list grows with every run, so wait for OUR button, confirm the
        # selection actually took, and allow for a slower render.
        admin.wait_for_selector(f'button[data-org="{org_id}"]', timeout=15000)
        admin.click(f'button[data-org="{org_id}"]')
        admin.wait_for_selector(f'button[data-org="{org_id}"].on', timeout=10000)
        admin.fill("#file-trace", trace)
        admin.click("#btn-fetch")
        admin.wait_for_selector("[data-rec]", timeout=15000)
        boxes = admin.query_selector_all("#file-records [data-rec]")
        ok(len(boxes) == 2, "admin: trace fetch lists both records")
        boxes[0].click()
        reason = f"e2e dashboard dispute {org_id} — DFSA sampling"
        admin.fill("#file-reason", reason)
        admin.wait_for_selector("#btn-file:not([disabled])", timeout=3000)
        admin.click("#btn-file")
        admin.wait_for_selector("#file-done", state="visible", timeout=10000)
        ok(True, "admin: request filed from the dashboard")
        admin.click("#btn-file-view")

        # --- Admin: read before approval -> boundary message -------------------
        admin.select_option("#filter-status", "pending")
        ours = f'[data-open]:has-text("{org_id}")'
        admin.wait_for_selector(ours, timeout=5000)
        admin.click(ours)
        admin.wait_for_selector("[data-read]", timeout=5000)
        admin.click("[data-read]")
        admin.wait_for_selector(".readout >> text=403", timeout=10000)
        ok(True, "admin: read before approval shows the 403 boundary")

        # --- Customer approves in the console ---------------------------------
        customer.click('nav.screens button[data-k="requests"]')
        customer.click("#btn-refresh")
        customer.wait_for_selector("[data-open]", timeout=5000)
        customer.click("[data-open]")
        customer.wait_for_selector(".approver", timeout=5000)
        customer.click('[data-rec="0"]')
        customer.fill(".approver", "officer_e2e")
        customer.fill(".keypaste", priv_pem)
        customer.evaluate(
            "const t=document.querySelector('#toast');"
            "t.className=''; t.style.display='none'")
        customer.click(".approve")
        customer.wait_for_selector("#toast.ok >> text=Approved", timeout=15000)
        ok(True, "customer: approved with locally-held private key")

        # --- Admin: read approved record ---------------------------------------
        admin.click("#btn-back")
        admin.select_option("#filter-status", "approved")
        admin.wait_for_selector(ours, timeout=10000)
        admin.click(ours)
        admin.wait_for_selector("[data-read]", timeout=5000)
        admin.click("[data-read]")
        admin.wait_for_selector(".readout >> text=synthetic-1", timeout=10000)
        ok(True, "admin: approved record readable in the dashboard")

        # --- Admin: consent trail renders and verifies -------------------------
        admin.wait_for_selector("#trailbox >> text=ACCESS_REQUEST", timeout=10000)
        trail_text = admin.inner_text("#trailbox")
        for expected in ("ACCESS_REQUEST", "ACCESS_APPROVAL", "ACCESS_READ"):
            ok(expected in trail_text, f"trail shows {expected}")
        admin.click("#btn-verify-detail")
        admin.wait_for_selector("#trail-verdict >> text=TRAIL VERIFIED", timeout=15000)
        ok(True, "admin: consent trail verified in the dashboard")

        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()
    print("\nALL ADMIN-DASHBOARD E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
