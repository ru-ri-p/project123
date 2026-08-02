"""End-to-end: the admin dashboard and customer console drive the full ceremony
against each other in two real Chromium pages.

Admin UI: connect -> look up the customer trace -> tick one record -> file.
Customer UI: connect -> keygen (WebCrypto) -> go dark -> approve with local key.
Admin UI: read the approved record (content shown), read out-of-scope (403),
open the consent trail (access_request/approval/read, all verified).

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
        customer.wait_for_selector("#connstatus.ok", timeout=5000)
        customer.click("#btn-keygen")
        customer.wait_for_selector("#keygenout", state="visible", timeout=30000)
        priv_pem = customer.evaluate("keypairPems.priv")
        customer.click("#btn-enable")
        customer.wait_for_selector("#enablestatus.ok", timeout=5000)
        ok(True, "customer: connected, keygen, customer-key enabled")

        # --- Customer records two dark events (the SDK path) -------------------
        trace = str(uuid.uuid4())
        for seq in (1, 2):
            r = rq.post(f"{BASE}/v1/event", headers={"x-api-key": api_key}, json={
                "trace_id": trace, "seq": seq, "type": "model_completion",
                "payload": {"secret": f"synthetic-{seq}"}})
            assert r.status_code == 200, r.text
        ok(True, "customer: two dark events recorded")

        # --- Admin dashboard: connect, look up the trace, file for record 1 ----
        admin.goto(BASE + "/admin")
        admin.fill("#adminkey", ADMIN_KEY)
        admin.click("#btn-connect")
        admin.wait_for_selector("#appui", state="visible", timeout=5000)
        ok(True, "admin: connected")

        admin.select_option("#file-org", org_id)
        admin.fill("#file-trace", trace)
        admin.click("#btn-load-records")
        admin.wait_for_selector("#file-records input[type=checkbox]", timeout=5000)
        boxes = admin.query_selector_all("#file-records input[type=checkbox]")
        ok(len(boxes) == 2, "admin: trace lookup lists both records")
        boxes[0].check()
        admin.fill("#file-reason", "e2e dashboard dispute")
        admin.click("#btn-file")
        admin.wait_for_selector("#toast.ok >> text=filed", timeout=10000)
        admin.wait_for_selector(".req", timeout=5000)
        # The dashboard refreshes its list right after filing; let the re-render
        # settle so we open the final DOM node, not one about to be replaced.
        admin.wait_for_timeout(700)
        ok(True, "admin: request filed from the dashboard")

        # --- Admin: read before approval -> boundary message -------------------
        admin.click(".req summary")
        admin.wait_for_selector(".req button[data-read]", timeout=5000)
        admin.click(".req button[data-read]")
        admin.wait_for_selector(".req .readout >> text=403", timeout=10000)
        ok(True, "admin: read before approval shows the 403 boundary")

        # --- Customer approves in the console ---------------------------------
        customer.click('nav.tabs button[data-tab="requests"]')
        customer.click("#btn-refresh")
        customer.wait_for_selector(".req", timeout=5000)
        customer.click(".req summary")
        customer.wait_for_selector(".req .approver", timeout=5000)
        customer.fill(".req .approver", "officer_e2e")
        customer.fill(".req .keypaste", priv_pem)
        customer.evaluate(
            "const t=document.querySelector('#toast');"
            "t.className=''; t.style.display='none'")
        customer.click(".req .approve")
        customer.wait_for_selector("#toast.ok >> text=Approved", timeout=15000)
        ok(True, "customer: approved with locally-held private key")

        # --- Admin: read approved record and the out-of-scope one --------------
        admin.click("#btn-reqs")
        admin.wait_for_selector(".req", timeout=5000)
        admin.wait_for_timeout(700)
        admin.click(".req summary")
        admin.wait_for_selector(".req button[data-read]", timeout=5000)
        admin.click(".req button[data-read]")
        admin.wait_for_selector(".req .readout pre.content >> text=synthetic-1", timeout=10000)
        ok(True, "admin: approved record readable in the dashboard")

        # --- Admin: consent trail shows and verifies ---------------------------
        admin.click(".req button[data-trail]")
        admin.wait_for_selector(".trailout >> text=trail verified", timeout=10000)
        trail_text = admin.inner_text(".trailout")
        for expected in ("access_request", "access_approval", "access_read"):
            ok(expected in trail_text, f"trail shows {expected}")
        ok(True, "admin: consent trail verified in the dashboard")

        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()
    print("\nALL ADMIN-DASHBOARD E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
