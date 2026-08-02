"""End-to-end proof of the customer console: real Chromium driving the real page,
WebCrypto in the browser interoperating with the Python server crypto.

Flow: connect -> keygen (browser) -> enable customer-key -> record 2 events (SDK
path) -> admin files scoped request -> approve IN THE BROWSER (regrant via
WebCrypto) -> admin reads exactly the approved record; out-of-scope stays 403.
"""

import sys
import uuid

import requests as rq
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8300"
ADMIN = {"x-admin-key": "e2e-admin-key"}


def make_org():
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    from app.auth import hash_api_key
    from app.db.models import Org
    from app.db.session import SessionLocal

    org_id = f"org_e2e_{uuid.uuid4().hex[:8]}"
    api_key = f"key_{uuid.uuid4().hex}"
    db = SessionLocal()
    db.add(Org(id=org_id, name="Console E2E", api_key_hash=hash_api_key(api_key)))
    db.commit()
    db.close()
    return org_id, api_key


def payload_hash(trace_id, seq):
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    from app.db.models import Event
    from app.db.session import SessionLocal

    db = SessionLocal()
    ev = db.query(Event).filter(
        Event.trace_id == uuid.UUID(trace_id), Event.seq == seq).one()
    h = ev.payload_hash
    db.close()
    return h


def main():
    org_id, api_key = make_org()
    org_h = {"x-api-key": api_key}
    def ok(cond, msg):
        print(("PASS " if cond else "FAIL ") + msg)
        if not cond:
            sys.exit(1)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(BASE + "/console")
        ok("Attest Customer Console" in page.content(), "console page served")

        # 1. Connect
        page.fill("#apikey", api_key)
        page.click("#btn-connect")
        page.wait_for_selector("#connstatus.ok", timeout=5000)
        ok(org_id in page.inner_text("#orgbadge"), "connected; org badge shows " + org_id)

        # 2. Keygen in the browser
        page.click("#btn-keygen")
        page.wait_for_selector("#keygenout", state="visible", timeout=30000)
        priv_pem = page.evaluate("keypairPems.priv")
        pub_pem = page.evaluate("keypairPems.pub")
        ok(priv_pem.startswith("-----BEGIN PRIVATE KEY-----"),
           "browser generated PKCS8 private key")
        ok(pub_pem.startswith("-----BEGIN PUBLIC KEY-----"), "browser generated SPKI public key")

        # 3. Enable customer-key mode
        page.click("#btn-enable")
        page.wait_for_selector("#enablestatus.ok", timeout=5000)
        ok(True, "customer-key mode enabled via console")

        # 4. Record two events (the SDK/app path, unchanged)
        trace = str(uuid.uuid4())
        for seq in (1, 2):
            r = rq.post(f"{BASE}/v1/event", headers=org_h, json={
                "trace_id": trace, "seq": seq, "type": "model_completion",
                "payload": {"secret": f"synthetic-{seq}"}})
            assert r.status_code == 200, r.text
        h1, h2 = payload_hash(trace, 1), payload_hash(trace, 2)
        ok(True, "two dark events recorded")

        # Server must NOT be able to read them (dark at rest)
        r = rq.post(f"{BASE}/v1/admin/access-requests", headers=ADMIN, json={
            "org_id": org_id, "payload_hashes": [h1], "reason": "e2e dispute"})
        assert r.status_code == 200, r.text
        req_id = r.json()["request_id"]
        r = rq.get(f"{BASE}/v1/admin/access-requests/{req_id}/records/{h1}", headers=ADMIN)
        ok(r.status_code == 403, "before approval: admin read -> 403")

        # 5. Approve in the browser (paste key, WebCrypto regrant)
        page.click('nav.tabs button[data-tab="requests"]')
        page.click("#btn-refresh")
        page.wait_for_selector(".req", timeout=5000)
        page.click(".req summary")
        page.wait_for_selector(".req .approver", timeout=5000)
        page.fill(".req .approver", "officer_e2e")
        page.fill(".req .keypaste", priv_pem)
        # Dismiss any lingering toast so we wait on the APPROVE toast, not a stale one.
        page.evaluate(
            "const t=document.querySelector('#toast');"
            "t.className=''; t.style.display='none'")
        page.click(".req .approve")
        page.wait_for_selector("#toast.ok >> text=Approved", timeout=15000)
        ok(True, "approved in browser (local WebCrypto key release)")

        # 6. The boundary: approved record opens, out-of-scope stays sealed
        r = rq.get(f"{BASE}/v1/admin/access-requests/{req_id}/records/{h1}", headers=ADMIN)
        ok(r.status_code == 200 and r.json()["content"] == {"secret": "synthetic-1"},
           "after approval: admin reads EXACTLY the approved record")
        r = rq.get(f"{BASE}/v1/admin/access-requests/{req_id}/records/{h2}", headers=ADMIN)
        ok(r.status_code == 403, "out-of-scope record still 403")

        # 7. Records tab: verify a trace
        page.click('nav.tabs button[data-tab="records"]')
        page.click("#btn-traces")
        page.wait_for_selector("button[data-trace]", timeout=5000)
        page.click(f'button[data-trace="{trace}"]')
        page.wait_for_selector(".chip.ok >> text=verified", timeout=15000)
        ok(True, "trace replay-verified from the console")

        ok(not errors, f"no browser JS errors (got: {errors})")
        browser.close()
    print("\nALL CONSOLE E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
