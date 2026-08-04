"""First run: a brand-new customer is walked through onboarding before recording.

  1. The SDK is refused with an actionable 409 — and does NOT buffer it, because
     a setup problem must not masquerade as an outage.
  2. The console shows an onboarding wizard instead of the dashboard.
  3. Two steps: declare the profile, publish a starter policy.
  4. Recording works immediately afterwards.

Run with the API on 127.0.0.1:8300 and ADMIN_API_KEY=e2e-admin-key.
"""

from __future__ import annotations

import sys
import tempfile
import uuid
from pathlib import Path

import requests as rq
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attest_sdk import AttestClient  # noqa: E402

BASE = "http://127.0.0.1:8300"
ADMIN_KEY = "e2e-admin-key"


def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def main() -> None:
    rq.post(f"{BASE}/v1/admin/regulation-packs/seed", headers={"x-admin-key": ADMIN_KEY})
    org_id = f"org_first_{uuid.uuid4().hex[:8]}"
    api_key = rq.post(f"{BASE}/v1/admin/orgs", headers={"x-admin-key": ADMIN_KEY},
                      json={"org_id": org_id, "name": "Brand New Bank"}).json()["api_key"]

    # --- 1. The SDK is refused, clearly, and does not buffer ---------------
    state = Path(tempfile.mkdtemp(prefix="attest-first-"))
    attest = AttestClient(api_key=api_key, base_url=BASE, state_dir=state)
    result = attest.gate({"text": "before onboarding"})
    ok(result.status == "misconfigured", f"gate refused with a config error ({result.status})")
    ok(result.buffered is False, "a setup problem is NOT buffered as if it were an outage")
    ok(result.recorded is False, "and nothing was recorded")
    ok("Settings" in result.reasons[0], "the message says what to do")
    ok(attest.pending_offline == 0, "the offline queue stays clean")

    # --- 2-3. The console walks them through it ----------------------------
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        page = browser.new_page(viewport={"width": 1440, "height": 1300})
        errs: list[str] = []
        page.on("pageerror", lambda e: errs.append(str(e)))
        page.goto(BASE + "/console")
        page.fill("#apikey", api_key)
        page.click("#btn-connect")

        page.wait_for_selector("#onboarding", state="visible", timeout=8000)
        ok(not page.is_visible("#appui"), "the dashboard is replaced by onboarding on first run")
        intro = page.inner_text("#onboarding")
        ok("before anything is recorded" in intro, "it explains WHY the profile comes first")

        page.click('[data-obj="difc"]')
        page.click('[data-obs="capital_markets"]')
        page.click("#ob-save-profile")
        page.wait_for_selector("#ob-step1-chip >> text=DONE", timeout=10000)
        ok("rulebook" in page.inner_text("#ob-status"), "it reports which rulebooks now apply")

        page.click("#ob-create-policy")
        page.wait_for_selector("#ob-done", state="visible", timeout=10000)
        ok(True, "starter policy published from the wizard")

        page.screenshot(path="/tmp/first_run.png")
        page.click("#ob-finish")
        page.wait_for_selector("#appui", state="visible", timeout=8000)
        ok(page.is_visible("#appui"), "the dashboard opens once setup is complete")

        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()

    # --- 4. Recording works now --------------------------------------------
    after = attest.gate({"text": "after onboarding"})
    ok(after.recorded, f"recording works once onboarded ({after.status})")
    ok(after.status in ("compliant", "flagged"), "and it was evaluated")

    profile = rq.get(f"{BASE}/v1/policies/profile", headers={"x-api-key": api_key}).json()
    ok("difc_dp_reg10" in profile["mandatory_pack_codes"],
       "the rulebooks derived at onboarding are in force")

    print("\nALL FIRST-RUN E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
