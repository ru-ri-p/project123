"""The Settings page: obligations derived, and not droppable.

Drives the real page in a real browser:
  1. Pick DIFC + capital markets -> the implied rulebooks apply automatically.
  2. Add healthcare -> applies immediately (more obligations is never blocked).
  3. Try to drop healthcare -> the page warns, demands a reason, and the change
     goes to Attest. The rulebook KEEPS applying meanwhile.
  4. Attest approves -> only then does it come off.

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
A = {"x-admin-key": ADMIN_KEY}


def clear_toast(page) -> None:
    """A toast already on screen would satisfy the next wait and mask a race."""
    page.evaluate(
        "const t=document.querySelector('#toast');"
        "t.className=''; t.style.display='none'")


def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def main() -> None:
    rq.post(f"{BASE}/v1/admin/regulation-packs/seed", headers=A)
    org_id = f"org_set_{uuid.uuid4().hex[:8]}"
    api_key = rq.post(f"{BASE}/v1/admin/orgs", headers=A,
                      json={"org_id": org_id, "name": "TradeEasy DMCC"}).json()["api_key"]
    H = {"x-api-key": api_key}
    # Onboard via the API first: this script exercises CHANGING a profile, which
    # is a different screen from the first-run wizard (covered by first_run_e2e).
    rq.put(f"{BASE}/v1/policies/profile", headers=H,
           json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        page = browser.new_page(viewport={"width": 1440, "height": 1400})
        errs: list[str] = []
        page.on("pageerror", lambda e: errs.append(str(e)))
        page.goto(BASE + "/console")
        page.fill("#apikey", api_key)
        page.click("#btn-connect")
        page.wait_for_selector("#orgbadge", state="visible", timeout=6000)
        page.click('nav.screens button[data-k="settings"]')
        page.wait_for_selector("[data-sector]", timeout=8000)

        text = page.inner_text("#scr-settings")
        ok("derived, not chosen" in text, "page states rulebooks are derived, not chosen")
        ok("ISIC" in text, "sectors show their ISIC classification")

        # --- 1. Declare the profile ---------------------------------------
        # Already selected from the API-set profile; re-saving is a no-op edit.
        # Dismiss the connect toast first, or the wait below is satisfied by a
        # toast that is already on screen and we race the save.
        clear_toast(page)
        page.click("#btn-save-profile")
        page.wait_for_selector("#toast.ok >> text=Profile updated", timeout=10000)
        profile = rq.get(f"{BASE}/v1/policies/profile", headers=H).json()
        codes = set(profile["mandatory_pack_codes"])
        ok("difc_dp_reg10" in codes, "DIFC data protection applied from jurisdiction")
        ok("uae_fin_enabling_tech" in codes,
           "joint financial-sector AI guidelines applied from sector")
        ok("uae_health_ai" not in codes, "healthcare rulebook correctly not applied")
        mine = {p["code"] for p in rq.get(f"{BASE}/v1/policies/packs/mine", headers=H).json()}
        ok(codes <= mine, "every derived rulebook is actually in force")

        # --- 2. Adding is instant ------------------------------------------
        clear_toast(page)
        page.click('[data-sector="healthcare_provider"]')
        page.click("#btn-save-profile")
        page.wait_for_selector("#toast.ok >> text=Profile updated", timeout=10000)
        codes = set(rq.get(f"{BASE}/v1/policies/profile", headers=H).json()["mandatory_pack_codes"])
        ok("uae_health_ai" in codes, "adding a sector applied immediately")

        # --- 3. Removing is not ---------------------------------------------
        page.click('[data-sector="healthcare_provider"]')  # untick
        page.wait_for_selector("#set-reasonbox", state="visible", timeout=5000)
        warning = page.inner_text("#set-reasonbox")
        ok("removes obligations" in warning, "page warns before a reduction is submitted")
        ok("healthcare_provider" in warning, "page names exactly what is being removed")

        page.fill("#set-reason", "we exited healthcare in June")
        clear_toast(page)
        page.click("#btn-save-profile")
        page.wait_for_selector("#toast.err", timeout=10000)

        profile = rq.get(f"{BASE}/v1/policies/profile", headers=H).json()
        ok("healthcare_provider" in profile["sectors"], "the sector is NOT dropped on request")
        ok("uae_health_ai" in profile["mandatory_pack_codes"],
           "the rulebook keeps applying while approval is pending")
        ok(profile["pending_changes"] == 1, "a change request is waiting for Attest")

        # --- 4. Attest decides ----------------------------------------------
        pending = rq.get(f"{BASE}/v1/admin/profile-changes", headers=A).json()
        mine_req = [p for p in pending if p["org_id"] == org_id]
        ok(len(mine_req) == 1, "the request is visible to Attest")
        ok(mine_req[0]["reason"] == "we exited healthcare in June", "with the stated reason")

        rq.post(f"{BASE}/v1/admin/profile-changes/{mine_req[0]['id']}/decide?approve=true",
                headers=A)
        after = rq.get(f"{BASE}/v1/policies/profile", headers=H).json()
        ok("healthcare_provider" not in after["sectors"], "approval applies the reduction")

        page.screenshot(path="/tmp/settings_page.png")
        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()
    print("\nALL SETTINGS E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
