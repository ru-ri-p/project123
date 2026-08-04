"""The ops Organisations screen must show whether a customer has a profile,
because gating one that has not stops their recording."""

from __future__ import annotations

import sys
import uuid

import requests as rq
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8300"
ADMIN_KEY = "e2e-admin-key"
A = {"x-admin-key": ADMIN_KEY}


def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def main() -> None:
    bare = f"org_bare_{uuid.uuid4().hex[:8]}"
    done = f"org_done_{uuid.uuid4().hex[:8]}"
    rq.post(f"{BASE}/v1/admin/orgs", headers=A, json={"org_id": bare, "name": "Bare Co"})
    # Grandfathered, like TradeEasy: gate off, no profile. This is the row where
    # clicking "Require onboarding" would stop a live integration.
    rq.post(f"{BASE}/v1/admin/orgs/{bare}/require-onboarding?required=false", headers=A)
    key = rq.post(f"{BASE}/v1/admin/orgs", headers=A,
                  json={"org_id": done, "name": "Done Co"}).json()["api_key"]
    rq.put(f"{BASE}/v1/policies/profile", headers={"x-api-key": key},
           json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        page = browser.new_page(viewport={"width": 1600, "height": 1100})
        errs: list[str] = []
        page.on("pageerror", lambda e: errs.append(str(e)))

        page.goto(BASE + "/admin")
        page.fill("#gate-key", ADMIN_KEY)
        page.click("#gate-connect")
        page.wait_for_selector("#appui", state="visible", timeout=8000)
        page.click('nav.screens button[data-k="orgs"]')

        page.fill("#orgsearch", done)
        page.wait_for_timeout(900)
        row = page.inner_text("#orgrows")
        ok("PROFILE SET" in row, "a configured org reads PROFILE SET")
        ok("DIFC" in row, "and shows what they declared")

        page.fill("#orgsearch", bare)
        page.wait_for_timeout(900)
        row = page.inner_text("#orgrows")
        ok("NO PROFILE" in row, "an unconfigured org reads NO PROFILE")

        # Gating the bare one must WARN, not proceed quietly.
        seen: list[str] = []
        page.on("dialog", lambda d: (seen.append(d.message), d.dismiss()))
        page.click('#orgrows button[data-gate]')
        page.wait_for_timeout(500)
        ok(seen and "NO PROFILE" in seen[0],
           f"gating a profile-less org warns that recording stops (got: {seen})")

        page.screenshot(path="/tmp/orgprofile.png")
        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()

    print("\nALL ORG-PROFILE CHECKS PASSED")


if __name__ == "__main__":
    main()
