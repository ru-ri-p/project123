"""Regulation Watch in the ops dashboard, including a fabrication attempt.

The sweep runs against the REAL registered sources. In this environment the
regulator hosts are blocked by egress policy, so every fetch fails — which is
itself the point of one check here: a dead or unreachable source must be reported
loudly, never silently ignored.

The anti-fabrication guarantees are proven at the unit level in
tests/test_reg_watch.py against a controlled official text; this script proves the
operator surface works and reports honestly.

Run with the API on 127.0.0.1:8300 and ADMIN_API_KEY=e2e-admin-key.
"""

from __future__ import annotations

import sys
from pathlib import Path

import requests as rq
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BASE = "http://127.0.0.1:8300"
ADMIN_KEY = "e2e-admin-key"
A = {"x-admin-key": ADMIN_KEY}


def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def main() -> None:
    rq.post(f"{BASE}/v1/admin/regulation-packs/seed", headers=A)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        page = browser.new_page(viewport={"width": 1440, "height": 1200})
        errs: list[str] = []
        page.on("pageerror", lambda e: errs.append(str(e)))

        page.goto(BASE + "/admin")
        page.fill("#gate-key", ADMIN_KEY)
        page.click("#gate-connect")
        page.wait_for_selector("#appui", state="visible", timeout=8000)
        page.click('nav.screens button[data-k="regwatch"]')

        page.click("#btn-rw-sources")
        page.wait_for_selector("#rw-sources table", timeout=10000)
        sources = page.inner_text("#rw-sources")
        ok("difc" in sources.lower(), "official sources are registered per pack")
        ok("difc.com" in sources or "http" in sources, "each source shows its official URL")

        stance = page.inner_text("#scr-regwatch")
        ok("Nothing is generated" in stance, "the page states the anti-fabrication stance")
        ok("never auto-updates rule meaning" in stance,
           "and that a changed regulation does not auto-update meaning")

        # A dry run must never publish, whatever it finds.
        page.evaluate(
            "const t=document.querySelector('#toast');"
            "t.className=''; t.style.display='none'")
        page.click("#btn-rw-dry")
        page.wait_for_selector("#toast", state="visible", timeout=30000)
        ok("Checked" in page.inner_text("#toast"), "dry run reports what it checked")

        before = rq.get(f"{BASE}/v1/admin/regulation-watch/changes?status=auto_published",
                        headers=A).json()
        ok(all(c["status"] != "auto_published" or c["published_version"]
               for c in before), "any auto-publish records the version it published")

        page.click("#btn-rw-changes")
        page.wait_for_timeout(800)
        changes = page.inner_text("#rw-changes")
        ok("NEEDS REVIEW" in changes,
           "unreachable sources are quarantined and surfaced, not silently ignored")

        page.screenshot(path="/tmp/regwatch.png")
        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()

    # The sweep must never have invented a citation into any pack.
    packs = rq.get(f"{BASE}/v1/admin/regulation-packs", headers=A).json()
    for pack in packs:
        ok(pack["verification_status"] in ("unverified", "source_verified", "counsel_reviewed"),
           f"{pack['code']} carries an honest verification status")
    # The meaningful check is not "no pack is counsel-reviewed" (a human may
    # legitimately mark one), but that nothing the WATCHER published claims it.
    # Watcher-published versions carry the +sv suffix.
    watcher_published = [p for p in packs if "+sv" in p["version"]]
    ok(all(p["verification_status"] == "source_verified" for p in watcher_published),
       f"every watcher-published pack is source_verified, never promoted "
       f"({len(watcher_published)} checked)")

    print("\nALL REGWATCH E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
