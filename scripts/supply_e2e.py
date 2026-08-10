"""Supplying official text by hand, in the ops dashboard.

difc.com and rulebook.centralbank.ae refuse automated clients, so four of seven
sources could never be checked. A person supplies the text instead — and the
whole point of this screen is that the weaker provenance is visible, not hidden.

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

OFFICIAL = (
    "DATA PROTECTION LAW, DIFC LAW NO. 5 OF 2020\n"
    "Article 10 - High Risk Processing Activities\n"
    "Article 26 - List of Adequate Data Protection Regimes\n"
)


def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def seed_pack(code: str) -> str:
    """A pack citing a URL, with a candidate citation waiting to be confirmed."""
    from app.db.session import SessionLocal
    from app.services import reg_watch
    from app.services.regulation_packs import upsert_pack

    url = f"https://blocked.test/{code}"
    db = SessionLocal()
    upsert_pack(db, {
        "code": code, "jurisdiction": "difc", "jurisdictions": ["difc"],
        "sectors": ["*"], "name": "Supply E2E", "version": "1.0",
        "instrument": "Test Instrument", "source_url": url,
        "verification_status": "unverified", "schema_version": 2, "engine": "json",
        "rules": [{
            "id": "r1", "priority": 100, "tier": "orange", "decision": "flag",
            "match": {"has_pii": True}, "reason": "test", "topic": "t",
            "provision": None, "provision_candidate": "Article 26",
        }],
    })
    reg_watch.register_sources(db)
    db.commit()
    db.close()
    return url


def main() -> None:
    code = f"supply_{uuid.uuid4().hex[:8]}"
    url = seed_pack(code)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        page = browser.new_page(viewport={"width": 1500, "height": 1200})
        errs: list[str] = []
        page.on("pageerror", lambda e: errs.append(str(e)))

        page.goto(BASE + "/admin")
        page.fill("#gate-key", ADMIN_KEY)
        page.click("#gate-connect")
        page.wait_for_selector("#appui", state="visible", timeout=8000)
        page.click('nav.screens button[data-k="regwatch"]')
        page.click("#btn-rw-sources")
        page.wait_for_selector("#rw-sources table", timeout=10000)

        page.click(f'button[data-supply="{code}"]')
        page.wait_for_selector("#supply-panel", state="visible", timeout=5000)

        panel = page.inner_text("#supply-panel")
        ok("weakens provenance" in panel,
           "the panel states plainly that this weakens provenance")
        ok("attested_verified" in panel and "source_verified" in panel,
           "and names both statuses so the difference is legible")

        # An attestation with no name must be refused before any round trip.
        page.fill("#supply-text", OFFICIAL)
        page.click("#supply-save")
        page.wait_for_timeout(600)
        ok("required" in page.inner_text("#toast").lower(),
           "an unattributed attestation is refused")

        page.fill("#supply-by", "E2E Operator")
        page.fill("#supply-note", "downloaded by hand for the e2e run")
        page.click("#supply-save")
        page.wait_for_selector("#supply-panel", state="hidden", timeout=20000)
        ok("attested" in page.inner_text("#toast").lower(),
           "a named attestation is accepted")

        page.wait_for_timeout(1200)
        sources = page.inner_text("#rw-sources")
        ok("ATTESTED BY HAND" in sources, "the source is marked as hand-attested")
        ok("E2E Operator" in sources, "and names who attested it")

        page.screenshot(path="/tmp/supply.png")
        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()

    packs = rq.get(f"{BASE}/v1/admin/regulation-packs", headers=A).json()
    mine = [p for p in packs if p["code"] == code]
    ok(mine, "the pack is listed")
    latest = sorted(mine, key=lambda p: p["version"])[-1]
    ok(latest["verification_status"] == "attested_verified",
       f"published as attested_verified, not source_verified (got "
       f"{latest['verification_status']})")
    ok("+av" in latest["version"],
       f"and carries the +av marker (got {latest['version']})")
    ok("+sv" not in latest["version"],
       "never the +sv marker that means Attest fetched it")

    changes = rq.get(f"{BASE}/v1/admin/regulation-watch/changes?limit=200",
                     headers=A).json()
    supplied = [c for c in changes
                if c["pack_code"] == code and c["change_type"] == "text_supplied"]
    ok(supplied, "the attestation itself is recorded as a change")
    ev = supplied[0]["evidence"]
    ok(ev.get("attested_by") == "E2E Operator", "with the attestor's name")
    ok(ev.get("text_sha256"), "and the hash of exactly what was supplied")

    # Gate 1 still admits nothing from an unregistered URL.
    r = rq.post(f"{BASE}/v1/admin/regulation-watch/sources/supply", headers=A, json={
        "pack_code": code, "url": "https://not-registered.test/x",
        "text": OFFICIAL, "attested_by": "E2E Operator",
    })
    ok(r.status_code == 404,
       f"supplying text for an unregistered URL is refused (got {r.status_code})")
    ok(url, "registered url used above")

    print("\nALL SUPPLY-TEXT E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
