"""The gate, end to end: one SDK call per AI output, results on the dashboard.

Proves the integration a customer actually writes — `attest.gate(output)` — and
that every outcome reaches their Compliance screen labelled correctly:

  compliant  -> logged, "no problem with the output"
  flagged    -> DIFC finding cited, advisory, did NOT block
  blocked    -> their OWN policy denied it

Also checks the friction is genuinely gone: no trace ids, no sequence numbers,
and Attest being unreachable does not take down the caller's application.

Run with the API on 127.0.0.1:8300 and ADMIN_API_KEY=e2e-admin-key.
"""

from __future__ import annotations

import sys
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
    org_id = f"org_gate_{uuid.uuid4().hex[:8]}"
    api_key = rq.post(
        f"{BASE}/v1/admin/orgs", headers={"x-admin-key": ADMIN_KEY},
        json={"org_id": org_id, "name": "TradeEasy DMCC"},
    ).json()["api_key"]
    rq.post(f"{BASE}/v1/admin/orgs/{org_id}/regulation-packs",
            headers={"x-admin-key": ADMIN_KEY}, json={"pack_code": "difc_dp_reg10"})
    rq.put(f"{BASE}/v1/policies/profile", headers={"x-api-key": api_key},
           json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    rq.put(f"{BASE}/v1/policies/internal", headers={"x-api-key": api_key}, json={
        "name": "Internal AI policy", "version": "v1", "activate": True,
        "rules": {"schema_version": 2, "engine": "json", "rules": [
            {"id": "block_wires", "priority": 1000, "tier": "red", "decision": "deny",
             "match": {"action": ["wire_transfer"]},
             "reason": "Wire transfers require a human."}]}})

    attest = AttestClient(api_key=api_key, base_url=BASE, enable_local_precheck=False)

    # --- THIS IS THE ENTIRE INTEGRATION ------------------------------------
    clean = attest.gate({"text": "The market closed higher today."})
    ok(clean.compliant, f"compliant output -> {clean.status}")
    ok(clean.recorded and clean.output_hash != "", "compliant output was still recorded")
    ok(clean.trace_id != "", "a trace was created automatically")

    flagged = attest.gate({"text": "declined", "_classifier_tier": "discriminatory_lending"})
    ok(flagged.flagged, f"non-compliant output -> {flagged.status}")
    ok(flagged.allowed is True, "a jurisdiction finding does not block")
    ok(flagged.jurisdictions == ["difc"], "attributed to DIFC")
    ok("Regulation 10" in flagged.findings[0]["instrument"], "instrument cited on the result")

    blocked = attest.gate({"amount": 5000}, action="wire_transfer")
    ok(blocked.blocked, f"their own policy blocks -> {blocked.status}")
    ok(blocked.allowed is False, "blocked outputs report allowed=False")

    # Multi-step: pass the trace to group steps; sequences stay invisible.
    step1 = attest.gate({"step": "draft"}, action="model_completion")
    step2 = attest.gate({"step": "tool"}, action="tool_call", trace=step1.trace_id)
    ok(step2.trace_id == step1.trace_id, "steps group into one trace when asked")
    events = rq.get(f"{BASE}/v1/trace/{step1.trace_id}/events",
                    headers={"x-api-key": api_key}).json()
    ok(len(events) == 4, f"both steps chained with their decisions ({len(events)} events)")
    replay = rq.get(f"{BASE}/v1/trace/{step1.trace_id}/replay",
                    headers={"x-api-key": api_key}).json()
    ok(replay["all_verified"], "the multi-step chain verifies")

    # An outage must not take down the caller's application, and must not lose
    # the record either. (Exercised in depth by scripts/outage_e2e.py.)
    import tempfile

    offline = AttestClient(
        api_key=api_key, base_url="http://127.0.0.1:9", server_timeout=2,
        state_dir=tempfile.mkdtemp(prefix="attest-gate-e2e-"),
    )
    degraded = offline.gate({"text": "x"})
    ok(degraded.allowed is True, "the caller's application keeps serving during an outage")
    ok(degraded.buffered and not degraded.recorded,
       "the output is buffered locally rather than lost")

    # --- It all shows up on their dashboard --------------------------------
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium")
        page = browser.new_page(viewport={"width": 1440, "height": 1400})
        errs: list[str] = []
        page.on("pageerror", lambda e: errs.append(str(e)))
        page.goto(BASE + "/console")
        page.fill("#apikey", api_key)
        page.click("#btn-connect")
        page.wait_for_selector("#orgbadge", state="visible", timeout=6000)
        page.click('nav.screens button[data-k="compliance"]')
        page.click("#btn-decisions")
        page.wait_for_selector("#decisions >> text=COMPLIANT", timeout=10000)

        dec = page.inner_text("#decisions")
        ok("✓ COMPLIANT" in dec, "dashboard shows clean outputs as compliant")
        ok("⚠ FLAGGED" in dec, "dashboard shows the non-compliant output as flagged")
        ok("✕ BLOCKED" in dec, "dashboard shows the blocked output")
        ok("ADVISORY — DID NOT BLOCK" in dec, "flagged finding shown as advisory")
        ok("Regulation 10" in dec, "instrument cited on the dashboard")

        summary = page.inner_text("#scr-compliance")
        ok("passed with no problem" in summary, "summary reports the clean outputs")

        page.screenshot(path="/tmp/gate_dashboard.png")
        ok(not errs, f"no browser JS errors (got: {errs})")
        browser.close()
    print("\nALL GATE E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
