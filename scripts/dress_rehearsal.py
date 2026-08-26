#!/usr/bin/env python3
"""The pre-customer dress rehearsal: run everything TradeEasy will run, first.

One command against a live deployment. Creates throwaway orgs, then walks:

  A  setup & gates      — health, pack coverage, onboarding gate (409 before a
                          profile exists), profile, policy
  B  verdicts           — the pilot's trigger catalogue: clean, PII (flagged
                          with DIFC citation, never blocked), own-policy block,
                          classifier, cross-border, phone-with-spaces
  C  rule ownership     — edit the customer's own rule, watch the verdict
                          change; red+flag routes to human approval (blocked
                          with approval_id) — the documented semantics
  D  the chained story  — multi-step trace, replay all_verified
  E  remediation loop   — flag → suggested fix → re-gate → REMEDIATED
  F  consent ceremony   — go dark, DENY (we read nothing), approve (we read
                          exactly one record), out-of-scope still refused
  G  outage             — offline verdict, durable queue, drain on recovery
  H  evidence           — export the bundle and verify it with verify.py,
                          exactly as an outside auditor would

Non-destructive: nothing existing is touched; all data is synthetic.

    ATTEST_URL=https://attest-api-ipvl.onrender.com python scripts/dress_rehearsal.py

ADMIN_API_KEY is read from the environment (already set in the Render shell).
Exit code 0 = every check passed = safe to send the customer package.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

import requests as rq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

URL = os.environ.get("ATTEST_URL", "http://127.0.0.1:8300").rstrip("/")
ADMIN = os.environ.get("ADMIN_API_KEY") or sys.exit("set ADMIN_API_KEY")
A = {"x-admin-key": ADMIN}
T = 30  # request timeout

RESULTS: list[tuple[bool, str]] = []


def check(section: str, ok: bool, msg: str) -> bool:
    RESULTS.append((ok, f"[{section}] {msg}"))
    print(("PASS " if ok else "FAIL ") + f"[{section}] {msg}")
    return ok


def policy_doc(trade_tier: str, trade_decision: str) -> dict:
    return {
        "schema_version": 2, "engine": "json",
        "rules": [
            {"id": "high_risk_financial_action", "priority": 1000,
             "tier": trade_tier, "decision": trade_decision,
             "match": {"action": ["wire_transfer", "execute_trade"]},
             "reason": "High-risk financial action requires human approval."},
            {"id": "personal_data_in_output", "priority": 800, "tier": "orange",
             "decision": "flag", "match": {"has_pii": True},
             "reason": "Personal data detected — review before release."},
        ],
    }


def new_org(name: str) -> tuple[str, dict]:
    org_id = f"org_dr_{uuid.uuid4().hex[:8]}"
    r = rq.post(f"{URL}/v1/admin/orgs", headers=A,
                json={"org_id": org_id, "name": name}, timeout=T)
    r.raise_for_status()
    return org_id, {"x-api-key": r.json()["api_key"]}


def gate(H: dict, action: str, output: dict, **extra) -> rq.Response:
    return rq.post(f"{URL}/v1/gate", headers=H, timeout=T,
                   json={"action": action, "output": output, **extra})


def main() -> int:  # noqa: PLR0915 — a rehearsal is long by nature
    print(f"Dress rehearsal against {URL}\n" + "=" * 62)

    # ---- A · setup & gates --------------------------------------------------
    ok = rq.get(f"{URL}/health", timeout=T).status_code == 200
    check("A1", ok, "service answers /health")

    cov = rq.get(f"{URL}/v1/admin/regulation-packs/coverage", headers=A,
                 timeout=T).json()
    check("A2", cov.get("complete") is True,
          f"all bundled packs are published ({cov.get('seeded')}/{cov.get('expected')}"
          f"{'' if cov.get('complete') else ' — MISSING: ' + str(cov.get('missing'))})")

    org_id, H = new_org("Dress Rehearsal")
    r = gate(H, "model_completion", {"output": "hello"})
    check("A3", r.status_code == 409
          and r.json().get("detail", {}).get("code") == "profile_required",
          "a new org CANNOT record before onboarding (409 profile_required)")

    rq.put(f"{URL}/v1/policies/profile", headers=H, timeout=T,
           json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    rq.put(f"{URL}/v1/policies/internal", headers=H, timeout=T,
           json={"name": "Rehearsal", "version": "v1",
                 "rules": policy_doc("red", "deny"), "activate": True})
    r = gate(H, "model_completion", {"output": "hello again"})
    check("A4", r.status_code == 200 and r.json()["status"] == "compliant",
          "recording works the moment profile + policy exist")

    # ---- B · verdicts (the pilot's trigger catalogue) -----------------------
    cases = [
        ("B1", "clean output", "model_completion",
         {"output": "Gold closed higher today."}, "compliant", None),
        ("B2", "PII (email)", "model_completion",
         {"output": "send the statement to sara.m@example.com"}, "flagged", "difc"),
        ("B3", "PII (phone with spaces)", "model_completion",
         {"output": "call the client on +971 50 123 4567"}, "flagged", "difc"),
        ("B4", "individualised advice", "model_completion",
         {"output": "you should buy X", "classifier": "individualised_advice"},
         "flagged", "difc_dp_reg10"),
        ("B5", "cross-border, no basis", "model_completion",
         {"output": "sending data", "cross_border": True}, "flagged", "difc"),
        ("B6", "cross-border WITH basis", "model_completion",
         {"output": "sending data", "cross_border": True,
          "lawful_basis": "contract"}, "compliant", None),
        ("B7", "own-policy deny", "execute_trade",
         {"output": "executing"}, "blocked", None),
    ]
    for sec, name, action, payload, expect, cite in cases:
        body = gate(H, action, payload).json()
        good = body.get("status") == expect
        if good and cite:
            good = any(str(f.get("pack_code", "")).startswith(cite)
                       for f in body.get("findings", []))
        if good and expect == "flagged":
            good = body.get("allowed") is True  # flags never block
        check(sec, good, f"{name} → {expect}"
              + (f", citing {cite}*" if cite else "")
              + (", not blocked" if expect == "flagged" else ""))

    # ---- C · rule ownership -------------------------------------------------
    rq.put(f"{URL}/v1/policies/internal", headers=H, timeout=T,
           json={"name": "Rehearsal", "version": "v2",
                 "rules": policy_doc("orange", "flag"), "activate": True})
    body = gate(H, "execute_trade", {"output": "executing"}).json()
    check("C1", body["status"] == "flagged" and body["allowed"] is True,
          "customer edits their rule to orange+flag → same action now flags")

    rq.put(f"{URL}/v1/policies/internal", headers=H, timeout=T,
           json={"name": "Rehearsal", "version": "v3",
                 "rules": policy_doc("red", "flag"), "activate": True})
    body = gate(H, "execute_trade", {"output": "executing"}).json()
    check("C2", body["status"] == "blocked" and body.get("approval_id"),
          "red + flag = the human-approval gate: blocked WITH an approval id")

    rq.put(f"{URL}/v1/policies/internal", headers=H, timeout=T,
           json={"name": "Rehearsal", "version": "v4",
                 "rules": policy_doc("red", "deny"), "activate": True})

    # ---- D · the chained story ----------------------------------------------
    trace = str(uuid.uuid4())
    seqs = []
    for act, out in [("retrieval", {"query": "client risk profile"}),
                     ("model_completion", {"output": "draft summary"}),
                     ("finalize", {"output": "final summary"})]:
        seqs.append(gate(H, act, out, trace_id=trace).json()["output_seq"])
    check("D1", seqs == sorted(seqs) and len(set(seqs)) == 3,
          "multi-step trace: server-assigned sequence, in order")
    rep = rq.get(f"{URL}/v1/trace/{trace}/replay", headers=H, timeout=T).json()
    check("D2", rep.get("all_verified") is True,
          f"replay verifies every hash/signature/link ({len(rep.get('events', []))} events)")

    # ---- E · remediation loop -----------------------------------------------
    rtrace = str(uuid.uuid4())
    first = gate(H, "model_completion",
                 {"output": "email sara.m@example.com the file"},
                 trace_id=rtrace).json()
    fix = first.get("suggested_fix") or {}
    ok = (first["status"] == "flagged" and fix.get("revised_output")
          and "sara.m@example.com" not in str(fix["revised_output"]))
    check("E1", bool(ok), "a flag arrives with a working fix (PII gone from revision)")
    second = gate(H, "model_completion", fix.get("revised_output") or {},
                  trace_id=rtrace, remediates=first["decision_seq"]).json()
    check("E2", second.get("status") == "compliant"
          and second.get("remediation_of") == first["decision_seq"],
          "the applied fix re-gates compliant, naming the flag it cures")
    decs = rq.get(f"{URL}/v1/policies/decisions?limit=50", headers=H,
                  timeout=T).json()
    row = next((d for d in decs if d["trace_id"] == rtrace
                and d["seq"] == first["decision_seq"]), {})
    check("E3", row.get("remediated_by_seq") == second.get("decision_seq"),
          "the original flag shows REMEDIATED (closed by the compliant re-check)")

    # ---- F · consent ceremony (the one that matters) ------------------------
    from attest_sdk.consent import ConsentClient
    from attest_sdk.orgcrypto import generate_wrapping_keypair

    c_org, CH = new_org("Rehearsal Dark Co")
    rq.put(f"{URL}/v1/policies/profile", headers=CH, timeout=T,
           json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    rq.put(f"{URL}/v1/policies/internal", headers=CH, timeout=T,
           json={"name": "Rehearsal", "version": "v1",
                 "rules": policy_doc("red", "deny"), "activate": True})
    private_pem, public_pem = generate_wrapping_keypair()
    consent = ConsentClient(api_key=CH["x-api-key"], base_url=URL)
    mode = consent.enable_customer_key(public_pem)
    check("F1", mode.get("confidentiality_mode") == "customer_key",
          "org goes dark: Attest holds only the PUBLIC wrapping key")

    ctrace = str(uuid.uuid4())
    gate(CH, "model_completion",
         {"output": "dark record one — synthetic secret alpha"}, trace_id=ctrace)
    gate(CH, "model_completion",
         {"output": "dark record two — synthetic secret beta"}, trace_id=ctrace)
    ev = rq.get(f"{URL}/v1/admin/traces/{ctrace}/events", headers=A,
                timeout=T).json()
    content_hashes = [e["payload_hash"] for e in ev
                     if e["type"] == "model_completion"]
    check("F2", len(content_hashes) == 2, "two dark records exist in the trace")

    def file_request(hashes: list[str]) -> str:
        r = rq.post(f"{URL}/v1/admin/access-requests", headers=A, timeout=T,
                    json={"org_id": c_org, "payload_hashes": hashes,
                          "reason": "dress rehearsal — please DENY / approve",
                          "required_approvals": 1, "ttl_seconds": 3600})
        r.raise_for_status()
        body = r.json()
        return str(body.get("request_id") or body["id"])

    req1 = file_request([content_hashes[0]])
    consent.deny(req1)
    r = rq.get(f"{URL}/v1/admin/access-requests/{req1}/records/"
               f"{content_hashes[0]}", headers=A, timeout=T)
    check("F3", r.status_code != 200,
          f"DENIED → Attest reads NOTHING (HTTP {r.status_code})")

    req2 = file_request([content_hashes[0]])
    consent.approve(req2, approver_id="rehearsal_officer",
                    org_private_pem=private_pem)
    r = rq.get(f"{URL}/v1/admin/access-requests/{req2}/records/"
               f"{content_hashes[0]}", headers=A, timeout=T)
    got = r.json() if r.status_code == 200 else {}
    check("F4", r.status_code == 200
          and "alpha" in str(got.get("content", "")),
          "APPROVED → Attest reads exactly that record, decrypted via the grant")

    r = rq.get(f"{URL}/v1/admin/access-requests/{req2}/records/"
               f"{content_hashes[1]}", headers=A, timeout=T)
    check("F5", r.status_code != 200,
          f"the OTHER record stays dark — approval is scoped (HTTP {r.status_code})")

    # ---- G · outage ----------------------------------------------------------
    from attest_sdk import AttestClient

    state = tempfile.mkdtemp(prefix="attest_dr_")
    live = AttestClient(api_key=H["x-api-key"], base_url=URL, state_dir=state)
    warm = live.gate({"output": "warming the offline cache"})
    broken = AttestClient(api_key=H["x-api-key"],
                          base_url="https://127.0.0.1:9", state_dir=state,
                          server_timeout=2)
    broken._prepared = True  # noqa: SLF001 — cache already warmed by `live`
    off = broken.gate({"output": "recorded during the rehearsal outage"})
    check("G1", warm.recorded and off.recorded is False and off.buffered,
          "outage → local verdict, durably queued (app never waits on Attest)")
    drained = live.gate({"output": "back online"})
    check("G2", drained.recorded,
          "recovery gate succeeds and hands the queue over for grafting")

    # ---- H · evidence, verified as an outsider would ------------------------
    z = rq.get(f"{URL}/v1/evidence/{rtrace}/export?format=zip", headers=H,
               timeout=60)
    ok = z.status_code == 200 and len(z.content) > 1000
    check("H1", ok, f"evidence bundle exports ({len(z.content):,} bytes)")
    verified = False
    if ok:
        with tempfile.TemporaryDirectory() as td:
            zipfile.ZipFile(io.BytesIO(z.content)).extractall(td)
            out = subprocess.run([sys.executable, "verify.py"], cwd=td,
                                 capture_output=True, text=True, timeout=120)
            verified = "ALL EVENTS VERIFIED" in out.stdout
    check("H2", verified,
          "verify.py run offline on the bundle: ALL EVENTS VERIFIED")

    # ---- verdict -------------------------------------------------------------
    failed = [msg for good, msg in RESULTS if not good]
    print("=" * 62)
    print(f"{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if failed:
        print("\nFAILED:")
        for msg in failed:
            print("  " + msg)
        print("\nDO NOT send the customer package until these are green.")
        return 1
    print("\nEvery check a customer's pilot would exercise is green.")
    print("Safe to send the TradeEasy package.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
