"""A real outage, through the real SDK: keep serving, keep the trail.

  1. Normal operation — gate() works, nothing buffered.
  2. Attest goes away — gate() still returns a correct verdict (evaluated
     locally against the synced bundle, packs included) and durably queues the
     event, signed by this SDK's own key.
  3. The process restarts mid-outage — the queue survives on disk.
  4. Attest comes back — buffered events are grafted in automatically, verified,
     marked deferred, and the chain verifies.

Run with the API on 127.0.0.1:8300 and ADMIN_API_KEY=e2e-admin-key.
"""

from __future__ import annotations

import sys
import tempfile
import uuid
from pathlib import Path

import requests as rq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attest_sdk import AttestClient  # noqa: E402

BASE = "http://127.0.0.1:8300"
DEAD = "http://127.0.0.1:9"  # nothing listens here — a genuine outage
ADMIN_KEY = "e2e-admin-key"


def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def main() -> None:
    rq.post(f"{BASE}/v1/admin/regulation-packs/seed", headers={"x-admin-key": ADMIN_KEY})
    org_id = f"org_out_{uuid.uuid4().hex[:8]}"
    api_key = rq.post(f"{BASE}/v1/admin/orgs", headers={"x-admin-key": ADMIN_KEY},
                      json={"org_id": org_id, "name": "Outage E2E"}).json()["api_key"]
    rq.post(f"{BASE}/v1/admin/orgs/{org_id}/regulation-packs",
            headers={"x-admin-key": ADMIN_KEY}, json={"pack_code": "difc_dp_reg10"})
    rq.put(f"{BASE}/v1/policies/profile", headers={"x-api-key": api_key},
           json={"jurisdictions": ["difc"], "sectors": ["capital_markets"]})
    rq.put(f"{BASE}/v1/policies/internal", headers={"x-api-key": api_key}, json={
        "name": "Internal", "version": "v1", "activate": True,
        "rules": {"schema_version": 2, "engine": "json", "rules": [
            {"id": "block_wires", "priority": 1000, "tier": "red", "decision": "deny",
             "match": {"action": ["wire_transfer"]}, "reason": "Human required."}]}})

    state = Path(tempfile.mkdtemp(prefix="attest-outage-"))

    # --- 1. Healthy --------------------------------------------------------
    live = AttestClient(api_key=api_key, base_url=BASE, state_dir=state)
    healthy = live.gate({"text": "all good"})
    ok(healthy.compliant and healthy.recorded, "healthy: recorded server-side")
    ok(live.pending_offline == 0, "healthy: nothing buffered")
    ok((state / "device.json").exists(), "device key provisioned automatically")
    ok((state / "bundle.json").exists(), "rules cached for an outage")

    # --- 2. Outage ---------------------------------------------------------
    down = AttestClient(api_key=api_key, base_url=DEAD, state_dir=state, server_timeout=2)
    flagged = down.gate({"text": "declined", "_classifier_tier": "discriminatory_lending"})
    ok(flagged.buffered and not flagged.recorded, "outage: event buffered, not recorded")
    ok(flagged.offline, "outage: verdict computed locally")
    ok(flagged.status == "flagged", f"outage: correct verdict offline ({flagged.status})")
    ok(flagged.jurisdictions == ["difc"],
       "outage: DIFC finding still raised (packs were synced)")

    blocked = down.gate({"amount": 900}, action="wire_transfer")
    ok(blocked.blocked, "outage: own policy still blocks")

    clean = down.gate({"text": "fine"})
    ok(clean.compliant, "outage: clean output still judged compliant")
    ok(down.pending_offline == 3, f"outage: 3 events queued (got {down.pending_offline})")

    # --- 3. Process restart mid-outage -------------------------------------
    restarted = AttestClient(api_key=api_key, base_url=DEAD, state_dir=state, server_timeout=2)
    ok(restarted.pending_offline == 3, "restart: the queue survived on disk")
    raw = (state / "buffer.jsonl").read_bytes()
    ok(b"discriminatory_lending" not in raw, "restart: buffered payloads are encrypted at rest")

    # --- 4. Recovery -------------------------------------------------------
    recovered = AttestClient(api_key=api_key, base_url=BASE, state_dir=state)
    sent = recovered.flush_offline()
    ok(sent == 3, f"recovery: all 3 events handed over (got {sent})")
    ok(recovered.pending_offline == 0, "recovery: queue drained")

    decisions = rq.get(f"{BASE}/v1/policies/decisions?limit=100",
                       headers={"x-api-key": api_key}).json()
    statuses = sorted(d["status"] for d in decisions)
    ok(statuses == sorted(["compliant", "flagged", "blocked", "compliant"]),
       f"recovery: every outage decision reached the dashboard ({statuses})")

    # The grafted events are marked deferred and still verify.
    for d in decisions:
        replay = rq.get(f"{BASE}/v1/trace/{d['trace_id']}/replay",
                        headers={"x-api-key": api_key}).json()
        ok(replay["all_verified"], f"recovery: trace {d['trace_id'][:8]} verifies")

    # A further gate() drains automatically, without an explicit flush.
    down2 = AttestClient(api_key=api_key, base_url=DEAD, state_dir=state, server_timeout=2)
    down2.gate({"text": "during a second blip"})
    ok(down2.pending_offline == 1, "second outage: buffered again")
    back = AttestClient(api_key=api_key, base_url=BASE, state_dir=state)
    back.gate({"text": "back up"})
    ok(back.pending_offline == 0, "recovery: the next gate() drained it automatically")

    print("\nALL OUTAGE E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
