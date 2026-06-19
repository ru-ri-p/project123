#!/usr/bin/env python3
"""End-to-end enforcement demo: RED precheck → gate → approve → resume → record."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sdk.attest import AttestClient

API_KEY = "org_demo_key"
BASE_URL = "http://127.0.0.1:8000"


def main() -> None:
    client = AttestClient(api_key=API_KEY, base_url=BASE_URL)
    trace_id = client.new_trace()

    print(f"Trace: {trace_id}")
    decision = client.precheck(
        trace_id,
        1,
        "wire_transfer",
        {"amount_aed": 75000, "beneficiary": "ACME Trading LLC"},
    )
    print(f"Precheck tier={decision['tier']} allowed={decision['allowed']}")
    print(f"  approval_id={decision.get('approval_id')}")
    print(f"  mitigations={decision.get('mitigations')}")

    gate = client.workflow_gate(trace_id)
    print(f"Gate: {gate['workflow_status']} resume_allowed={gate['resume_allowed']}")

    approval_id = decision.get("approval_id")
    if not approval_id:
        print("No approval required — exiting.")
        return

    if gate["resume_allowed"]:
        print("Already allowed to resume.")
    else:
        print("Approve in dashboard or via API, then re-run with --approve")
        if "--approve" not in sys.argv:
            return
        result = client.resolve_approval(
            approval_id,
            "approved",
            "demo_officer",
            "Demo approval for enforcement workflow",
        )
        print(f"Resolved: resume_allowed={result['resume_allowed']}")
        gate = client.workflow_gate(trace_id)
        print(f"Gate after approve: {gate['workflow_status']}")

    if client.workflow_gate(trace_id)["resume_allowed"]:
        # seq 1 = policy_decision; seq 2 = approval_action after resolve
        event = client.record_event(
            trace_id,
            3,
            "model_completion",
            {"output": "Wire transfer executed after human approval"},
        )
        print(f"Recorded post-approval event seq={event['seq']} hash={event['hash'][:16]}...")
    else:
        print("Workflow still blocked — cannot record follow-up event.")


if __name__ == "__main__":
    main()
