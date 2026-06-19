#!/usr/bin/env python3
"""Design-partner 'done when' demo (instructions §3 Phase 4).

Run workflow → RED precheck → human approve → export evidence → offline verify.py
→ ALL EVENTS VERIFIED.

Requires API + DB + seed:
  uvicorn app.main:app --reload
  python scripts/seed_dev_org.py && python scripts/seed_dev_policy.py
  python scripts/demo_design_partner.py --approve
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
VERIFY_SCRIPT = ROOT / "app" / "bundle" / "verify.py"
API_KEY = "org_demo_key"
BASE_URL = "http://127.0.0.1:8000"


def _headers() -> dict[str, str]:
    return {"x-api-key": API_KEY, "Content-Type": "application/json"}


def main() -> None:
    health = requests.get(f"{BASE_URL}/health", timeout=5)
    health.raise_for_status()
    print(f"API health: {health.json()}")

    from sdk.attest import AttestClient

    client = AttestClient(api_key=API_KEY, base_url=BASE_URL)
    trace_id = client.new_trace()
    print(f"\n1. Trace created: {trace_id}")

    decision = client.precheck(
        trace_id,
        1,
        "wire_transfer",
        {"amount_aed": 85000, "beneficiary": "Design Partner Demo LLC"},
    )
    print(f"2. Precheck: tier={decision['tier']} allowed={decision['allowed']}")
    approval_id = decision.get("approval_id")
    if not approval_id:
        print("   Expected RED/orange with approval — check seed_dev_policy.py")
        sys.exit(1)

    gate = client.workflow_gate(trace_id)
    print(f"3. Gate: {gate['workflow_status']} resume_allowed={gate['resume_allowed']}")

    if not gate["resume_allowed"]:
        if "--approve" not in sys.argv:
            print("\n   Re-run with --approve after risk officer review (or use dashboard).")
            sys.exit(0)
        result = client.resolve_approval(
            approval_id,
            "approved",
            "design_partner_officer",
            "Design partner pilot — documented human oversight",
        )
        print(f"4. Approved: resume_allowed={result['resume_allowed']}")
        gate = client.workflow_gate(trace_id)

    if not gate["resume_allowed"]:
        print("Workflow still blocked.")
        sys.exit(1)

    event = client.record_event(
        trace_id,
        3,
        "model_completion",
        {"output": "Action executed after documented approval"},
    )
    print(f"5. Post-approval event seq={event['seq']} hash={event['hash'][:16]}...")

    export = requests.get(
        f"{BASE_URL}/v1/evidence/{trace_id}/export",
        headers={"x-api-key": API_KEY},
        timeout=30,
    )
    export.raise_for_status()
    bundle = export.json()
    assert bundle["replay_summary"]["all_verified"] is True
    assert bundle.get("manifest")
    assert bundle.get("compliance_summary")
    print(f"6. Evidence exported (schema {bundle.get('bundle_schema')})")
    print(f"   Signing: {bundle['manifest']['signing']['backend']}")
    print(f"   Workflow: {bundle['compliance_summary']['workflow_gate']['workflow_status']}")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        bundle_path = tmp_path / "bundle.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        zip_path = tmp_path / "evidence.zip"
        zip_resp = requests.get(
            f"{BASE_URL}/v1/evidence/{trace_id}/export?format=zip",
            headers={"x-api-key": API_KEY},
            timeout=30,
        )
        zip_resp.raise_for_status()
        zip_path.write_bytes(zip_resp.content)
        with zipfile.ZipFile(zip_path) as zf:
            names = set(zf.namelist())
        print(f"7. ZIP contents: {', '.join(sorted(names))}")

        result = subprocess.run(
            [sys.executable, str(VERIFY_SCRIPT), str(bundle_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            sys.exit(result.returncode)

    print("\nDone — risk officer can run verify.py on their machine with zero server access.")
    print(f"Dashboard: http://localhost:3000/traces/{trace_id}")


if __name__ == "__main__":
    main()
