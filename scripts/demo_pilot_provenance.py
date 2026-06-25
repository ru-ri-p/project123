#!/usr/bin/env python3
"""Provenance-only pilot demo: record 100+ events the way TradeEasy would.

Each "transaction" (one AI-synthesized output) is a trace; each step inside it
(model completion, tool call) is a signed, hash-chained event. After recording,
every trace is replayed and one evidence bundle is exported.

The Attest API must be running and reachable, e.g.:
    uvicorn app.main:app

Usage:
    python scripts/demo_pilot_provenance.py \
        --base-url http://localhost:8000 --api-key org_demo_key --transactions 25
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sdk.attest import AttestClient  # noqa: E402

# One synthetic transaction = these steps (no customer data — pilot is synthetic).
STEPS = [
    ("model_completion", {"action": "classify_listing", "output": "category=electronics"}),
    ("tool_call", {"tool": "price_lookup", "args": {"sku": "DEMO"}, "result": "AED 199"}),
    ("model_completion", {"action": "synthesize_description", "output": "..."}),
    ("tool_call", {"tool": "policy_lookup", "result": "ok"}),
    ("model_completion", {"action": "finalize_output", "output": "published"}),
]


def record_transactions(client: AttestClient, count: int) -> list[str]:
    trace_ids: list[str] = []
    total_events = 0
    for n in range(count):
        trace_id = client.new_trace()
        for i, (event_type, payload) in enumerate(STEPS, start=1):
            client.record_event(trace_id, i, event_type, {**payload, "txn": n})
            total_events += 1
        trace_ids.append(trace_id)
    print(f"Recorded {count} transactions, {total_events} events total")
    return trace_ids


def replay_all(base_url: str, api_key: str, trace_ids: list[str]) -> bool:
    headers = {"x-api-key": api_key}
    all_ok = True
    for trace_id in trace_ids:
        resp = requests.get(f"{base_url}/v1/trace/{trace_id}/replay", headers=headers, timeout=30)
        resp.raise_for_status()
        if not resp.json().get("all_verified"):
            all_ok = False
            print(f"  trace {trace_id}: NOT verified")
    print(f"Replay of {len(trace_ids)} traces: all_verified={all_ok}")
    return all_ok


def export_bundle(base_url: str, api_key: str, trace_id: str, out: Path) -> None:
    resp = requests.get(
        f"{base_url}/v1/evidence/{trace_id}/export",
        headers={"x-api-key": api_key},
        timeout=30,
    )
    resp.raise_for_status()
    out.write_text(json.dumps(resp.json(), indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Exported evidence bundle for {trace_id} -> {out}")
    print("Verify offline with:  python app/bundle/verify.py", out)
    print("  add --tsa-roots <trusted TSA root pem> to verify the external anchor")


def main() -> int:
    parser = argparse.ArgumentParser(description="Attest provenance-only pilot demo")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--api-key", default="org_demo_key")
    parser.add_argument("--transactions", type=int, default=25, help="25 x 5 steps = 125 events")
    parser.add_argument("--out", type=Path, default=ROOT / "pilot_bundle.json")
    args = parser.parse_args()

    client = AttestClient(api_key=args.api_key, base_url=args.base_url, enable_local_precheck=False)
    trace_ids = record_transactions(client, args.transactions)
    ok = replay_all(args.base_url, args.api_key, trace_ids)
    export_bundle(args.base_url, args.api_key, trace_ids[-1], args.out)
    client.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
