#!/usr/bin/env python3
"""Thick SDK demo — local green precheck + buffered recording."""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sdk.attest import AttestClient

API_KEY = "org_demo_key"
BASE_URL = "http://127.0.0.1:8000"


def main() -> None:
    client = AttestClient(api_key=API_KEY, base_url=BASE_URL, enable_buffer=True)
    client.load_policy_bundle()
    trace_id = client.new_trace()

    print(f"Trace: {trace_id}")

    start = time.perf_counter()
    decision = client.precheck_smart(
        trace_id,
        1,
        "model_completion",
        {"prompt": "Summarise UAE banking sector", "citations": 2},
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    local_only = decision.get("local_only")
    print(f"Local precheck: tier={decision['tier']} in {elapsed_ms:.2f}ms local_only={local_only}")

    if not decision.get("allowed", True):
        print("Blocked — stopping.")
        client.close()
        return

    seq = client.next_seq(trace_id)
    client.record_event(
        trace_id,
        seq,
        "model_completion",
        {"output": "Sector showed resilience in Q1."},
        buffered=True,
    )
    print(f"Buffered event seq={seq} — flushing...")
    client.flush()
    print(f"Flush complete. buffer_errors={client.buffer_errors}")
    client.close()


if __name__ == "__main__":
    main()
