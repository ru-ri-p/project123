#!/usr/bin/env python3
"""Tradeeasy-style demo workflow — record a market summary trace via the SDK."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attest_sdk.attest import AttestClient

API_KEY = "org_demo_key"
BASE_URL = "http://127.0.0.1:8000"


def main() -> None:
    client = AttestClient(api_key=API_KEY, base_url=BASE_URL)
    trace_id = client.new_trace()

    client.record_event(
        trace_id,
        1,
        "model_completion",
        {
            "prompt": "Summarise Q1 market conditions for UAE equities",
            "output": "Markets showed moderate growth with sector rotation into financials.",
            "citations": 3,
        },
        policy_version="v0",
    )
    client.record_event(
        trace_id,
        2,
        "tool_call",
        {"tool": "market_data_fetch", "symbols": ["DFMGI", "ADXGI"], "rows": 120},
    )
    client.record_event(
        trace_id,
        3,
        "model_completion",
        {
            "prompt": "Finalize summary with citations",
            "output": "Q1 summary complete with 3 primary sources cited.",
            "citations": 3,
        },
    )

    print(f"Trace recorded: {trace_id}")
    print(f"Replay:  GET {BASE_URL}/v1/trace/{trace_id}/replay")
    print(f"Export:  GET {BASE_URL}/v1/evidence/{trace_id}/export")


if __name__ == "__main__":
    main()
