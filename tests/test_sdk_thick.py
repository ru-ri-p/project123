"""Thick SDK — local precheck, buffer, and server escalation."""

from __future__ import annotations

import subprocess
import sys
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import requests
from fastapi.testclient import TestClient

from sdk.attest import AttestClient

ROOT = Path(__file__).resolve().parents[1]
API_KEY = "org_demo_key"
BASE = "http://testserver"


class _MockResponse:
    def __init__(self, response: Any) -> None:
        self._response = response
        self.status_code = response.status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)

    def json(self) -> dict[str, Any]:
        return self._response.json()


@pytest.fixture(scope="module")
def api_base(db_available: bool) -> Generator[str, None, None]:
    if not db_available:
        pytest.skip("PostgreSQL not available")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_dev_org.py")],
        check=True,
        cwd=ROOT,
    )
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_dev_policy.py")],
        check=True,
        cwd=ROOT,
    )
    from app.main import app

    tc = TestClient(app)

    def post(url: str, **kwargs: Any) -> _MockResponse:
        path = url.replace(BASE, "") or "/"
        return _MockResponse(tc.post(path, headers=kwargs.get("headers"), json=kwargs.get("json")))

    def get(url: str, **kwargs: Any) -> _MockResponse:
        path = url.replace(BASE, "") or "/"
        return _MockResponse(tc.get(path, headers=kwargs.get("headers")))

    with (
        patch("sdk.attest.requests.post", side_effect=post),
        patch("sdk.attest.requests.get", side_effect=get),
    ):
        yield BASE


def test_precheck_smart_green_skips_server_precheck(api_base: str) -> None:
    client = AttestClient(api_key=API_KEY, base_url=api_base, enable_buffer=False)
    client.load_policy_bundle(force=True)

    with patch.object(client, "precheck") as mock_server:
        result = client.precheck_smart(
            str(uuid.uuid4()),
            1,
            "model_completion",
            {"prompt": "Market outlook", "citations": 3},
        )
        mock_server.assert_not_called()

    assert result["tier"] == "green"
    assert result["local_only"] is True
    assert result["escalated"] is False


def test_precheck_smart_red_escalates_to_server(api_base: str) -> None:
    trace_id = str(uuid.uuid4())
    client = AttestClient(api_key=API_KEY, base_url=api_base, enable_buffer=False)
    client.load_policy_bundle(force=True)

    result = client.precheck_smart(trace_id, 1, "wire_transfer", {"amount_aed": 5000})
    assert result["escalated"] is True
    assert result["local_only"] is False
    assert result["tier"] == "red"
    assert result.get("approval_id")


def test_buffered_record_event_flushes(api_base: str) -> None:
    trace_id = str(uuid.uuid4())
    client = AttestClient(api_key=API_KEY, base_url=api_base, enable_buffer=True)
    client.load_policy_bundle(force=True)

    out = client.record_event(
        trace_id,
        1,
        "model_completion",
        {"output": "Buffered write test"},
        buffered=True,
    )
    assert out.get("buffered") is True

    drained = client.flush(timeout=10.0)
    assert drained >= 1
    assert not client.buffer_errors

    gate = client.workflow_gate(trace_id)
    assert gate["workflow_status"] == "proceed"
    client.close()
