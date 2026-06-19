"""Evidence bundle manifest and compliance summary (Week 12)."""

from __future__ import annotations

import json
import uuid
import zipfile
from io import BytesIO

import pytest
from fastapi.testclient import TestClient

DEV_API_KEY = "org_demo_key"


@pytest.fixture(scope="module")
def client(db_available: bool) -> TestClient:
    if not db_available:
        pytest.skip("PostgreSQL not available — run: docker compose up -d")
    from app.main import app

    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"x-api-key": DEV_API_KEY}


@pytest.fixture(scope="module", autouse=True)
def seed_policy(db_available: bool) -> None:
    if not db_available:
        return
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [sys.executable, str(root / "scripts" / "seed_dev_policy.py")],
        check=True,
        capture_output=True,
    )


def _record_and_precheck_red(client: TestClient) -> str:
    trace_id = str(uuid.uuid4())
    precheck = client.post(
        "/v1/precheck",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "action": "wire_transfer",
            "payload": {"amount_aed": 90000},
        },
    )
    assert precheck.status_code == 200, precheck.text
    return trace_id


def test_evidence_includes_manifest_and_compliance(client: TestClient) -> None:
    trace_id = _record_and_precheck_red(client)
    response = client.get(f"/v1/evidence/{trace_id}/export", headers=_headers())
    assert response.status_code == 200
    bundle = response.json()
    assert bundle["bundle_schema"] == "1.0"
    assert bundle["manifest"]["signing"]["backend"] == "local"
    assert bundle["compliance_summary"]["org_id"] == "org_demo"
    assert bundle["compliance_summary"]["policy_decisions"]
    assert bundle["compliance_summary"]["workflow_gate"]["workflow_status"]


def test_evidence_zip_has_manifest_files(client: TestClient) -> None:
    trace_id = str(uuid.uuid4())
    client.post(
        "/v1/event",
        headers=_headers(),
        json={
            "trace_id": trace_id,
            "seq": 1,
            "type": "model_completion",
            "payload": {"step": 1},
            "policy_version": "v0",
        },
    )
    response = client.get(
        f"/v1/evidence/{trace_id}/export?format=zip",
        headers=_headers(),
    )
    assert response.status_code == 200
    with zipfile.ZipFile(BytesIO(response.content)) as zf:
        names = set(zf.namelist())
        assert "manifest.json" in names
        assert "compliance_summary.json" in names
        manifest = json.loads(zf.read("manifest.json"))
        assert manifest["bundle_schema"] == "1.0"


def test_health_reports_signing_backend(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["signing_backend"] == "local"
