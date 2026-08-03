"""Surviving an Attest outage without punching a hole in the audit trail.

The guarantees under test:
  * the SDK's claim definition and the server's verifier agree byte-for-byte;
  * a segment is accepted only if every signature and chain link holds, and is
    refused as a WHOLE (no half-grafted trail);
  * an edited payload, a broken chain, a foreign key or an unknown device are
    all rejected;
  * grafted events are marked deferred and carry the customer's claimed time
    alongside Attest's own — the gap is evidenced, never disguised as realtime.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

ADMIN_KEY = "test-admin-key"


@pytest.fixture(scope="module", autouse=True)
def _admin_env():
    os.environ["ADMIN_API_KEY"] = ADMIN_KEY
    from app.config import get_settings

    get_settings.cache_clear()
    yield
    del os.environ["ADMIN_API_KEY"]
    get_settings.cache_clear()


@pytest.fixture()
def client(db_available: bool):
    if not db_available:
        pytest.skip("PostgreSQL not available")
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


def _org(client) -> str:
    org_id = f"org_off_{uuid.uuid4().hex[:10]}"
    key = client.post(
        "/v1/admin/orgs", headers={"x-admin-key": ADMIN_KEY},
        json={"org_id": org_id, "name": "Offline Test"},
    ).json()["api_key"]
    client.put("/v1/policies/internal", headers={"x-api-key": key}, json={
        "name": "Internal", "version": "v1", "activate": True,
        "rules": {"schema_version": 2, "engine": "json", "rules": []}})
    return key


def _device(tmp_path: Path):
    from attest_sdk.device import DeviceKey

    return DeviceKey.load_or_create(tmp_path)


def _signed_item(
    device, *, action, output, local_seq, prev_local,
    occurred_at="2026-08-03T10:00:00+00:00",
):
    from attest_sdk.canonical import sha256_hex
    from attest_sdk.offline_envelope import build_offline_claim, offline_claim_hash

    claim = build_offline_claim(
        device_id=device.device_id, local_seq=local_seq, prev_local=prev_local,
        occurred_at=occurred_at, action=action, payload_hash=sha256_hex(output),
    )
    digest = offline_claim_hash(claim)
    return {
        "action": action, "output": output, "occurred_at": occurred_at,
        "local_seq": local_seq, "prev_local": prev_local,
        "payload_hash": claim["payload_hash"],
        "client_signature": device.sign_hex(digest),
    }, digest


def test_sdk_and_server_claim_definitions_agree() -> None:
    """Duplicated on purpose (the SDK cannot import the server) — so assert they
    never drift, because divergence would silently break every signature."""
    import inspect

    from app.crypto import offline_envelope as server
    from attest_sdk import offline_envelope as sdk

    for fn in ("build_offline_claim", "offline_claim_hash"):
        assert inspect.getsource(getattr(server, fn)) == inspect.getsource(getattr(sdk, fn)), fn
    assert server.OFFLINE_CLAIM_VERSION == sdk.OFFLINE_CLAIM_VERSION

    # And they produce identical digests for the same input.
    args = dict(device_id="d", local_seq=1, prev_local=None,
                occurred_at="2026-01-01T00:00:00+00:00", action="a", payload_hash="h")
    server_digest = server.offline_claim_hash(server.build_offline_claim(**args))
    sdk_digest = sdk.offline_claim_hash(sdk.build_offline_claim(**args))
    assert server_digest == sdk_digest


def test_buffered_segment_is_verified_and_grafted(client, tmp_path) -> None:
    key = _org(client)
    device = _device(tmp_path)
    client.post("/v1/sdk/devices", headers={"x-api-key": key}, json={
        "device_id": device.device_id, "public_pem": device.public_pem.decode()})

    a, ha = _signed_item(device, action="model_completion", output={"n": 1},
                         local_seq=1, prev_local=None)
    b, _ = _signed_item(device, action="tool_call", output={"n": 2},
                        local_seq=2, prev_local=ha)

    r = client.post("/v1/sdk/replay", headers={"x-api-key": key},
                    json={"device_id": device.device_id, "items": [a, b]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 2
    assert all(item["deferred"] is True for item in body["results"])
    assert body["results"][0]["occurred_at"] == a["occurred_at"]

    # The grafted events are real, chained, verifiable events.
    trace = body["results"][0]["trace_id"]
    assert client.get(f"/v1/trace/{trace}/replay",
                      headers={"x-api-key": key}).json()["all_verified"] is True


def test_edited_payload_is_rejected(client, tmp_path) -> None:
    """The signature binds the content; swapping it after signing must fail."""
    key = _org(client)
    device = _device(tmp_path)
    client.post("/v1/sdk/devices", headers={"x-api-key": key}, json={
        "device_id": device.device_id, "public_pem": device.public_pem.decode()})

    item, _ = _signed_item(device, action="model_completion", output={"n": 1},
                           local_seq=1, prev_local=None)
    item["output"] = {"n": 999}  # tampered after signing

    r = client.post("/v1/sdk/replay", headers={"x-api-key": key},
                    json={"device_id": device.device_id, "items": [item]})
    assert r.status_code == 422
    assert "payload" in r.json()["detail"]


def test_broken_local_chain_is_rejected_wholesale(client, tmp_path) -> None:
    """Removing an event from the middle must invalidate the segment, and the
    valid events around it must NOT be recorded either."""
    key = _org(client)
    device = _device(tmp_path)
    client.post("/v1/sdk/devices", headers={"x-api-key": key}, json={
        "device_id": device.device_id, "public_pem": device.public_pem.decode()})

    a, ha = _signed_item(device, action="a", output={"n": 1}, local_seq=1, prev_local=None)
    _, hb = _signed_item(device, action="b", output={"n": 2}, local_seq=2, prev_local=ha)
    c, _ = _signed_item(device, action="c", output={"n": 3}, local_seq=3, prev_local=hb)

    before = len(client.get("/v1/traces", headers={"x-api-key": key}).json())
    r = client.post("/v1/sdk/replay", headers={"x-api-key": key},
                    json={"device_id": device.device_id, "items": [a, c]})  # b dropped
    assert r.status_code == 422
    assert "chain" in r.json()["detail"]
    after = len(client.get("/v1/traces", headers={"x-api-key": key}).json())
    assert before == after, "a refused segment must write nothing at all"


def test_foreign_key_and_unknown_device_are_rejected(client, tmp_path) -> None:
    key = _org(client)
    device = _device(tmp_path / "real")
    attacker = _device(tmp_path / "attacker")
    client.post("/v1/sdk/devices", headers={"x-api-key": key}, json={
        "device_id": device.device_id, "public_pem": device.public_pem.decode()})

    # Signed by a different key, submitted under the registered device id.
    item, _ = _signed_item(attacker, action="a", output={"n": 1}, local_seq=1, prev_local=None)
    item_for_real_device = dict(item)
    r = client.post("/v1/sdk/replay", headers={"x-api-key": key},
                    json={"device_id": device.device_id, "items": [item_for_real_device]})
    assert r.status_code == 422

    # Never-registered device.
    good, _ = _signed_item(device, action="a", output={"n": 1}, local_seq=1, prev_local=None)
    r = client.post("/v1/sdk/replay", headers={"x-api-key": key},
                    json={"device_id": "nope-0000000000", "items": [good]})
    assert r.status_code == 422
    assert "unknown device" in r.json()["detail"]


def test_device_id_cannot_be_rebound_to_a_new_key(client, tmp_path) -> None:
    """Otherwise an old device's signed history would validate against a new key."""
    key = _org(client)
    first = _device(tmp_path / "one")
    second = _device(tmp_path / "two")
    client.post("/v1/sdk/devices", headers={"x-api-key": key}, json={
        "device_id": first.device_id, "public_pem": first.public_pem.decode()})

    r = client.post("/v1/sdk/devices", headers={"x-api-key": key}, json={
        "device_id": first.device_id, "public_pem": second.public_pem.decode()})
    assert r.status_code == 409

    # Re-registering the SAME key is fine (restarts must not break).
    r = client.post("/v1/sdk/devices", headers={"x-api-key": key}, json={
        "device_id": first.device_id, "public_pem": first.public_pem.decode()})
    assert r.status_code == 200


def test_bundle_carries_policy_and_adopted_packs(client) -> None:
    """Without the packs a local verdict would silently omit findings the server
    would have raised — same output, different answer depending on our uptime."""
    key = _org(client)
    org_id = client.get("/v1/org/me", headers={"x-api-key": key}).json()["id"]
    client.post("/v1/admin/regulation-packs/seed", headers={"x-admin-key": ADMIN_KEY})
    client.post(f"/v1/admin/orgs/{org_id}/regulation-packs",
                headers={"x-admin-key": ADMIN_KEY}, json={"pack_code": "difc_dp_reg10"})

    bundle = client.get("/v1/sdk/bundle", headers={"x-api-key": key}).json()
    assert bundle["policy_version"] == "v1"
    assert [p["code"] for p in bundle["packs"]] == ["difc_dp_reg10"]
    assert bundle["packs"][0]["rules"], "pack rules must be shipped for local evaluation"


def test_local_verdict_matches_the_server(client, tmp_path) -> None:
    """The whole point of shipping packs: one output, one answer, up or down."""
    from attest_sdk.offline import OfflineBundle

    key = _org(client)
    org_id = client.get("/v1/org/me", headers={"x-api-key": key}).json()["id"]
    client.post("/v1/admin/regulation-packs/seed", headers={"x-admin-key": ADMIN_KEY})
    client.post(f"/v1/admin/orgs/{org_id}/regulation-packs",
                headers={"x-admin-key": ADMIN_KEY}, json={"pack_code": "difc_dp_reg10"})

    bundle = OfflineBundle(client.get("/v1/sdk/bundle", headers={"x-api-key": key}).json(),
                           tmp_path)
    payload = {"text": "declined", "_classifier_tier": "discriminatory_lending"}
    local = bundle.evaluate("model_completion", payload)
    served = client.post("/v1/gate", headers={"x-api-key": key},
                         json={"action": "model_completion", "output": payload}).json()

    assert local["status"] == served["status"] == "flagged"
    assert local["tier"] == served["tier"]
    assert local["jurisdictions"] == served["jurisdictions"]
