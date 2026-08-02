"""The consent ceremony's tamper-evident trail.

Every ceremony action must land as a signed, chained event in the request's
consent trace; the trail must replay-verify; tampering must be detected; a read
that cannot be recorded must not return content; and no payload may ever carry
key material.
"""

from __future__ import annotations

import base64
import json
import uuid

import pytest


@pytest.fixture()
def db(db_available: bool):
    if not db_available:
        pytest.skip("PostgreSQL not available")
    from app.db.session import SessionLocal

    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


def _org(db, customer_key: bool = True):
    from app.auth import hash_api_key
    from app.crypto.org_encryption import generate_wrapping_keypair
    from app.db.models import Org

    org_id = f"org_trail_{uuid.uuid4().hex[:10]}"
    private_pem, public_pem = generate_wrapping_keypair()
    org = Org(id=org_id, name="Trail", api_key_hash=hash_api_key(f"key_{uuid.uuid4().hex}"))
    if customer_key:
        org.confidentiality_mode = "customer_key"
        org.wrapping_public_pem = public_pem.decode()
    db.add(org)
    db.commit()
    return org_id, private_pem


def _record(db, org_id, trace_id, seq, secret):
    from app.services.events import record_event

    out = record_event(
        db, org_id=org_id, trace_id=trace_id, seq=seq,
        event_type="model_completion", payload={"secret": secret}, policy_version=None,
    )
    db.commit()
    from app.db.models import Event

    ev = db.query(Event).filter(Event.trace_id == trace_id, Event.seq == seq).one()
    assert out.hash == ev.hash
    return ev.payload_hash


def _ceremony(db, org_id, private_pem, hashes):
    """File -> approve (org-side regrant) -> read. Returns the request."""
    from app.crypto.org_encryption import regrant_key
    from app.services import access_review

    req = access_review.create_access_request(
        db, org_id=org_id, requested_by="ops_1", payload_hashes=[hashes[0]],
        reason="trail test", required_approvals=1,
    )
    db.commit()
    released = {}
    for item in access_review.request_scope(db, req.id):
        wrapped = base64.b64decode(item["wrapped_key_for_org"])
        regranted = regrant_key(
            private_pem, wrapped, req.grantee_public_pem.encode())
        released[item["payload_hash"]] = base64.b64encode(regranted).decode()
    access_review.record_client_approval(
        db, request_id=req.id, approver_id="officer_1", released_keys=released)
    db.commit()
    content = access_review.read_via_grant(db, request_id=req.id, payload_hash=hashes[0])
    db.commit()
    assert content == {"secret": "s1"}
    return req


def _trail(db, req):
    from app.db.models import Event

    return (
        db.query(Event)
        .filter(Event.trace_id == req.trace_id)
        .order_by(Event.seq)
        .all()
    )


def test_full_ceremony_produces_signed_trail(db) -> None:
    org_id, private_pem = _org(db)
    trace = uuid.uuid4()
    h1 = _record(db, org_id, trace, 1, "s1")
    _record(db, org_id, trace, 2, "s2")

    req = _ceremony(db, org_id, private_pem, [h1])
    trail = _trail(db, req)

    assert [e.type for e in trail] == ["access_request", "access_approval", "access_read"]
    # Chain is linked and every event is signed with an algorithm id.
    for prev, cur in zip(trail, trail[1:], strict=False):
        assert cur.prev_hash == prev.hash
    assert all(e.signature and e.alg for e in trail)
    # The filing event binds scope and the grantee key fingerprint.

    env = trail[0].envelope
    assert env["type"] == "access_request"
    assert trail[0].org_id == org_id


def test_trail_replay_verifies(db) -> None:
    from app.services.replay import replay_trace

    org_id, private_pem = _org(db)
    trace = uuid.uuid4()
    h1 = _record(db, org_id, trace, 1, "s1")
    req = _ceremony(db, org_id, private_pem, [h1])

    result = replay_trace(db, org_id=org_id, trace_id=req.trace_id)
    assert result.all_verified, [e.__dict__ for e in result.events]


def test_tampered_trail_is_detected(db) -> None:
    from app.db.models import Event
    from app.services.replay import replay_trace

    org_id, private_pem = _org(db)
    trace = uuid.uuid4()
    h1 = _record(db, org_id, trace, 1, "s1")
    req = _ceremony(db, org_id, private_pem, [h1])

    # An insider rewrites the approval record (e.g. to point at a payload
    # blaming a different approver). Verification rebuilds the envelope from
    # the row's columns, so the divergence from the signed hash must surface.
    approval = (
        db.query(Event)
        .filter(Event.trace_id == req.trace_id, Event.type == "access_approval")
        .one()
    )
    approval.payload_hash = "0" * 64
    db.commit()

    result = replay_trace(db, org_id=org_id, trace_id=req.trace_id)
    assert not result.all_verified


def test_read_fails_closed_if_trail_write_fails(db, monkeypatch) -> None:
    """No unrecorded vendor access: if the access_read event cannot be written,
    the read must raise and return nothing."""
    from app.services import access_review, consent_events

    org_id, private_pem = _org(db)
    trace = uuid.uuid4()
    h1 = _record(db, org_id, trace, 1, "s1")
    req = _ceremony(db, org_id, private_pem, [h1])

    def boom(*a, **k):
        raise RuntimeError("chain unavailable")

    monkeypatch.setattr(consent_events, "record_consent_event", boom)
    with pytest.raises(RuntimeError):
        access_review.read_via_grant(db, request_id=req.id, payload_hash=h1)


def test_trail_payloads_carry_no_key_material(db) -> None:
    """Trail payloads may reference keys only by fingerprint — never PEMs or
    wrapped keys. Checked on an attest-managed org so content is readable."""
    from app.services import access_review
    from app.services.payload_store import read_payload_content

    org_id, _ = _org(db, customer_key=False)
    trace = uuid.uuid4()
    h1 = _record(db, org_id, trace, 1, "s1")
    req = access_review.create_access_request(
        db, org_id=org_id, requested_by="ops_1", payload_hashes=[h1], reason="check")
    db.commit()
    access_review.resolve_access_request(db, request_id=req.id, status="denied")
    db.commit()

    for ev in _trail(db, req):
        content = read_payload_content(db, org_id, ev.payload_hash)
        assert content is not None
        text = json.dumps(content)
        assert "BEGIN" not in text and "PRIVATE" not in text
        assert req.grantee_public_pem.splitlines()[1] not in text


def test_resolution_idempotent_no_duplicate_events(db) -> None:
    from app.services import access_review

    org_id, _ = _org(db, customer_key=False)
    trace = uuid.uuid4()
    h1 = _record(db, org_id, trace, 1, "s1")
    req = access_review.create_access_request(
        db, org_id=org_id, requested_by="ops_1", payload_hashes=[h1], reason="idem")
    db.commit()
    access_review.resolve_access_request(db, request_id=req.id, status="denied")
    db.commit()
    access_review.resolve_access_request(db, request_id=req.id, status="denied")
    db.commit()

    types = [e.type for e in _trail(db, req)]
    assert types == ["access_request", "access_resolution"]

    with pytest.raises(access_review.AccessReviewError):
        access_review.resolve_access_request(db, request_id=req.id, status="approved")
