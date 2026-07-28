"""Slice 4: per-org signing keys.

An org with its own key signs under it (key-id recorded per event) and verifies;
an org without one falls back to the global service key; and after rotation, the
old key's events still verify under the retired key.
"""

from __future__ import annotations

import uuid

import pytest

from app.db.models import Event, Org
from app.services import org_signing
from app.services.events import record_event
from app.services.replay import replay_trace


@pytest.fixture()
def db(db_available: bool):
    if not db_available:
        pytest.skip("PostgreSQL not available")
    from app.db.session import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _org(db) -> str:
    org_id = f"org_{uuid.uuid4().hex[:10]}"
    db.add(Org(id=org_id, name="T", api_key_hash=uuid.uuid4().hex))
    db.flush()
    return org_id


def _record(db, org_id, trace, seq, etype="model_completion") -> None:
    record_event(
        db, org_id=org_id, trace_id=trace, seq=seq, event_type=etype,
        payload={"n": seq}, policy_version=None,
    )


def test_per_org_key_signs_and_verifies(db) -> None:
    org_id = _org(db)
    key = org_signing.provision_managed_signing_key(db, org_id)
    trace = uuid.uuid4()
    _record(db, org_id, trace, 1)
    _record(db, org_id, trace, 2, etype="tool_call")

    ev1 = db.query(Event).filter(Event.trace_id == trace, Event.seq == 1).one()
    assert ev1.signing_key_id == key.key_id  # signed under the org's own key

    assert replay_trace(db, org_id=org_id, trace_id=trace).all_verified is True


def test_without_per_org_key_falls_back_to_global(db) -> None:
    org_id = _org(db)  # no key provisioned
    trace = uuid.uuid4()
    _record(db, org_id, trace, 1)

    ev = db.query(Event).filter(Event.trace_id == trace, Event.seq == 1).one()
    assert ev.signing_key_id is None  # global service key

    assert replay_trace(db, org_id=org_id, trace_id=trace).all_verified is True


def test_retired_key_events_still_verify_after_rotation(db) -> None:
    org_id = _org(db)
    k1 = org_signing.provision_managed_signing_key(db, org_id)
    trace = uuid.uuid4()
    _record(db, org_id, trace, 1)
    ev = db.query(Event).filter(Event.trace_id == trace, Event.seq == 1).one()
    assert ev.signing_key_id == k1.key_id

    # Rotate: k1 is retired, a new active key is created.
    k2 = org_signing.provision_managed_signing_key(db, org_id)
    db.refresh(k1)
    assert k1.status == "retired"
    assert k2.status == "active"

    # The old event still verifies under the retired key.
    assert replay_trace(db, org_id=org_id, trace_id=trace).all_verified is True
