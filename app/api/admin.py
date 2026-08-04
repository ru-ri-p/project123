"""Attest-ops admin API (x-admin-key) — what the admin dashboard drives.

Everything here requires the ADMIN_API_KEY (503 if unconfigured, 401 on
mismatch). Responses never include secrets: no api_key_hash, no
grantee_private_pem, no wrapped keys. A newly minted org API key appears exactly
once, in the response to the call that created it — only its hash is stored.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.auth import hash_api_key
from app.db.models import (
    AccessGrantKey,
    AccessRequest,
    Event,
    Org,
    RegulationChange,
    RegulationPack,
    RegulationSource,
    Trace,
)
from app.db.session import get_db
from app.schemas import (
    AdminOrgActivity,
    AdminOrgCreateIn,
    AdminOrgKeyOut,
    AdminOrgOut,
    AdminRequestDetailOut,
    AdminRequestOut,
    AdminScopeItem,
    AdminStatsOut,
    AdminTraceEventOut,
    DailyCount,
    EventReplayItem,
    PackSubscriptionIn,
    ProfileChangeRequestOut,
    RegulationChangeOut,
    RegulationPackOut,
    RegulationSourceOut,
    TraceReplayOut,
    WatchRunOut,
)
from app.services import access_review, reg_watch
from app.services import org_profile as profile_service
from app.services import orgs as org_service
from app.services import regulation_packs as pack_service
from app.services.access import TraceNotFoundError
from app.services.replay import replay_trace
from app.services.verification import TraceReplayResult

router = APIRouter(prefix="/v1/admin", dependencies=[Depends(require_admin)])


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid id") from exc


@router.get("/ping")
def ping() -> dict[str, bool]:
    """Auth probe for the dashboard connect button."""
    return {"ok": True}


@router.get("/stats", response_model=AdminStatsOut)
def stats(db: Session = Depends(get_db)) -> AdminStatsOut:
    """Live system health for the ops Overview — real queries, no vanity numbers."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func

    from app.crypto.signing_provider import SigningKeyError, get_signing_provider
    from app.db.models import Anchor, Batch

    try:
        backend = str(get_signing_provider().metadata().get("backend", "unknown"))
    except SigningKeyError:
        backend = "unavailable"

    anchored = db.query(func.count(Anchor.id)).scalar() or 0
    total_batches = db.query(func.count(Batch.id)).scalar() or 0
    last_anchor = db.query(func.max(Anchor.anchored_at)).scalar()
    unbatched = (
        db.query(func.count(Event.id)).filter(Event.batch_id.is_(None)).scalar() or 0
    )

    now = datetime.now(UTC)
    since_24h = now - timedelta(hours=24)
    events_24h = (
        db.query(func.count(Event.id)).filter(Event.created_at >= since_24h).scalar() or 0
    )
    pending_requests = (
        db.query(func.count(AccessRequest.id))
        .filter(AccessRequest.status == "pending")
        .scalar()
        or 0
    )

    window_start = (now - timedelta(days=11)).replace(hour=0, minute=0, second=0, microsecond=0)
    day_col = func.date_trunc("day", Event.created_at)
    rows = (
        db.query(Event.org_id, day_col.label("day"), func.count(Event.id))
        .filter(Event.created_at >= window_start)
        .group_by(Event.org_id, day_col)
        .all()
    )
    by_org: dict[str, dict[str, int]] = {}
    for org_id, day, count in rows:
        by_org.setdefault(org_id, {})[day.strftime("%Y-%m-%d")] = count
    days = [(window_start + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(12)]

    # Only the most recently active orgs — an Overview is a glance, not a census,
    # and computing 12-day sparklines for every customer scales badly.
    active_ids = sorted(by_org, key=lambda oid: sum(by_org[oid].values()), reverse=True)[:12]
    orgs = (
        db.query(Org).filter(Org.id.in_(active_ids)).all()
        if active_ids
        else db.query(Org).order_by(Org.created_at.desc()).limit(12).all()
    )
    activity = [
        AdminOrgActivity(
            id=o.id,
            name=o.name,
            confidentiality_mode=o.confidentiality_mode,
            events_today=by_org.get(o.id, {}).get(days[-1], 0),
            daily=[DailyCount(day=d, count=by_org.get(o.id, {}).get(d, 0)) for d in days],
        )
        for o in orgs
    ]

    return AdminStatsOut(
        signing_backend=backend,
        anchored_batches=anchored,
        pending_batches=max(0, total_batches - anchored),
        last_anchor_at=last_anchor.isoformat() if last_anchor else None,
        unbatched_events=unbatched,
        events_24h=events_24h,
        pending_requests=pending_requests,
        orgs=activity,
    )


# --- Orgs ---------------------------------------------------------------------


def _org_out(org: Org) -> AdminOrgOut:
    return AdminOrgOut(
        id=org.id,
        name=org.name,
        region=org.region,
        confidentiality_mode=org.confidentiality_mode,
        fail_mode=org.fail_mode,
        created_at=org.created_at.isoformat(),
        requires_profile=org.requires_profile,
    )


@router.get("/orgs", response_model=list[AdminOrgOut])
def list_orgs(
    q: str | None = None, limit: int = 100, db: Session = Depends(get_db)
) -> list[AdminOrgOut]:
    """Newest first, bounded, and searchable.

    Deliberately not unbounded: rendering every customer is fine at ten and
    unusable at several hundred, and it makes the org pickers unworkable.
    """
    query = db.query(Org)
    if q:
        needle = f"%{q.strip()}%"
        query = query.filter(Org.id.ilike(needle) | Org.name.ilike(needle))
    orgs = query.order_by(Org.created_at.desc()).limit(max(1, min(limit, 500))).all()
    return [_org_out(o) for o in orgs]


@router.post("/orgs", response_model=AdminOrgKeyOut)
def create_org(body: AdminOrgCreateIn, db: Session = Depends(get_db)) -> AdminOrgKeyOut:
    try:
        org, plaintext_key = org_service.create_org_with_api_key(
            db, org_id=body.org_id, name=body.name, region=body.region, api_key=body.api_key
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    return AdminOrgKeyOut(org_id=org.id, api_key=plaintext_key)


@router.post("/orgs/{org_id}/rotate-key", response_model=AdminOrgKeyOut)
def rotate_org_key(org_id: str, db: Session = Depends(get_db)) -> AdminOrgKeyOut:
    """Mint a fresh API key for an org; the old key stops working immediately."""
    org = db.query(Org).filter(Org.id == org_id).one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="org not found")
    plaintext_key = org_service.generate_api_key(prefix="attest")
    org.api_key_hash = hash_api_key(plaintext_key)
    db.commit()
    return AdminOrgKeyOut(org_id=org_id, api_key=plaintext_key)


@router.post("/orgs/{org_id}/require-onboarding", response_model=AdminOrgOut)
def set_require_onboarding(
    org_id: str, required: bool = True, db: Session = Depends(get_db)
) -> AdminOrgOut:
    """Turn the onboarding requirement on or off for one customer.

    Orgs that predate the gate are grandfathered so a live integration is never
    broken by a deploy. Use this to bring one of them under the gate once they
    are ready — recording stops until they declare a profile, so agree it with
    them first.
    """
    org = db.query(Org).filter(Org.id == org_id).one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="org not found")
    org.requires_profile = required
    db.commit()
    return _org_out(org)


# --- Regulation packs ---------------------------------------------------------


@router.post("/regulation-packs/seed", response_model=list[RegulationPackOut])
def seed_packs(db: Session = Depends(get_db)) -> list[RegulationPackOut]:
    """Publish the bundled starter packs. Idempotent on (code, version).

    Everything published this way is `unverified` — drafted from public sources,
    not transcribed from official texts. It must not be presented to a customer
    as a settled legal position until reviewed.
    """
    packs = pack_service.seed_builtin_packs(db)
    db.commit()
    return [_admin_pack_out(p) for p in packs]


@router.get("/regulation-packs", response_model=list[RegulationPackOut])
def list_regulation_packs(
    jurisdiction: str | None = None, db: Session = Depends(get_db)
) -> list[RegulationPackOut]:
    return [_admin_pack_out(p) for p in pack_service.list_packs(db, jurisdiction)]


def _admin_pack_out(pack: RegulationPack) -> RegulationPackOut:
    doc = pack.rules if isinstance(pack.rules, dict) else {}
    rules = doc.get("rules", [])
    return RegulationPackOut(
        id=str(pack.id),
        code=pack.code,
        jurisdiction=pack.jurisdiction,
        name=pack.name,
        version=pack.version,
        instrument=pack.instrument,
        instrument_notes=pack.instrument_notes,
        source_url=pack.source_url,
        effective_date=pack.effective_date,
        verification_status=pack.verification_status,
        reviewed_by=pack.reviewed_by,
        rule_count=len(rules) if isinstance(rules, list) else 0,
    )


@router.get("/orgs/{org_id}/regulation-packs", response_model=list[RegulationPackOut])
def list_org_packs(org_id: str, db: Session = Depends(get_db)) -> list[RegulationPackOut]:
    """Which jurisdiction rulebooks currently apply to a customer."""
    out = []
    for pack, sub in pack_service.org_subscriptions(db, org_id):
        item = _admin_pack_out(pack)
        item.enabled = sub.enabled
        item.enforcement = sub.enforcement
        out.append(item)
    return out


@router.post("/orgs/{org_id}/regulation-packs", response_model=RegulationPackOut)
def subscribe_org_to_pack(
    org_id: str, body: PackSubscriptionIn, db: Session = Depends(get_db)
) -> RegulationPackOut:
    """Apply a jurisdiction pack to a customer (ops-side onboarding)."""
    if db.query(Org).filter(Org.id == org_id).one_or_none() is None:
        raise HTTPException(status_code=404, detail="org not found")
    try:
        pack_service.subscribe_org(
            db,
            org_id=org_id,
            pack_code=body.pack_code,
            enabled=body.enabled,
            enforcement=body.enforcement,
        )
    except pack_service.PackError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    pack = pack_service.latest_pack_by_code(db, body.pack_code)
    assert pack is not None
    return _admin_pack_out(pack)


# --- Regulation watch (auto-update pipeline) ----------------------------------


@router.post("/regulation-watch/run", response_model=WatchRunOut)
def run_regulation_watch(
    auto_publish: bool = True, db: Session = Depends(get_db)
) -> WatchRunOut:
    """Sweep every registered official source now.

    Also runs on a schedule. Auto-publication is limited to claims provable
    verbatim against the fetched official text; anything needing judgement is
    quarantined. Pass auto_publish=false to observe without publishing.
    """
    summary = reg_watch.run_watch(db, auto_publish=auto_publish)
    db.commit()
    return WatchRunOut(**summary)


@router.get("/regulation-watch/sources", response_model=list[RegulationSourceOut])
def list_watch_sources(db: Session = Depends(get_db)) -> list[RegulationSourceOut]:
    reg_watch.register_sources(db)
    db.commit()
    return [
        RegulationSourceOut(
            pack_code=s.pack_code, url=s.url, content_hash=s.content_hash,
            last_checked_at=s.last_checked_at.isoformat() if s.last_checked_at else None,
            last_status=s.last_status, last_error=s.last_error,
        )
        for s in db.query(RegulationSource).order_by(RegulationSource.pack_code).all()
    ]


@router.get("/regulation-watch/changes", response_model=list[RegulationChangeOut])
def list_watch_changes(
    status: str | None = None, limit: int = 100, db: Session = Depends(get_db)
) -> list[RegulationChangeOut]:
    query = db.query(RegulationChange)
    if status:
        query = query.filter(RegulationChange.status == status)
    rows = (
        query.order_by(RegulationChange.created_at.desc())
        .limit(max(1, min(limit, 500)))
        .all()
    )
    return [
        RegulationChangeOut(
            id=str(c.id), pack_code=c.pack_code, url=c.url, change_type=c.change_type,
            status=c.status, summary=c.summary, evidence=c.evidence or {},
            published_version=c.published_version, created_at=c.created_at.isoformat(),
        )
        for c in rows
    ]


@router.post("/regulation-watch/changes/{change_id}/review", response_model=RegulationChangeOut)
def review_watch_change(
    change_id: str, status: str = "actioned", db: Session = Depends(get_db)
) -> RegulationChangeOut:
    """Close out a quarantined change once a person has dealt with it."""
    if status not in ("actioned", "dismissed"):
        raise HTTPException(status_code=422, detail="status must be actioned or dismissed")
    change = db.get(RegulationChange, _parse_uuid(change_id))
    if change is None:
        raise HTTPException(status_code=404, detail="change not found")
    change.status = status
    change.reviewed_by = "attest_admin"
    change.reviewed_at = datetime.now(UTC)
    db.commit()
    return RegulationChangeOut(
        id=str(change.id), pack_code=change.pack_code, url=change.url,
        change_type=change.change_type, status=change.status, summary=change.summary,
        evidence=change.evidence or {}, published_version=change.published_version,
        created_at=change.created_at.isoformat(),
    )


# --- Profile change requests (the anti-evasion control) -----------------------


@router.get("/profile-changes", response_model=list[ProfileChangeRequestOut])
def list_profile_changes(db: Session = Depends(get_db)) -> list[ProfileChangeRequestOut]:
    """Customers asking to DROP a jurisdiction or sector — i.e. shed obligations.

    Additions never appear here; they apply immediately. Only reductions need a
    decision, because only reductions reduce what the customer is checked against.
    """
    return [
        ProfileChangeRequestOut(
            id=str(r.id),
            org_id=r.org_id,
            requested_by=r.requested_by,
            reason=r.reason,
            removed=list(r.removed or []),
            proposed_jurisdictions=list(r.proposed_jurisdictions or []),
            proposed_sectors=list(r.proposed_sectors or []),
            status=r.status,
            created_at=r.created_at.isoformat(),
        )
        for r in profile_service.pending_change_requests(db)
    ]


@router.post("/profile-changes/{request_id}/decide", response_model=ProfileChangeRequestOut)
def decide_profile_change(
    request_id: str, approve: bool = True, db: Session = Depends(get_db)
) -> ProfileChangeRequestOut:
    try:
        req = profile_service.decide_change_request(
            db, request_id=str(_parse_uuid(request_id)), approve=approve,
            decided_by="attest_admin",
        )
    except profile_service.ProfileError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    db.commit()
    return ProfileChangeRequestOut(
        id=str(req.id),
        org_id=req.org_id,
        requested_by=req.requested_by,
        reason=req.reason,
        removed=list(req.removed or []),
        proposed_jurisdictions=list(req.proposed_jurisdictions or []),
        proposed_sectors=list(req.proposed_sectors or []),
        status=req.status,
        created_at=req.created_at.isoformat(),
    )


# --- Access requests ----------------------------------------------------------


def _req_out(db: Session, req: AccessRequest) -> AdminRequestOut:
    return AdminRequestOut(
        request_id=str(req.id),
        org_id=req.org_id,
        status=req.status,
        reason=req.reason,
        required_approvals=req.required_approvals,
        approvals=access_review.approvals_count(db, req.id),
        grantee_public_pem=req.grantee_public_pem,
        expires_at=req.expires_at.isoformat(),
        requested_by=req.requested_by,
        trace_id=str(req.trace_id) if req.trace_id else None,
    )


@router.get("/access-requests", response_model=list[AdminRequestOut])
def list_all_requests(
    org_id: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
) -> list[AdminRequestOut]:
    query = db.query(AccessRequest)
    if org_id is not None:
        query = query.filter(AccessRequest.org_id == org_id)
    if status is not None:
        query = query.filter(AccessRequest.status == status)
    reqs = query.order_by(AccessRequest.created_at.desc()).limit(200).all()
    return [_req_out(db, r) for r in reqs]


@router.get("/access-requests/{request_id}", response_model=AdminRequestDetailOut)
def request_detail(request_id: str, db: Session = Depends(get_db)) -> AdminRequestDetailOut:
    req = db.get(AccessRequest, _parse_uuid(request_id))
    if req is None:
        raise HTTPException(status_code=404, detail="access request not found")
    items = db.query(AccessGrantKey).filter(AccessGrantKey.request_id == req.id).all()
    scope = [
        AdminScopeItem(payload_hash=i.payload_hash, released=i.wrapped_key_b64 is not None)
        for i in items
    ]
    base = _req_out(db, req)
    return AdminRequestDetailOut(**base.model_dump(), scope=scope)


# --- Trace lookup + verification (any org — admin views metadata, not content) -


@router.get("/traces/{trace_id}/events", response_model=list[AdminTraceEventOut])
def trace_events(trace_id: str, db: Session = Depends(get_db)) -> list[AdminTraceEventOut]:
    """Event metadata for any trace (hashes and types — never payload content)."""
    tid = _parse_uuid(trace_id)
    events = (
        db.query(Event).filter(Event.trace_id == tid).order_by(Event.seq).all()
    )
    if not events:
        raise HTTPException(status_code=404, detail="trace not found")
    return [
        AdminTraceEventOut(
            seq=e.seq,
            type=e.type,
            payload_hash=e.payload_hash,
            hash=e.hash,
            prev_hash=e.prev_hash,
            created_at=e.created_at.isoformat(),
        )
        for e in events
    ]


@router.get("/traces/{trace_id}/replay", response_model=TraceReplayOut)
def trace_replay(trace_id: str, db: Session = Depends(get_db)) -> TraceReplayOut:
    """Re-verify a trace's hashes, signatures and chain links (admin view)."""
    tid = _parse_uuid(trace_id)
    trace = db.get(Trace, tid)
    if trace is None:
        raise HTTPException(status_code=404, detail="trace not found")
    try:
        result: TraceReplayResult = replay_trace(db, org_id=trace.org_id, trace_id=tid)
    except TraceNotFoundError as exc:
        raise HTTPException(status_code=404, detail="trace not found") from exc
    return TraceReplayOut(
        trace_id=str(tid),
        all_verified=result.all_verified,
        events=[
            EventReplayItem(
                seq=e.seq,
                type=e.type,
                verified=e.verified,
                hash_ok=e.hash_ok,
                signature_ok=e.signature_ok,
                chain_ok=e.chain_ok,
            )
            for e in result.events
        ],
    )
