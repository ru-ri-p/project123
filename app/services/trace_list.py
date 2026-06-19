"""Trace listing for dashboard."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.repositories import traces as trace_repo


def list_traces(
    db: Session,
    org_id: str,
    *,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, str | int]]:
    traces = trace_repo.list_traces_for_org(db, org_id, limit=limit, offset=offset)
    return [
        {
            "trace_id": str(trace.id),
            "created_at": trace.created_at.isoformat(),
            "policy_version": trace.policy_version or "",
            "event_count": trace_repo.event_count_for_trace(db, org_id, trace.id),
        }
        for trace in traces
    ]
