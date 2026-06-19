"""Trace access control — org isolation (instructions §7)."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.repositories import traces as trace_repo
from app.services.access import TraceAccessDeniedError, TraceNotFoundError


def ensure_trace_access(db: Session, org_id: str, trace_id: uuid.UUID) -> None:
    """Raise if the trace is missing or owned by another org."""
    trace = trace_repo.get_trace_by_id(db, trace_id)
    if trace is None:
        raise TraceNotFoundError(f"trace not found: {trace_id}")
    if trace.org_id != org_id:
        raise TraceAccessDeniedError(f"trace access denied: {trace_id}")
