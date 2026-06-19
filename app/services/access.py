"""Cross-tenant access errors."""

from __future__ import annotations


class TraceAccessDeniedError(PermissionError):
    """Trace exists but belongs to a different organisation."""


class TraceNotFoundError(LookupError):
    """No trace with this id (for the requesting org)."""
