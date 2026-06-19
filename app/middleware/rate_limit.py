"""Simple in-memory rate limiting by API key (instructions §7)."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

if TYPE_CHECKING:
    from starlette.types import ASGIApp

# Paths that skip rate limiting
_EXEMPT_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Token-bucket style limiter keyed on x-api-key header."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_requests: int = 120,
        window_seconds: int = 60,
    ) -> None:
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        api_key = request.headers.get("x-api-key", "anonymous")
        now = time.monotonic()
        bucket = self._hits[api_key]

        while bucket and now - bucket[0] > self.window_seconds:
            bucket.popleft()

        if len(bucket) >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "rate limit exceeded"},
            )

        bucket.append(now)
        return await call_next(request)
