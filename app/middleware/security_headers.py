"""Security response headers — cheap, standard, and the first thing a
customer's security reviewer checks with a scanner.

Each header, and why:
- Strict-Transport-Security: once seen over HTTPS, the browser refuses plain
  HTTP to this host for a year — defeats SSL-strip downgrade. Only emitted on
  HTTPS requests (emitting it on plain HTTP is meaningless and can trap a
  local dev box). Render terminates TLS and sets x-forwarded-proto=https.
- Content-Security-Policy: the real backstop against XSS in the console,
  which renders flagged AI outputs (hostile content is our NORMAL content).
  default-src 'self' plus explicit narrow allowances. NOTE: the console and
  login pages ship inline <script>/<style> and data: fonts, so 'unsafe-inline'
  and data: are permitted for now — a real relaxation, tracked in SECURITY.md
  to tighten with nonces/hashes later. Even so, frame-ancestors, object-src
  and base-uri are locked down, and no external script origin is allowed.
- X-Frame-Options / frame-ancestors: the console cannot be framed, so it
  cannot be clickjacked into approving something.
- X-Content-Type-Options: no MIME sniffing — a text payload can't be coaxed
  into executing as script.
- Referrer-Policy: never leak a full URL (which can carry ids) cross-origin.
- Permissions-Policy: switch off browser features we never use.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# Self-hosted app + WebCrypto (console key custody) + data: fonts/images.
# No external script/style/connect origins: nothing here loads from a CDN.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)
_PERMISSIONS = "camera=(), microphone=(), geolocation=(), payment=()"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        h = response.headers
        h.setdefault("Content-Security-Policy", _CSP)
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        h.setdefault("Permissions-Policy", _PERMISSIONS)
        # HSTS only when the edge served this over HTTPS (Render sets the
        # forwarded header). Never on plain HTTP — it would wrongly pin a
        # dev host to HTTPS it does not speak.
        forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        if forwarded_proto == "https":
            h.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response
