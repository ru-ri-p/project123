from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.approvals import router as approvals_router
from app.api.erasure import router as erasure_router
from app.api.events import router as events_router
from app.api.mitigations import router as mitigations_router
from app.api.orgs import router as orgs_router
from app.api.policies import router as policies_router
from app.api.precheck import router as precheck_router
from app.api.traces import router as traces_router
from app.config import get_settings
from app.crypto.signing_provider import SigningKeyError, get_signing_provider
from app.middleware.rate_limit import RateLimitMiddleware

app = FastAPI(title="Attest API", version="0.2.0")
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.cors_origins.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=settings.rate_limit_max_requests,
    window_seconds=settings.rate_limit_window_seconds,
)
app.include_router(events_router)
app.include_router(traces_router)
app.include_router(orgs_router)
app.include_router(erasure_router)
app.include_router(approvals_router)
app.include_router(precheck_router)
app.include_router(policies_router)
app.include_router(mitigations_router)


@app.get("/health")
def health() -> dict[str, str]:
    """Confirm the server is alive (used by monitoring and local dev)."""
    payload: dict[str, str] = {"status": "ok", "service": "attest"}
    try:
        provider = get_signing_provider()
        meta = provider.metadata()
        payload["signing_backend"] = meta["backend"]
        if meta.get("kms_key_id"):
            payload["kms_key_id"] = str(meta["kms_key_id"])
        if meta.get("kms_region"):
            payload["kms_region"] = str(meta["kms_region"])
    except SigningKeyError as exc:
        payload["signing_backend"] = "unavailable"
        payload["signing_error"] = str(exc)
    return payload

