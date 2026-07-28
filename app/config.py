"""Application configuration via environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[1]

SigningBackend = Literal["local", "kms"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql+psycopg2://attest:devpass@localhost:5433/attest"
    signing_backend: SigningBackend = "local"
    signing_private_key_path: Path = ROOT / "keys" / "ed25519_private.pem"
    signing_public_key_path: Path = ROOT / "keys" / "ed25519_public.pem"
    kms_key_id: str | None = None
    kms_region: str = "me-central-1"
    kms_public_key_pem_path: Path | None = None
    tsa_url: str = "https://freetsa.org/tsr"
    batch_interval_seconds: int = 300
    auto_batch_on_startup: bool = False
    rate_limit_max_requests: int = 120
    rate_limit_window_seconds: int = 60
    cors_origins: str = "http://localhost:3000"
    # Attest-ops admin key for the access-review console endpoints. Unset = the
    # admin API is disabled (endpoints return 503).
    admin_api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
