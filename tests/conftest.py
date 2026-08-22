"""Shared pytest fixtures."""

from __future__ import annotations

import os

# The suite fires hundreds of requests through one TestClient in well under the
# production rate-limit window, so late-alphabet test files were getting 429s
# from our own limiter — surfacing as KeyError('api_key') in org setup, which
# points nowhere near the cause. Must be set before anything imports app.main,
# where the middleware reads its budget. Production keeps the real default.
os.environ.setdefault("RATE_LIMIT_MAX_REQUESTS", "1000000")

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.db.session import engine


@pytest.fixture(scope="session")
def db_available() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except OperationalError:
        return False
