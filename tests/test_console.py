"""The customer console is served and self-contained.

The full ceremony (WebCrypto keygen -> enable -> approve -> scoped read) is
exercised against a real Chromium in scripts/console_e2e — this test guards the
cheap invariants: the route exists and the page has no external dependencies
(a strict CSP or offline org network must not break it).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_console_served() -> None:
    client = TestClient(app)
    res = client.get("/console")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    assert "Customer Console" in res.text
    # /dashboard serves the same page.
    assert "Customer Console" in client.get("/dashboard").text


def test_console_is_self_contained() -> None:
    """No external scripts/styles/fonts: everything must be inline."""
    html = TestClient(app).get("/console").text
    for marker in ("<script src=", "<link rel=\"stylesheet\" href=", "https://cdn",
                   "googleapis.com", "@import"):
        assert marker not in html, f"console must not reference external resources: {marker}"
