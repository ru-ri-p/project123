"""Security headers ride on every response, and HSTS only over HTTPS."""

from __future__ import annotations

import pytest


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


def test_core_headers_on_every_response(client) -> None:
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "strict-origin" in r.headers["referrer-policy"]
    assert "camera=()" in r.headers["permissions-policy"]
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_headers_ride_on_the_console_html_too(client) -> None:
    r = client.get("/console")
    assert r.status_code == 200
    assert r.headers["x-frame-options"] == "DENY", "the console cannot be framed"
    assert "content-security-policy" in r.headers


def test_hsts_absent_on_plain_http(client) -> None:
    # TestClient speaks http:// and sends no x-forwarded-proto.
    r = client.get("/health")
    assert "strict-transport-security" not in r.headers, (
        "HSTS on plain HTTP would wrongly pin a dev host"
    )


def test_hsts_present_when_edge_served_https(client) -> None:
    r = client.get("/health", headers={"x-forwarded-proto": "https"})
    hsts = r.headers.get("strict-transport-security", "")
    assert "max-age=31536000" in hsts and "includeSubDomains" in hsts
