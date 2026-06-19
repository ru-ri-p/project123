"""Layer 1 — PII pattern detection (no redaction; used before allow/deny)."""

from __future__ import annotations

from typing import Any

from app.services.pii import PATTERNS


def detect_pii_labels(payload: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    _scan(payload, labels)
    return sorted(set(labels))


def _scan(value: Any, labels: list[str]) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _scan(item, labels)
    elif isinstance(value, list):
        for item in value:
            _scan(item, labels)
    elif isinstance(value, str):
        for label, pattern in PATTERNS.items():
            if pattern.search(value):
                labels.append(label)
