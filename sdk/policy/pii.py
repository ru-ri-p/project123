"""PII detection for local SDK evaluation."""

from __future__ import annotations

import re
from typing import Any

PATTERNS: dict[str, re.Pattern[str]] = {
    "emirates_id": re.compile(r"\b784-?\d{4}-?\d{7}-?\d\b"),
    "iban_ae": re.compile(r"\bAE\d{2}\d{3}\d{16}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "phone_ae": re.compile(r"\b(?:\+?971|0)5\d{8}\b"),
}


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
