"""PII detection and redaction before storage (instructions §5 — PDPL minimisation)."""

from __future__ import annotations

import copy
import re
from typing import Any

PATTERNS: dict[str, re.Pattern[str]] = {
    "emirates_id": re.compile(r"\b784-?\d{4}-?\d{7}-?\d\b"),
    "iban_ae": re.compile(r"\bAE\d{2}\d{3}\d{16}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "phone_ae": re.compile(r"\b(?:\+?971|0)5\d{8}\b"),
}


def redact_text(text: str) -> tuple[str, list[str]]:
    found: list[str] = []
    for label, pattern in PATTERNS.items():
        if pattern.search(text):
            found.append(label)
            text = pattern.sub(f"[REDACTED:{label}]", text)
    return text, found


def redact_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return a deep copy with PII redacted and a deduplicated list of labels found."""
    redacted = copy.deepcopy(payload)
    labels: list[str] = []
    _redact_in_place(redacted, labels)
    unique_labels = sorted(set(labels))
    return redacted, unique_labels


def _redact_in_place(value: Any, labels: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str):
                value[key], found = redact_text(item)
                labels.extend(found)
            elif isinstance(item, (dict, list)):
                _redact_in_place(item, labels)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str):
                value[index], found = redact_text(item)
                labels.extend(found)
            elif isinstance(item, (dict, list)):
                _redact_in_place(item, labels)
