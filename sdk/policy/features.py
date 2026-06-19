"""Feature extraction for local SDK policy evaluation."""

from __future__ import annotations

import re
from typing import Any

from sdk.policy.pii import detect_pii_labels
from sdk.policy.types import FeatureVector

PROHIBITED_PHRASE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "guaranteed_return",
        re.compile(r"\b(guaranteed|risk[- ]?free|will return|assured profit)\b", re.I),
    ),
    (
        "absolute_claim",
        re.compile(r"\b(100% certain|no risk|cannot lose)\b", re.I),
    ),
)


def extract_features(action: str, payload: dict[str, Any]) -> FeatureVector:
    pii_labels = detect_pii_labels(payload)
    citations = payload.get("citations")
    if isinstance(citations, int):
        citation_count = max(0, citations)
    elif isinstance(citations, list):
        citation_count = len(citations)
    else:
        citation_count = 0

    amount = payload.get("amount_aed")
    amount_aed = float(amount) if isinstance(amount, (int, float)) else None

    return FeatureVector(
        action=action,
        citation_count=citation_count,
        has_pii=bool(pii_labels),
        pii_labels=tuple(pii_labels),
        cross_border=bool(payload.get("cross_border") or payload.get("transfer_abroad")),
        lawful_basis_present=bool(
            payload.get("lawful_basis") or payload.get("cross_border_lawful_basis")
        ),
        prohibited_phrases=tuple(_detect_prohibited_phrases(payload)),
        amount_aed=amount_aed,
    )


def _detect_prohibited_phrases(payload: dict[str, Any]) -> list[str]:
    found: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            for label, pattern in PROHIBITED_PHRASE_PATTERNS:
                if pattern.search(value) and label not in found:
                    found.append(label)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(payload)
    return found
