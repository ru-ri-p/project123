"""Extract structural features for policy evaluation (deterministic, microseconds)."""

from __future__ import annotations

import re
from typing import Any

from app.domain.policy_contract import FeatureVector
from app.services.policy.pii_layer import detect_pii_labels

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
    citation_count = _citation_count(payload)
    cross_border = bool(payload.get("cross_border") or payload.get("transfer_abroad"))
    lawful_basis = bool(
        payload.get("lawful_basis") or payload.get("cross_border_lawful_basis")
    )
    amount = payload.get("amount_aed")
    amount_aed: float | None = float(amount) if isinstance(amount, (int, float)) else None

    return FeatureVector(
        action=action,
        citation_count=citation_count,
        has_pii=bool(pii_labels),
        pii_labels=tuple(pii_labels),
        cross_border=cross_border,
        lawful_basis_present=lawful_basis,
        prohibited_phrases=tuple(_detect_prohibited_phrases(payload)),
        amount_aed=amount_aed,
    )


def _citation_count(payload: dict[str, Any]) -> int:
    citations = payload.get("citations")
    if isinstance(citations, int):
        return max(0, citations)
    if isinstance(citations, list):
        return len(citations)
    return 0


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
