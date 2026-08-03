"""Jurisdictions Attest can evaluate against.

The UAE is not one legal environment. Onshore federal regulation and the two
financial free zones (DIFC, ADGM) are separate regimes with their own regulators
and their own rulebooks, and a single institution may sit in more than one at
once. So jurisdiction is structural here, not a label: an action is evaluated
against every pack that applies to it, and the strictest finding wins.

WHAT THIS MODULE IS NOT: a source of legal advice. It records where a rule came
from so a lawyer can check it. Every pack carries a verification status, and
nothing ships as `COUNSEL_REVIEWED` until a qualified reviewer has signed it off.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

JurisdictionCode = Literal["difc", "adgm", "uae_onshore", "internal"]

# How much scrutiny a pack's content has had. Findings are labelled with this so
# an unverified rule can never be mistaken for a settled legal position.
UNVERIFIED = "unverified"  # drafted from public sources; NOT checked by counsel
SELF_REVIEWED = "self_reviewed"  # checked in-house against the official text
COUNSEL_REVIEWED = "counsel_reviewed"  # signed off by a qualified lawyer

VERIFICATION_STATUSES = (UNVERIFIED, SELF_REVIEWED, COUNSEL_REVIEWED)


@dataclass(frozen=True)
class Jurisdiction:
    code: JurisdictionCode
    name: str
    regulators: tuple[str, ...]
    summary: str
    # Where the primary materials live. Recorded so packs can be verified and
    # refreshed against the source rather than trusted because they are in git.
    official_sources: tuple[str, ...]


JURISDICTIONS: dict[str, Jurisdiction] = {
    "difc": Jurisdiction(
        code="difc",
        name="Dubai International Financial Centre",
        regulators=("DFSA", "DIFC Commissioner of Data Protection"),
        summary=(
            "Financial free zone with its own common-law framework. Federal UAE "
            "financial regulation generally does not apply inside it; the DFSA "
            "Rulebook and DIFC enacted laws do."
        ),
        official_sources=(
            "https://www.difc.com/business/laws-and-regulations/legal-database",
            "https://www.difc.com/business/registrars-and-commissioners/commissioner-of-data-protection",
            "https://dfsaen.thomsonreuters.com/rulebook",
        ),
    ),
    "adgm": Jurisdiction(
        code="adgm",
        name="Abu Dhabi Global Market",
        regulators=("FSRA", "ADGM Office of Data Protection"),
        summary=(
            "Financial free zone with its own legal framework and regulator "
            "(FSRA), separate from both onshore UAE and the DIFC."
        ),
        official_sources=(
            "https://www.adgm.com/legal-framework/legislation",
            "https://en.adgm.thomsonreuters.com/rulebook",
        ),
    ),
    "uae_onshore": Jurisdiction(
        code="uae_onshore",
        name="United Arab Emirates (onshore / federal)",
        regulators=("CBUAE", "SCA", "UAE Data Office"),
        summary=(
            "Federal regime outside the financial free zones. Banking, insurance "
            "and payments sit with the Central Bank; capital markets with the SCA; "
            "personal data under the federal data protection law."
        ),
        official_sources=(
            "https://www.centralbank.ae/en/cbuae-rulebook/",
            "https://www.sca.gov.ae/en/regulations.aspx",
            "https://u.ae/en/about-the-uae/digital-uae/data/data-protection-laws",
        ),
    ),
    "internal": Jurisdiction(
        code="internal",
        name="Institution's own policy",
        regulators=(),
        summary=(
            "The institution's own documented rules, authored by the institution. "
            "Attest enforces these; it does not supply them."
        ),
        official_sources=(),
    ),
}


def get_jurisdiction(code: str) -> Jurisdiction | None:
    return JURISDICTIONS.get(code)


def list_jurisdictions() -> list[Jurisdiction]:
    return list(JURISDICTIONS.values())
