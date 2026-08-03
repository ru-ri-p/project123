"""Sector taxonomy — what an institution does, which decides what applies to it.

GROUNDED, NOT INVENTED
======================
Top-level sectors follow the UN's **ISIC Rev.4** sections, the international
standard for classifying economic activity. Using a recognised taxonomy matters:
a bespoke list would be one more thing to defend in a regulator conversation, and
would not map onto anything a customer already reports elsewhere.

Sub-sectors are split only where UAE regulation actually differs — DFSA licence
categories distinguish banking from advisory; healthcare AI is governed by
emirate-level health authorities, not the financial regulators. Splitting further
than the rules do would be false precision.

WHY SECTOR AND JURISDICTION ARE BOTH NEEDED
===========================================
A bank in the DIFC answers to the DFSA; an onshore bank answers to the CBUAE.
Same sector, different rulebook. And some instruments cut across both: the
"Guidelines for Financial Institutions Adopting Enabling Technologies" were
issued *jointly* by the CBUAE, SCA, DFSA and FSRA, so they apply to financial
institutions in every UAE jurisdiction. Obligations are therefore the
intersection of (where you are licensed) x (what you do), which is why a pack
declares both.

AI USE-CASE RISK IS A SEPARATE AXIS
===================================
Sector is not the whole story. The EU AI Act's Annex III attaches high-risk
duties to what the AI *does* — credit scoring, biometric identification,
employment screening, access to essential services — regardless of industry. That
is a third axis (recorded here as AI_RISK_DOMAINS for reference) and a natural
next step; the settings page deliberately starts with sector, which is what a
customer can answer about themselves without ambiguity.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Sector:
    code: str
    name: str
    group: str
    isic: str  # ISIC Rev.4 section(s) this maps to
    description: str
    # UAE bodies that regulate this sector's use of AI, where one exists.
    regulators: tuple[str, ...] = field(default_factory=tuple)


# Ordered so the regulated, AI-sensitive sectors appear first in the UI — those
# are where an institution most needs to get the answer right.
SECTORS: tuple[Sector, ...] = (
    # --- Financial services (ISIC K) ------------------------------------------
    Sector("banking", "Banking & credit", "Financial services", "K",
           "Deposit-taking, lending, credit assessment.",
           ("CBUAE", "DFSA", "FSRA")),
    Sector("insurance_takaful", "Insurance & takaful", "Financial services", "K",
           "Underwriting, pricing, claims handling, including Sharia-compliant cover.",
           ("CBUAE", "DFSA", "FSRA")),
    Sector("capital_markets", "Capital markets & brokerage", "Financial services", "K",
           "Dealing, arranging and executing in investments.",
           ("SCA", "DFSA", "FSRA")),
    Sector("asset_management", "Asset & wealth management", "Financial services", "K",
           "Managing assets, funds and discretionary portfolios.",
           ("SCA", "DFSA", "FSRA")),
    Sector("advisory", "Financial advisory", "Financial services", "K",
           "Advising on investments or credit without holding client assets.",
           ("SCA", "DFSA", "FSRA")),
    Sector("payments", "Payments & e-money", "Financial services", "K",
           "Payment services, remittance, stored value.",
           ("CBUAE",)),
    Sector("virtual_assets", "Virtual assets & crypto", "Financial services", "K",
           "Virtual asset services, exchanges and custody.",
           ("VARA", "SCA", "FSRA")),
    # --- Health (ISIC Q) ------------------------------------------------------
    Sector("healthcare_provider", "Healthcare provision", "Health", "Q",
           "Clinical care, diagnosis, triage and decision support.",
           ("DoH Abu Dhabi", "DHA", "MOHAP")),
    Sector("health_insurance", "Health insurance", "Health", "Q",
           "Health cover, claims adjudication and prior authorisation.",
           ("DoH Abu Dhabi", "DHA")),
    Sector("pharma_medtech", "Pharmaceuticals & medical devices", "Health", "C/Q",
           "Manufacture and supply of medicines and medical devices, including software.",
           ("MOHAP",)),
    # --- Public sector (ISIC O) ----------------------------------------------
    Sector("government", "Government & public administration", "Public sector", "O",
           "Public services, benefits and administrative decisions."),
    Sector("law_enforcement", "Law enforcement & justice", "Public sector", "O",
           "Policing, investigation and administration of justice."),
    # --- Professional services (ISIC M) ---------------------------------------
    Sector("legal", "Legal services", "Professional services", "M",
           "Legal advice, drafting and representation."),
    Sector("accounting_audit", "Accounting & audit", "Professional services", "M",
           "Audit, assurance, tax and accounting."),
    Sector("consulting", "Consulting & professional advisory", "Professional services", "M",
           "Management, technical and scientific consulting."),
    # --- Information & communication (ISIC J) ---------------------------------
    Sector("technology", "Software & technology services", "Technology & media", "J",
           "Software, SaaS and IT services."),
    Sector("telecoms", "Telecommunications", "Technology & media", "J",
           "Fixed, mobile and data communications.", ("TDRA",)),
    Sector("media", "Media & publishing", "Technology & media", "J",
           "Broadcasting, publishing and content production."),
    # --- Education (ISIC P) ---------------------------------------------------
    Sector("education", "Education & training", "Education", "P",
           "Admissions, assessment, grading and vocational training.",
           ("KHDA", "MOE")),
    # --- Everything else, so any customer can classify themselves -------------
    Sector("real_estate", "Real estate", "Property & construction", "L",
           "Property sale, letting, valuation and management.", ("DLD",)),
    Sector("construction", "Construction & engineering", "Property & construction", "F",
           "Building, civil engineering and specialised construction."),
    Sector("retail_consumer", "Retail & consumer", "Trade & consumer", "G",
           "Wholesale and retail trade, e-commerce."),
    Sector("hospitality", "Hospitality, travel & tourism", "Trade & consumer", "I",
           "Accommodation, food service, travel and tourism."),
    Sector("transport_logistics", "Transport & logistics", "Industry & infrastructure", "H",
           "Transport, storage, freight and supply chain."),
    Sector("energy_utilities", "Energy & utilities", "Industry & infrastructure", "D/E",
           "Power, water, waste and critical utility infrastructure."),
    Sector("manufacturing", "Manufacturing", "Industry & infrastructure", "C",
           "Industrial and consumer goods manufacturing."),
    Sector("agriculture", "Agriculture & food production", "Industry & infrastructure", "A",
           "Farming, fishing, forestry and food production."),
    Sector("mining", "Mining & extraction", "Industry & infrastructure", "B",
           "Extraction of minerals, oil and gas."),
    Sector("hr_employment", "HR, recruitment & staffing", "Cross-cutting", "N",
           "Recruitment, screening, evaluation and workforce management."),
    Sector("other", "Other", "Cross-cutting", "S",
           "Anything not covered above. Baseline obligations still apply."),
)

SECTOR_CODES: frozenset[str] = frozenset(s.code for s in SECTORS)

# Every sector inside these groups is treated as a financial institution for the
# purpose of the jointly-issued financial-sector AI guidelines.
FINANCIAL_SECTORS: frozenset[str] = frozenset(
    s.code for s in SECTORS if s.group == "Financial services"
)
HEALTH_SECTORS: frozenset[str] = frozenset(s.code for s in SECTORS if s.group == "Health")

# Reference only, not yet used for matching: the EU AI Act's Annex III attaches
# duties to what the AI DOES rather than to the industry. Recorded here because
# it is the natural next axis for this page once sector is bedded in.
AI_RISK_DOMAINS: tuple[tuple[str, str], ...] = (
    ("biometrics", "Biometric identification or categorisation"),
    ("critical_infrastructure", "Management of critical infrastructure"),
    ("education_access", "Access to education, grading or assessment"),
    ("employment", "Recruitment, screening or worker management"),
    ("essential_services", "Access to essential public or private services"),
    ("creditworthiness", "Creditworthiness or credit scoring"),
    ("insurance_pricing", "Life or health insurance risk assessment and pricing"),
    ("law_enforcement", "Law enforcement use"),
    ("migration_border", "Migration, asylum or border control"),
    ("justice", "Administration of justice or democratic processes"),
)


def get_sector(code: str) -> Sector | None:
    for sector in SECTORS:
        if sector.code == code:
            return sector
    return None


def validate_sectors(codes: list[str]) -> list[str]:
    """Normalise and reject anything not in the taxonomy."""
    cleaned = sorted({c.strip() for c in codes if c and c.strip()})
    unknown = [c for c in cleaned if c not in SECTOR_CODES]
    if unknown:
        msg = f"unknown sector(s): {', '.join(unknown)}"
        raise ValueError(msg)
    return cleaned


def grouped_sectors() -> list[dict[str, object]]:
    """Sectors arranged by group, for rendering the settings page."""
    groups: dict[str, list[Sector]] = {}
    for sector in SECTORS:
        groups.setdefault(sector.group, []).append(sector)
    return [
        {
            "group": name,
            "sectors": [
                {
                    "code": s.code,
                    "name": s.name,
                    "isic": s.isic,
                    "description": s.description,
                    "regulators": list(s.regulators),
                }
                for s in members
            ],
        }
        for name, members in groups.items()
    ]
