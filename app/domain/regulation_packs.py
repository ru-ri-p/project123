"""Starter regulation packs — MVP drafts, pending legal review.

READ THIS BEFORE USING ANY OF IT
================================
Every rule below is `unverified`: drafted from publicly reported summaries of the
instruments named, NOT transcribed from the official texts. The official sources
(difc.com, adgm.com, the DFSA Rulebook) are unreachable from the build
environment, so provisions are cited at instrument level and `provision` is left
None wherever an exact article/section number could not be confirmed against the
source. Nothing here invents a clause number.

That is a deliberate design stance, not a shortcut: a rules engine that cites
regulations it cannot evidence is worse than one that admits what it has not
checked. Every finding these packs produce is labelled with its verification
status, so an unreviewed rule can never present itself as a settled legal
position — to a customer or to a regulator.

To promote a pack: obtain the official text, check each rule against it, fill in
`provision`, record the reviewer, and raise `verification_status`.

WHAT A RULE IS
==============
A rule maps a *checkable condition* in a proposed AI action to a risk tier, a
plain-English reason, and a citation. It is the institution's own operational
interpretation of an obligation — not a legal conclusion.
"""

from __future__ import annotations

from typing import Any

from app.domain.jurisdictions import UNVERIFIED
from app.domain.sectors import FINANCIAL_SECTORS, HEALTH_SECTORS

# --- DIFC ---------------------------------------------------------------------
# Regulation 10 is the reason this jurisdiction is first: it is squarely about
# personal data processed by autonomous / semi-autonomous systems (i.e. AI), and
# moved to full enforcement on 1 January 2026. It is the closest thing in the
# region to an AI-governance rulebook, which is exactly Attest's surface.

DIFC_DP_REG10: dict[str, Any] = {
    "code": "difc_dp_reg10",
    "jurisdiction": "difc",
    "jurisdictions": ["difc"],
    "sectors": ["*"],  # data protection binds every sector in the DIFC
    "name": (
        "DIFC Data Protection Regulations — Regulation 10 "
        "(Autonomous & Semi-Autonomous Systems)"
    ),
    "version": "2026.1-draft",
    "instrument": "DIFC Data Protection Regulations, Regulation 10",
    "instrument_notes": (
        "In force 1 September 2023; reported as moving to full enforcement from "
        "1 January 2026. Introduces Deployer and Operator roles, an Autonomous "
        "Systems Officer for high-risk Systems, transparency duties toward data "
        "subjects, fairness/non-discrimination duties, and evidence-of-compliance "
        "record-keeping."
    ),
    "source_url": (
        "https://www.difc.com/business/registrars-and-commissioners/"
        "commissioner-of-data-protection/regulation-10"
    ),
    "effective_date": "2023-09-01",
    "verification_status": UNVERIFIED,
    "schema_version": 2,
    "engine": "json",
    "rules": [
        {
            "id": "difc_reg10_ai_personal_data",
            "priority": 900,
            "tier": "orange",
            "decision": "flag",
            "match": {"has_pii": True},
            "reason": (
                "Personal data processed by an autonomous system. Regulation 10 "
                "duties are engaged: transparency to the data subject, fairness, "
                "and retained evidence of compliance."
            ),
            "topic": "AI processing of personal data",
            "provision": None,
            "guidance": (
                "Confirm the Deployer is identified, the required notice has been "
                "given, and this decision is retained as evidence of compliance."
            ),
        },
        {
            "id": "difc_reg10_profiling",
            "priority": 890,
            "tier": "orange",
            "decision": "flag",
            "match": {"feature": "classifier", "equals": "individualised_advice"},
            "reason": (
                "Systematic evaluation of an individual by an autonomous system. "
                "Engages Regulation 10 fairness duties and may qualify as High "
                "Risk Processing under the DP Law."
            ),
            "topic": "profiling / systematic evaluation",
            "provision": None,
            "guidance": "Consider whether a DPIA and human review are required.",
        },
        {
            "id": "difc_reg10_fairness",
            "priority": 880,
            "tier": "red",
            "decision": "flag",
            "match": {"feature": "classifier", "equals": "discriminatory_lending"},
            "reason": (
                "Output suggests a potentially discriminatory basis. Regulation 10 "
                "requires algorithmic decisions to be unbiased and to treat "
                "individuals equally and fairly."
            ),
            "topic": "algorithmic fairness / non-discrimination",
            "provision": None,
            "guidance": "Escalate to the Autonomous Systems Officer before release.",
        },
    ],
}

DIFC_DP_LAW: dict[str, Any] = {
    "code": "difc_dp_law_5_2020",
    "jurisdiction": "difc",
    "jurisdictions": ["difc"],
    "sectors": ["*"],
    "name": "DIFC Data Protection Law No. 5 of 2020",
    "version": "2026.1-draft",
    "instrument": "DIFC Law No. 5 of 2020 (Data Protection Law)",
    "instrument_notes": (
        "Enacted 21 May 2020, in force 1 July 2020; amended subsequently. Covers "
        "lawful basis, High Risk Processing Activities, data protection impact "
        "assessments, transfers of personal data out of the DIFC, and data "
        "subject rights."
    ),
    "source_url": (
        "https://www.difc.com/business/laws-and-regulations/legal-database/"
        "difc-laws/data-protection-law-difc-law-no-5-2020"
    ),
    "effective_date": "2020-07-01",
    "verification_status": UNVERIFIED,
    "schema_version": 2,
    "engine": "json",
    "rules": [
        {
            "id": "difc_dp_transfer_out",
            "priority": 870,
            "tier": "red",
            "decision": "flag",
            "match": {"feature": "cross_border", "without_lawful_basis": True},
            "reason": (
                "Personal data appears to leave the DIFC without a recorded lawful "
                "basis. The DP Law restricts transfers out of the DIFC absent an "
                "adequate regime or another permitted ground."
            ),
            "topic": "transfers of personal data out of the DIFC",
            "provision": None,
            "guidance": "Record the adequacy determination or transfer safeguard relied on.",
        },
        {
            "id": "difc_dp_high_risk",
            "priority": 860,
            "tier": "orange",
            "decision": "flag",
            "match": {"has_pii": True},
            "reason": (
                "Processing may be a High Risk Processing Activity (new technology, "
                "large volume, or systematic evaluation), which attracts additional "
                "assessment and record-keeping duties."
            ),
            "topic": "High Risk Processing Activities / DPIA",
            "provision": None,
            "guidance": "Check whether a DPIA is on file for this processing activity.",
        },
    ],
}

# --- ADGM ---------------------------------------------------------------------
# Structurally present so an institution spanning zones is modelled correctly.
# Content is a stub: the ADGM sources were unreachable, and guessing would be
# worse than an honest gap.

ADGM_DP: dict[str, Any] = {
    "code": "adgm_dp_regs",
    "jurisdiction": "adgm",
    "jurisdictions": ["adgm"],
    "sectors": ["*"],
    "name": "ADGM Data Protection Regulations",
    "version": "0.1-stub",
    "instrument": "ADGM Data Protection Regulations 2021",
    "instrument_notes": (
        "STUB — structure only. Official ADGM sources were not reachable when "
        "this pack was drafted; no rule content has been written."
    ),
    "source_url": "https://www.adgm.com/legal-framework/legislation",
    "effective_date": None,
    "verification_status": UNVERIFIED,
    "schema_version": 2,
    "engine": "json",
    "rules": [],
}

# --- UAE onshore --------------------------------------------------------------

UAE_ONSHORE: dict[str, Any] = {
    "code": "uae_onshore_core",
    "jurisdiction": "uae_onshore",
    "jurisdictions": ["uae_onshore"],
    "sectors": ["*"],
    "name": "UAE onshore — federal data protection & financial conduct",
    "version": "0.1-stub",
    "instrument": (
        "Federal Decree-Law No. 45 of 2021 (Personal Data Protection Law); "
        "CBUAE Rulebook; SCA regulations"
    ),
    "instrument_notes": (
        "STUB — structure only. Carries the two rules the previous reference "
        "policy already asserted, retained so onshore orgs are not left with an "
        "empty pack. Both need checking against the official texts."
    ),
    "source_url": "https://u.ae/en/about-the-uae/digital-uae/data/data-protection-laws",
    "effective_date": None,
    "verification_status": UNVERIFIED,
    "schema_version": 2,
    "engine": "json",
    "rules": [
        {
            "id": "uae_pdpl_cross_border",
            "priority": 870,
            "tier": "red",
            "decision": "flag",
            "match": {"feature": "cross_border", "without_lawful_basis": True},
            "reason": "Cross-border personal data transfer without a recorded lawful basis.",
            "topic": "cross-border transfer",
            "provision": None,
            "guidance": "Record the transfer ground relied on.",
        },
        {
            "id": "cbuae_human_oversight_payments",
            "priority": 1000,
            "tier": "red",
            "decision": "flag",
            "match": {"action": ["wire_transfer", "execute_trade"]},
            "reason": (
                "High-risk financial action taken by an AI system; human oversight "
                "expectations apply."
            ),
            "topic": "human oversight of high-risk financial actions",
            "provision": None,
            "guidance": "Route to a named human approver before execution.",
        },
    ],
}


# --- Financial services, ALL UAE jurisdictions --------------------------------
# The reason packs need a sector axis as well as a jurisdiction one. These
# guidelines were issued JOINTLY by the CBUAE, SCA, DFSA and FSRA, so they reach
# financial institutions onshore, in the DIFC and in the ADGM alike — a pack
# keyed only by jurisdiction could not express that.

UAE_FIN_ENABLING_TECH: dict[str, Any] = {
    "code": "uae_fin_enabling_tech",
    "jurisdiction": "uae_onshore",
    "jurisdictions": ["uae_onshore", "difc", "adgm"],
    "sectors": sorted(FINANCIAL_SECTORS),
    "name": "Guidelines for Financial Institutions Adopting Enabling Technologies",
    "version": "0.1-draft",
    "instrument": (
        "Guidelines for Financial Institutions Adopting Enabling Technologies "
        "(CBUAE, SCA, DFSA, FSRA — joint)"
    ),
    "instrument_notes": (
        "Cross-sectoral principles for financial institutions adopting enabling "
        "technologies, expressly including Big Data Analytics and Artificial "
        "Intelligence, biometrics, cloud and DLT. Covers governance, risk "
        "management, model validation, outsourcing controls, data protection and "
        "supervisory engagement. Issued jointly, so it applies across onshore, "
        "DIFC and ADGM."
    ),
    "source_url": (
        "https://rulebook.centralbank.ae/en/rulebook/"
        "guidelines-financial-institutions-adopting-enabling-technologies"
    ),
    "effective_date": None,
    "verification_status": UNVERIFIED,
    "schema_version": 2,
    "engine": "json",
    "rules": [
        {
            "id": "uae_fin_model_validation",
            "priority": 850,
            "tier": "orange",
            "decision": "flag",
            "match": {"feature": "classifier", "equals": "individualised_advice"},
            "reason": (
                "An AI model is driving an individualised financial outcome. The "
                "joint guidelines expect documented model validation, governance "
                "and human oversight proportionate to the risk."
            ),
            "topic": "model validation & governance",
            "provision": None,
            "guidance": "Confirm the model is validated and the decision is reviewable.",
        },
        {
            "id": "uae_fin_high_risk_action",
            "priority": 990,
            "tier": "red",
            "decision": "flag",
            "match": {"action": ["wire_transfer", "execute_trade"]},
            "reason": (
                "High-risk financial action executed with AI involvement. Human "
                "oversight and accountability expectations apply."
            ),
            "topic": "human oversight of high-risk actions",
            "provision": None,
            "guidance": "Route to a named human approver before execution.",
        },
    ],
}

CBUAE_AI_CONSUMER: dict[str, Any] = {
    "code": "cbuae_ai_consumer",
    "jurisdiction": "uae_onshore",
    "jurisdictions": ["uae_onshore"],
    "sectors": sorted(FINANCIAL_SECTORS),
    "name": "CBUAE — Consumer Protection & Responsible Adoption of AI/ML",
    "version": "0.1-draft",
    "instrument": (
        "CBUAE Guidance Note on Consumer Protection and Responsible Adoption of "
        "Artificial Intelligence and Machine Learning"
    ),
    "instrument_notes": (
        "Reported as published 11 February 2026. Reported to require documented AI "
        "governance frameworks, periodic bias testing, third-party audit rights, "
        "and board-level accountability. Onshore only — the CBUAE does not "
        "supervise DIFC or ADGM firms."
    ),
    "source_url": "https://rulebook.centralbank.ae/",
    "effective_date": "2026-02-11",
    "verification_status": UNVERIFIED,
    "schema_version": 2,
    "engine": "json",
    "rules": [
        {
            "id": "cbuae_ai_bias",
            "priority": 880,
            "tier": "red",
            "decision": "flag",
            "match": {"feature": "classifier", "equals": "discriminatory_lending"},
            "reason": (
                "Output suggests a potentially discriminatory basis in a consumer "
                "financial decision. Bias testing and board-level accountability "
                "expectations are engaged."
            ),
            "topic": "bias testing & consumer fairness",
            "provision": None,
            "guidance": "Retain this decision as evidence for the next bias review.",
        },
        {
            "id": "cbuae_ai_consumer_pii",
            "priority": 800,
            "tier": "orange",
            "decision": "flag",
            "match": {"has_pii": True},
            "reason": (
                "Consumer personal data processed by an AI system; responsible-"
                "adoption and consumer-protection duties apply."
            ),
            "topic": "consumer protection in AI adoption",
            "provision": None,
            "guidance": "Check the documented AI governance framework covers this use.",
        },
    ],
}

# --- Health, UAE --------------------------------------------------------------
# Healthcare has its own AI-specific instruments, issued by the emirate health
# authorities rather than any financial regulator — which is exactly why sector
# has to be modelled rather than assumed.

UAE_HEALTH_AI: dict[str, Any] = {
    "code": "uae_health_ai",
    "jurisdiction": "uae_onshore",
    "jurisdictions": ["uae_onshore", "difc", "adgm"],
    "sectors": sorted(HEALTH_SECTORS),
    "name": "UAE health authorities — AI in healthcare",
    "version": "0.1-draft",
    "instrument": (
        "DoH Abu Dhabi Policy on the Use of AI in the Healthcare Sector and "
        "Responsible AI Standard; DHA Policy for the Use of AI in Healthcare"
    ),
    "instrument_notes": (
        "Abu Dhabi DoH published an AI-in-healthcare policy (reported 2018) and a "
        "Responsible AI Standard (reported 2025); the DHA published its own policy "
        "(reported August 2021). Both are reported to rest on transparency, "
        "accountability, safety and security, privacy and ethics, and to cover "
        "providers, insurers, manufacturers and researchers."
    ),
    "source_url": "https://www.doh.gov.ae/en/resources",
    "effective_date": None,
    "verification_status": UNVERIFIED,
    "schema_version": 2,
    "engine": "json",
    "rules": [
        {
            "id": "uae_health_patient_data",
            "priority": 900,
            "tier": "orange",
            "decision": "flag",
            "match": {"has_pii": True},
            "reason": (
                "Patient personal data processed by an AI system. Health-authority "
                "AI policies engage transparency, privacy, safety and "
                "accountability duties."
            ),
            "topic": "AI in clinical care — patient data",
            "provision": None,
            "guidance": "Confirm clinician oversight and that the use is disclosed.",
        },
        {
            "id": "uae_health_clinical_decision",
            "priority": 950,
            "tier": "red",
            "decision": "flag",
            "match": {"action": ["clinical_decision", "diagnosis", "triage"]},
            "reason": (
                "AI contributing to a clinical decision. Human accountability for "
                "the decision must be preserved and recorded."
            ),
            "topic": "clinical decision support",
            "provision": None,
            "guidance": "A licensed clinician must own and record the final decision.",
        },
    ],
}


BUILTIN_PACKS: tuple[dict[str, Any], ...] = (
    DIFC_DP_REG10,
    DIFC_DP_LAW,
    ADGM_DP,
    UAE_ONSHORE,
    UAE_FIN_ENABLING_TECH,
    CBUAE_AI_CONSUMER,
    UAE_HEALTH_AI,
)


def packs_for_jurisdiction(code: str) -> list[dict[str, Any]]:
    return [p for p in BUILTIN_PACKS if p["jurisdiction"] == code]
