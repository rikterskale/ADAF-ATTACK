"""Pure ADCS template / CA vulnerability classification (no network)."""

from __future__ import annotations

from typing import Any

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002

EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMART_CARD = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY = "2.5.29.37.0"
EKU_PKINIT_CLIENT = "1.3.6.1.5.2.3.4"
EKU_CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

CLIENT_AUTH_EKUS = {
    EKU_CLIENT_AUTH,
    EKU_ANY,
    EKU_SMART_CARD,
    EKU_PKINIT_CLIENT,
}


def client_auth_eku(ekus: list[str] | None) -> bool:
    if not ekus:
        return True
    return bool(set(ekus) & CLIENT_AUTH_EKUS)


def analyze_template_flags(
    *,
    name_flags: int = 0,
    enrollment_flags: int = 0,
    ra_signatures: int = 0,
    ekus: list[str] | None = None,
    application_policies: list[str] | None = None,
) -> dict[str, Any]:
    """Classify ESC1–ESC3 template conditions from numeric/string flags."""
    ekus = list(ekus or [])
    app = list(application_policies or [])
    enrollee_supplies = bool(name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    requires_manager = bool(enrollment_flags & CT_FLAG_PEND_ALL_REQUESTS)
    client_auth = client_auth_eku(ekus) or client_auth_eku(app)
    no_ra = ra_signatures == 0
    has_cra = EKU_CERTIFICATE_REQUEST_AGENT in ekus

    esc1 = enrollee_supplies and client_auth and not requires_manager and no_ra
    esc2 = enrollee_supplies and (not ekus or EKU_ANY in ekus) and not requires_manager and no_ra
    esc3_agent = has_cra and not requires_manager
    esc3_requires_ra = ra_signatures > 0 and not requires_manager

    tags: list[str] = []
    if esc1:
        tags.append("ESC1")
    if esc2 and not esc1:
        tags.append("ESC2")
    if esc3_agent:
        tags.append("ESC3_AGENT")
    if esc3_requires_ra:
        tags.append("ESC3_REQUIRES_RA")

    return {
        "enrollee_supplies_subject": enrollee_supplies,
        "requires_manager_approval": requires_manager,
        "client_auth_eku": client_auth,
        "ra_signatures_required": ra_signatures,
        "esc1_candidate": esc1,
        "esc2_candidate": esc2,
        "esc3_agent_template": esc3_agent,
        "esc3_requires_ra": esc3_requires_ra,
        "esc_tags": tags,
    }


def classify_acl_rights(rights: list[str]) -> dict[str, bool]:
    """Map ACE right names to ESC4 / ESC7 style signals."""
    s = set(rights)
    return {
        "esc4_template_acl": bool(
            s & {"GenericAll", "WriteDacl", "WriteOwner", "GenericWrite", "WriteProperty"}
        ),
        "esc7_ca_manage": bool(s & {"ManageCA", "ManageCertificates", "GenericAll"}),
        "enroll_right": bool(s & {"Enroll", "AutoEnroll", "AllExtendedRights", "GenericAll"}),
    }


def is_web_enrollment_endpoint(url: str) -> bool:
    low = (url or "").lower()
    return "http://" in low or "https://" in low
