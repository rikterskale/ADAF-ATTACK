"""Pure ADCS template / CA vulnerability classification (no network)."""

from __future__ import annotations

from typing import Any

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000  # msPKI-Enrollment-Flag bit used for ESC9

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
    """Classify ESC1-ESC3 / ESC9 template conditions from numeric/string flags."""
    ekus = list(ekus or [])
    app = list(application_policies or [])
    enrollee_supplies = bool(name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    requires_manager = bool(enrollment_flags & CT_FLAG_PEND_ALL_REQUESTS)
    client_auth = client_auth_eku(ekus) or client_auth_eku(app)
    no_ra = ra_signatures == 0
    has_cra = EKU_CERTIFICATE_REQUEST_AGENT in ekus
    no_security_extension = bool(enrollment_flags & CT_FLAG_NO_SECURITY_EXTENSION)

    esc1 = enrollee_supplies and client_auth and not requires_manager and no_ra
    esc2 = enrollee_supplies and (not ekus or EKU_ANY in ekus) and not requires_manager and no_ra
    esc3_agent = has_cra and not requires_manager
    esc3_requires_ra = ra_signatures > 0 and not requires_manager
    # ESC9: template lacks security extension and still issues client-auth certs
    esc9 = no_security_extension and client_auth and not requires_manager

    tags: list[str] = []
    if esc1:
        tags.append("ESC1")
    if esc2 and not esc1:
        tags.append("ESC2")
    if esc3_agent:
        tags.append("ESC3_AGENT")
    if esc3_requires_ra:
        tags.append("ESC3_REQUIRES_RA")
    if esc9:
        tags.append("ESC9")

    return {
        "enrollee_supplies_subject": enrollee_supplies,
        "requires_manager_approval": requires_manager,
        "client_auth_eku": client_auth,
        "ra_signatures_required": ra_signatures,
        "no_security_extension": no_security_extension,
        "esc1_candidate": esc1,
        "esc2_candidate": esc2,
        "esc3_agent_template": esc3_agent,
        "esc3_requires_ra": esc3_requires_ra,
        "esc9_candidate": esc9,
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


def classify_modern_esc(
    *,
    template_flags: dict[str, Any] | None = None,
    enroll_principal_count: int = 0,
    dangerous_acl: bool = False,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce a normalized ESC1-ESC15 candidate map with confidence labels.

    ESC10 / ESC11 / ESC13 are policy-driven and come from authorized artifacts
    (adcs-policy-probe).  ESC12 / ESC14 / ESC15 remain research signals and are
    emitted only when explicit policy evidence is supplied.
    """
    flags = template_flags or {}
    policy = policy or {}

    candidates: dict[str, dict[str, Any]] = {}

    def _add(esc: str, confidence: str, reason: str) -> None:
        candidates[esc] = {"confidence": confidence, "reason": reason}

    if flags.get("esc1_candidate"):
        conf = "high" if enroll_principal_count else "medium"
        _add("ESC1", conf, "Enrollee supplies subject + client auth + no manager approval")
    if flags.get("esc2_candidate") and not flags.get("esc1_candidate"):
        _add("ESC2", "medium", "Any-purpose / empty EKU with subject control")
    if flags.get("esc3_agent_template"):
        _add("ESC3", "medium", "Certificate Request Agent template")
    if dangerous_acl:
        _add("ESC4", "high", "Dangerous ACL on certificate template")
    if flags.get("esc9_candidate"):
        conf = "high" if enroll_principal_count else "medium"
        _add("ESC9", conf, "No security extension + client-auth capable template")

    if policy.get("weak_certificate_mapping"):
        _add("ESC10", "medium", "Weak certificate mapping policy observed")
    if policy.get("rpc_encryption_not_enforced"):
        _add("ESC11", "medium", "CA RPC encryption not enforced")
    if policy.get("issuance_policy_group_links"):
        _add("ESC13", "medium", "Issuance policy linked to security groups")
    if policy.get("application_policy_maps_to_group"):
        _add("ESC13", "medium", "Application policy maps into privileged group")
    if policy.get("shell_access_via_certificate"):
        _add("ESC14", "low", "Certificate grants interactive/shell path (research signal)")
    if policy.get("privileged_enrollment_agent"):
        _add("ESC15", "low", "Privileged enrollment-agent path (research signal)")

    return {
        "candidates": candidates,
        "esc_tags": sorted(candidates.keys()),
        "highest_confidence": max(
            (c["confidence"] for c in candidates.values()),
            default="unknown",
            key=lambda x: {"high": 3, "medium": 2, "low": 1, "unknown": 0}.get(x, 0),
        ),
    }
