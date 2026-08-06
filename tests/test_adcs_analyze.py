"""Unit tests for pure ADCS ESC classification."""

from adaf_attack.core.adcs_analyze import (
    EKU_ANY,
    EKU_CERTIFICATE_REQUEST_AGENT,
    EKU_CLIENT_AUTH,
    analyze_template_flags,
    classify_acl_rights,
    is_web_enrollment_endpoint,
)


def test_esc1_classic() -> None:
    r = analyze_template_flags(
        name_flags=0x1,  # enrollee supplies subject
        enrollment_flags=0,
        ra_signatures=0,
        ekus=[EKU_CLIENT_AUTH],
    )
    assert r["esc1_candidate"] is True
    assert "ESC1" in r["esc_tags"]


def test_esc1_blocked_by_manager_approval() -> None:
    r = analyze_template_flags(
        name_flags=0x1,
        enrollment_flags=0x2,  # pend all requests
        ra_signatures=0,
        ekus=[EKU_CLIENT_AUTH],
    )
    assert r["esc1_candidate"] is False
    assert r["requires_manager_approval"] is True


def test_esc1_blocked_by_ra_signature() -> None:
    r = analyze_template_flags(
        name_flags=0x1,
        enrollment_flags=0,
        ra_signatures=1,
        ekus=[EKU_CLIENT_AUTH],
    )
    assert r["esc1_candidate"] is False
    assert r["esc3_requires_ra"] is True


def test_esc2_any_purpose() -> None:
    r = analyze_template_flags(
        name_flags=0x1,
        enrollment_flags=0,
        ra_signatures=0,
        ekus=[EKU_ANY],
    )
    # ESC1 also true when Any Purpose + client-auth path; tags prefer ESC1
    assert r["esc1_candidate"] is True or r["esc2_candidate"] is True


def test_esc2_empty_eku() -> None:
    r = analyze_template_flags(
        name_flags=0x1,
        enrollment_flags=0,
        ra_signatures=0,
        ekus=[],
    )
    assert r["esc1_candidate"] is True  # empty EKU counts as client-auth capable


def test_esc3_agent_template() -> None:
    r = analyze_template_flags(
        name_flags=0,
        enrollment_flags=0,
        ra_signatures=0,
        ekus=[EKU_CERTIFICATE_REQUEST_AGENT],
    )
    assert r["esc3_agent_template"] is True
    assert "ESC3_AGENT" in r["esc_tags"]


def test_safe_template() -> None:
    r = analyze_template_flags(
        name_flags=0,
        enrollment_flags=0x2,
        ra_signatures=1,
        ekus=["1.3.6.1.5.5.7.3.1"],  # server auth only
    )
    assert r["esc1_candidate"] is False
    assert r["esc2_candidate"] is False
    assert r["esc3_agent_template"] is False


def test_classify_acl_esc4_esc7() -> None:
    c = classify_acl_rights(["WriteDacl", "Enroll"])
    assert c["esc4_template_acl"] is True
    assert c["enroll_right"] is True
    assert c["esc7_ca_manage"] is False

    c2 = classify_acl_rights(["ManageCA"])
    assert c2["esc7_ca_manage"] is True


def test_web_enrollment_endpoints() -> None:
    assert is_web_enrollment_endpoint("https://ca.corp.local/certsrv") is True
    assert is_web_enrollment_endpoint("http://ca/certsrv") is True
    assert is_web_enrollment_endpoint("rpc:ca.corp.local") is False
