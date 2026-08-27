from __future__ import annotations

from adaf_attack.core.cli_contract import ERROR_CATALOG, classify_run_error, error_for


def test_catalog_entries_have_complete_recovery_contracts() -> None:
    assert ERROR_CATALOG
    for code, entry in ERROR_CATALOG.items():
        assert code == code.upper()
        assert len(entry) >= 2
        assert all(isinstance(value, str) and value.strip() for value in entry[:2])
        if len(entry) > 2:
            assert entry[2].strip()


def test_guide_and_install_failure_codes_are_catalogued() -> None:
    for code in (
        "GUIDE_ADVANCE_UNSAFE",
        "APPROVAL_TOKEN_EXPIRED",
        "APPROVAL_TOKEN_INVALID",
        "PYTHON_UNSUPPORTED",
        "VENV_REQUIRED",
        "PATH_NOT_FOUND",
        "EXECUTION_POLICY_BLOCKED",
        "PROXY_TLS_FAILED",
        "EXTRA_MISSING",
        "SECRET_IN_OUTPUT",
    ):
        assert code in ERROR_CATALOG
        err = error_for(code)
        assert err.suggested_command


def test_common_runner_failures_map_to_actionable_codes() -> None:
    cases = {
        "LDAP bind failed for operator @ 10.0.0.1": "AUTHENTICATION_FAILED",
        "connection refused by target": "TARGET_UNREACHABLE",
        "permission denied: workspace": "PERMISSION_DENIED",
        "user list not found: users.txt": "INPUT_FILE_INVALID",
        "username required for certificate request": "REQUIRED_INPUT_MISSING",
        "unexpected provider failure": "RUN_FAILED",
        "externally-managed-environment": "VENV_REQUIRED",
        "token expired for engagement": "APPROVAL_TOKEN_EXPIRED",
        "SSL: CERTIFICATE_VERIFY_FAILED via proxy": "PROXY_TLS_FAILED",
    }
    for message, expected in cases.items():
        assert classify_run_error(message) == expected
