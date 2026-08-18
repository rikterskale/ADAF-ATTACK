from __future__ import annotations

from adaf_attack.core.cli_contract import ERROR_CATALOG, classify_run_error


def test_catalog_entries_have_complete_recovery_contracts() -> None:
    assert ERROR_CATALOG
    for code, entry in ERROR_CATALOG.items():
        assert code == code.upper()
        assert len(entry) >= 2
        assert all(isinstance(value, str) and value.strip() for value in entry[:2])
        if len(entry) > 2:
            assert entry[2].strip()


def test_common_runner_failures_map_to_actionable_codes() -> None:
    cases = {
        "LDAP bind failed for operator @ 10.0.0.1": "AUTHENTICATION_FAILED",
        "connection refused by target": "TARGET_UNREACHABLE",
        "permission denied: workspace": "PERMISSION_DENIED",
        "user list not found: users.txt": "INPUT_FILE_INVALID",
        "username required for certificate request": "REQUIRED_INPUT_MISSING",
        "unexpected provider failure": "RUN_FAILED",
    }
    for message, expected in cases.items():
        assert classify_run_error(message) == expected
