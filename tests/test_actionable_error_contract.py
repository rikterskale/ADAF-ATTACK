from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

import adaf_attack.cli as cli
from adaf_attack.cli import app
from adaf_attack.core.cli_contract import ERROR_CATALOG, classify_run_error, error_for
from adaf_attack.core.runner import RunError

runner = CliRunner()


def test_catalog_entries_have_complete_recovery_contracts() -> None:
    assert ERROR_CATALOG
    for code, entry in ERROR_CATALOG.items():
        assert code == code.upper()
        assert len(entry) >= 3
        assert all(isinstance(value, str) and value.strip() for value in entry[:3])
        err = error_for(code)
        assert err.suggested_command


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
        "Approval token has expired": "APPROVAL_TOKEN_EXPIRED",
        "Scoped approval rejected: Approval token has expired": "APPROVAL_TOKEN_EXPIRED",
        "Approval token signature is invalid": "APPROVAL_TOKEN_INVALID",
        "Scoped approval rejected: Approval token signature is invalid": "APPROVAL_TOKEN_INVALID",
        "SSL: CERTIFICATE_VERIFY_FAILED via proxy": "PROXY_TLS_FAILED",
    }
    for message, expected in cases.items():
        assert classify_run_error(message) == expected


def test_installer_and_version_codes_are_catalogued() -> None:
    for code in (
        "VERSION_SKEW",
        "KALI_REQUIRED",
        "UNOWNED_VENV",
        "SUDO_REQUIRED",
        "PYTHON_NOT_FOUND",
        "UNSUPPORTED_EXTRAS",
        "INSTALLER_ARGUMENT",
    ):
        assert code in ERROR_CATALOG
        assert error_for(code).suggested_command


@pytest.mark.parametrize(
    ("message", "code"),
    [
        ("LDAP bind failed for operator", "AUTHENTICATION_FAILED"),
        ("connection refused by target", "TARGET_UNREACHABLE"),
        ("permission denied: workspace", "PERMISSION_DENIED"),
        ("user list not found: users.txt", "INPUT_FILE_INVALID"),
        ("required -P template value is missing", "REQUIRED_INPUT_MISSING"),
        ("Approval token has expired", "APPROVAL_TOKEN_EXPIRED"),
        ("SSL: CERTIFICATE_VERIFY_FAILED via proxy", "PROXY_TLS_FAILED"),
        ("No module named 'textual'", "EXTRA_MISSING"),
        ("unexpected provider failure", "RUN_FAILED"),
    ],
)
def test_run_json_surfaces_induced_failures_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
    message: str,
    code: str,
) -> None:
    monkeypatch.setattr(
        cli,
        "execute_capability",
        lambda *args, **kwargs: (_ for _ in ()).throw(RunError(message)),
    )
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "run",
            "ldap-enum",
            "--domain",
            "corp.test",
            "--dc-ip",
            "192.0.2.10",
        ],
    )
    assert result.exit_code != 0
    error = json.loads(result.output)["error"]
    assert error["code"] == code
    assert error["recovery_command"].startswith("adaf-attack guide")
    assert error["suggested_command"]


def test_generic_provider_failure_collects_redacted_support_evidence() -> None:
    error = error_for("RUN_FAILED")
    assert "doctor --explain" in error.remediation
    assert "redacted support bundle" in error.remediation
    assert error.suggested_command == "adaf-attack support-bundle --output adaf-support-bundle.json"


def test_human_failures_print_guide_when_lost() -> None:
    result = runner.invoke(app, ["explain", "not-a-real-capability"])
    assert result.exit_code != 0
    assert "UNKNOWN_CAPABILITY" in result.output
    assert "When lost:" in result.output
    assert "adaf-attack guide" in result.output
    assert "Cmd:" in result.output
