"""Coverage for the hardened `doctor` prerequisite probes.

These exercise the Python-floor gate, the external-binary resolution helper, and
the doctor rendering branches for present vs. missing optional tooling, so the
operator can trust `doctor` as a real troubleshooting surface.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

import adaf_attack.cli as cli
from adaf_attack.cli import app

runner = CliRunner()


def test_python_supported_matches_running_interpreter() -> None:
    # The test suite only runs on supported interpreters (>= 3.11).
    assert cli._python_supported() is True


def test_resolve_binary_returns_first_match_then_none(monkeypatch: pytest.MonkeyPatch) -> None:
    resolved: dict[str, str] = {"ntlmrelayx.py": "/opt/tools/ntlmrelayx.py"}
    monkeypatch.setattr(cli.shutil, "which", lambda name: resolved.get(name))
    assert (
        cli._resolve_binary(("impacket-ntlmrelayx", "ntlmrelayx.py")) == "/opt/tools/ntlmrelayx.py"
    )
    assert cli._resolve_binary(("missing-a", "missing-b")) is None


def test_doctor_flags_unsupported_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_python_supported", lambda: False)
    result = runner.invoke(app, ["--format", "json", "doctor"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is False
    python_check = next(check for check in payload["checks"] if check["id"] == "python")
    assert python_check["status"] == "error"
    assert python_check["remediation"] and "Python" in python_check["remediation"]


def test_doctor_reports_resolved_external_binaries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_resolve_binary", lambda candidates: f"/usr/bin/{candidates[0]}")
    result = runner.invoke(app, ["--format", "json", "doctor", "--explain"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    binary_checks = {
        check["id"]: check for check in payload["checks"] if check["id"].endswith("(cli)")
    }
    assert binary_checks
    for check in binary_checks.values():
        assert check["status"] == "ok"
        assert check["value"].startswith("/usr/bin/")
        assert check["remediation"] is None
