"""Coverage for the hardened `doctor` prerequisite probes.

These exercise the Python-floor gate, the external-binary resolution helper, and
the doctor rendering branches for present vs. missing optional tooling, so the
operator can trust `doctor` as a real troubleshooting surface.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import adaf_attack.cli as cli
from adaf_attack.cli import app

runner = CliRunner()


def test_python_supported_matches_running_interpreter() -> None:
    assert cli._python_supported() is ((3, 11) <= sys.version_info < (3, 14))


def test_resolve_binary_returns_first_match_then_none(monkeypatch: pytest.MonkeyPatch) -> None:
    resolved: dict[str, str] = {"ntlmrelayx.py": "/opt/tools/ntlmrelayx.py"}
    monkeypatch.setattr(cli.shutil, "which", lambda name: resolved.get(name))
    assert (
        cli._resolve_binary(("impacket-ntlmrelayx", "ntlmrelayx.py")) == "/opt/tools/ntlmrelayx.py"
    )
    assert cli._resolve_binary(("missing-a", "missing-b")) is None


def test_path_write_probe_creates_and_removes_a_probe(tmp_path: Path) -> None:
    ok, error = cli._path_write_probe(tmp_path / "nested")
    assert ok is True and error is None
    assert list((tmp_path / "nested").iterdir()) == []


def test_path_write_probe_reports_os_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fail(*args, **kwargs):
        raise PermissionError("locked")

    monkeypatch.setattr(cli.tempfile, "NamedTemporaryFile", fail)
    ok, error = cli._path_write_probe(tmp_path)
    assert ok is False and error and "PermissionError" in error


def test_workspace_is_empty_for_missing_directory(tmp_path: Path) -> None:
    assert cli._workspace_is_empty(tmp_path / "missing") is True


def test_path_check_returns_actionable_error_for_unwritable_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "_path_write_probe", lambda path: (False, "PermissionError"))
    result = cli._path_check("workspace", tmp_path / "workspace")
    assert result["status"] == "error"
    assert "ADAF_ATTACK_WORKSPACE" in result["remediation"]


@pytest.mark.parametrize(
    ("path_id", "expected"),
    [("data_dir", "ADAF_ATTACK_DATA_DIR"), ("config_dir", "ADAF_ATTACK_CONFIG_DIR")],
)
def test_path_check_names_explicit_overrides(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, path_id: str, expected: str
) -> None:
    monkeypatch.setattr(cli, "_path_write_probe", lambda path: (False, "PermissionError"))
    result = cli._path_check(path_id, tmp_path / path_id)
    assert expected in result["remediation"]


def test_doctor_flags_unsupported_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_python_supported", lambda: False)
    result = runner.invoke(app, ["--format", "json", "doctor"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is False
    python_check = next(check for check in payload["checks"] if check["id"] == "python")
    assert python_check["status"] == "error"
    assert python_check["remediation"] and "Python" in python_check["remediation"]


def test_python_fourteen_is_outside_release_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    class VersionInfo:
        major = 3
        minor = 14

        def __ge__(self, other):
            return (self.major, self.minor) >= other

        def __lt__(self, other):
            return (self.major, self.minor) < other

    monkeypatch.setattr(cli.sys, "version_info", VersionInfo())
    assert cli._python_supported() is False


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
