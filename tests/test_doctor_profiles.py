"""Tests for scoped prerequisite diagnostics and redacted support bundles."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import adaf_attack.cli as cli
import adaf_attack.demo as demo
from adaf_attack.cli import app

runner = CliRunner()


def _localize_paths(monkeypatch, root: Path) -> None:
    monkeypatch.setattr(cli, "user_data_dir", lambda: root / "data")
    monkeypatch.setattr(cli, "user_config_dir", lambda: root / "config")
    monkeypatch.setattr(cli, "default_workspace_dir", lambda: root / "workspaces")
    monkeypatch.setattr(cli, "_workspace_is_empty", lambda path: True)
    monkeypatch.setattr(cli, "_python_supported", lambda: True)


def test_offline_profile_is_local_and_has_scoped_contract(monkeypatch, tmp_path: Path) -> None:
    _localize_paths(monkeypatch, tmp_path)

    def fail_network(*args, **kwargs):
        raise AssertionError("offline doctor must not perform network probes")

    monkeypatch.setattr(cli.socket, "create_connection", fail_network)
    monkeypatch.setattr(cli.socket, "getaddrinfo", fail_network)
    payload = cli._doctor_payload("offline")

    assert payload["ok"] is True
    assert payload["profile"] == "offline"
    assert all({"severity", "scope"} <= check.keys() for check in payload["checks"])
    assert not any(check["scope"] == "live-ad" for check in payload["checks"])


def test_live_profile_requires_explicit_target(monkeypatch, tmp_path: Path) -> None:
    _localize_paths(monkeypatch, tmp_path)
    payload = cli._doctor_payload("live-ad")
    check = next(item for item in payload["checks"] if item["id"] == "target-arguments")
    assert payload["ok"] is False
    assert check["severity"] == "blocking"
    assert "--domain" in check["remediation"]


def test_live_profile_runs_explicit_dns_and_port_probes(monkeypatch, tmp_path: Path) -> None:
    _localize_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(cli.socket, "getaddrinfo", lambda *args: [(0, 0, 0, "", ("10.0.0.10", 0))])

    class Connection:
        def close(self):
            return None

    probes = []

    def connect(address, timeout):
        probes.append((address, timeout))
        return Connection()

    monkeypatch.setattr(cli.socket, "create_connection", connect)
    payload = cli._doctor_payload("live-ad", domain="lab.test", dc_ip="10.0.0.10", timeout=1.5)

    assert payload["ok"] is True
    assert next(item for item in payload["checks"] if item["id"] == "domain-dns")["status"] == "ok"
    assert len(probes) == 4
    assert all(timeout == 1.5 for _, timeout in probes)


def test_profile_validation_and_socket_failures(monkeypatch, tmp_path: Path) -> None:
    _localize_paths(monkeypatch, tmp_path)
    with pytest.raises(Exception, match="unknown doctor profile"):
        cli._doctor_payload("unknown")
    with pytest.raises(Exception, match="between 0 and 60"):
        cli._doctor_payload("offline", timeout=0)

    monkeypatch.setattr(
        cli.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror("bad dns")),
    )
    status, detail = cli._socket_check("bad.test", 389, 1.0)
    assert status == "error" and "DNS resolution failed" in detail
    monkeypatch.setattr(
        cli.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("refused")),
    )
    status, detail = cli._socket_check("dc.test", 389, 1.0)
    assert status == "warning" and "not reachable" in detail


def test_operator_and_certipy_profiles_make_missing_tools_blocking(
    monkeypatch, tmp_path: Path
) -> None:
    _localize_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "_resolve_binary", lambda candidates: None)
    operator = cli._doctor_payload("operator")
    relay = next(item for item in operator["checks"] if item["id"] == "ntlmrelayx (cli)")
    assert relay["status"] == "error" and relay["severity"] == "blocking"

    real_version = cli._package_version
    monkeypatch.setattr(
        cli, "_package_version", lambda name: None if name == "certipy-ad" else real_version(name)
    )
    certipy = cli._doctor_payload("certipy")
    certipy_check = next(item for item in certipy["checks"] if item["id"] == "certipy")
    assert certipy_check["status"] == "error"


def test_live_profile_reports_dns_and_port_failures(monkeypatch, tmp_path: Path) -> None:
    _localize_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(
        cli.socket, "getaddrinfo", lambda *args: (_ for _ in ()).throw(socket.gaierror("missing"))
    )
    monkeypatch.setattr(
        cli.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("refused")),
    )
    payload = cli._doctor_payload("live-ad", domain="lab.test", dc_ip="10.0.0.10")
    assert (
        next(item for item in payload["checks"] if item["id"] == "domain-dns")["status"] == "error"
    )
    assert (
        next(item for item in payload["checks"] if item["id"] == "dc-ldap")["status"] == "warning"
    )


def test_returning_workspace_and_redaction_branches(monkeypatch, tmp_path: Path) -> None:
    _localize_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "_workspace_is_empty", lambda path: False)
    payload = cli._doctor_payload("offline")
    assert "capability-help" in payload["next_step"]
    assert cli._package_version("package-that-does-not-exist") is None
    assert cli._sanitize_support_value({"password": "secret"}) == {"password": "<redacted>"}


@pytest.mark.parametrize(
    ("direct_url", "expected"),
    [(None, "wheel-or-sdist"), ('{"editable": true}', "editable"), ('{"dir_info": {}}', "source")],
)
def test_installation_kind_contract(monkeypatch, direct_url: str | None, expected: str) -> None:
    distribution = SimpleNamespace(read_text=lambda name: direct_url)
    monkeypatch.setattr(cli.importlib_metadata, "distribution", lambda name: distribution)
    assert cli._installation_kind() == expected


def test_installation_kind_handles_missing_distribution(monkeypatch) -> None:
    def missing(name: str):
        raise cli.importlib_metadata.PackageNotFoundError(name)

    monkeypatch.setattr(cli.importlib_metadata, "distribution", missing)
    assert cli._installation_kind() == "unknown"


def test_packaged_demo_reports_missing_resource(monkeypatch, tmp_path: Path) -> None:
    class MissingResource:
        def is_file(self) -> bool:
            return False

    class MissingPackage:
        def joinpath(self, name: str) -> MissingResource:
            return MissingResource()

    monkeypatch.setattr(demo, "files", lambda package: MissingPackage())
    with pytest.raises(FileNotFoundError, match="acl-enum.json"):
        demo.materialize_demo_session(tmp_path / "demo")


def test_user_readiness_profile_checks_packaged_demo(monkeypatch, tmp_path: Path) -> None:
    _localize_paths(monkeypatch, tmp_path)
    payload = cli._doctor_payload("user-readiness")
    packaged = next(item for item in payload["checks"] if item["id"] == "packaged-demo")
    assert packaged["status"] == "ok"
    assert packaged["scope"] == "user-readiness"


def test_user_readiness_profile_reports_resource_errors(monkeypatch, tmp_path: Path) -> None:
    _localize_paths(monkeypatch, tmp_path)

    def fail_files(package: str):
        raise OSError("resource unavailable")

    monkeypatch.setattr("importlib.resources.files", fail_files)
    payload = cli._doctor_payload("user-readiness")
    packaged = next(item for item in payload["checks"] if item["id"] == "packaged-demo")
    assert packaged["status"] == "error"
    assert "resource unavailable" in str(packaged)


def test_support_bundle_write_failure_is_actionable(monkeypatch, tmp_path: Path) -> None:
    _localize_paths(monkeypatch, tmp_path)
    occupied = tmp_path / "occupied"
    occupied.write_text("file", encoding="utf-8")
    result = runner.invoke(
        app, ["--format", "json", "support-bundle", "--output", str(occupied / "bundle.json")]
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error"]["code"] == "SUPPORT_BUNDLE_WRITE_FAILED"


def test_support_bundle_redacts_sensitive_values(monkeypatch, tmp_path: Path) -> None:
    _localize_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("ADAF_APPROVAL_HMAC_KEY", "do-not-export")
    output = tmp_path / "support.json"
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "support-bundle",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    bundle = json.loads(output.read_text(encoding="utf-8"))
    assert bundle["schema"] == 1
    assert bundle["environment"]["ADAF_APPROVAL_HMAC_KEY"] == {"set": True}
    serialized = json.dumps(bundle)
    assert "do-not-export" not in serialized
    assert str(Path.home()) not in serialized


def test_support_identifier_replacement() -> None:
    value = {"value": "dc=10.0.0.10 domain=lab.test", "nested": ["lab.test"]}
    sanitized = cli._replace_support_identifiers(value, ("lab.test", "10.0.0.10"))
    assert sanitized == {"value": "dc=<TARGET> domain=<TARGET>", "nested": ["<TARGET>"]}
