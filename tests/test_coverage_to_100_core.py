"""Focused tests for every branch in the local profile and completion helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from adaf_attack.cli import app
from adaf_attack.core import completions, profiles, user_config


def test_completion_generators_and_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each supported shell has a usable script and hint."""
    for shell, marker in {
        "bash": "complete -F",
        "zsh": "compdef _adaf_attack",
        "fish": "complete -c adaf-attack",
        "powershell": "Register-ArgumentCompleter",
    }.items():
        assert marker in completions.generate_completion(shell)
        assert completions.completion_install_hint(shell)
    with pytest.raises(ValueError, match="Unsupported shell"):
        completions.generate_completion("cmd")

    from adaf_attack.core.registry import capability_registry

    monkeypatch.setattr(capability_registry, "ids", lambda: (_ for _ in ()).throw(RuntimeError()))
    assert completions._capability_ids() == []


def test_profiles_all_persistence_validation_and_opsec_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Profile persistence handles absent, malformed, valid, and invalid data."""
    profile_file = tmp_path / "nested" / "profiles.json"
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(profiles, "profiles_path", lambda: profile_file)
    monkeypatch.setattr(user_config, "config_path", lambda: config_file)

    assert profiles.load_profiles() == {}
    profile_file.parent.mkdir(parents=True)
    profile_file.write_text("[]", encoding="utf-8")
    assert profiles.load_profiles() == {}
    profile_file.write_text("not json", encoding="utf-8")
    assert profiles.load_profiles() == {}

    with pytest.raises(ValueError, match="non-empty"):
        profiles.set_profile("bad name", {})
    with pytest.raises(ValueError, match="Unknown profile field"):
        profiles.set_profile("lab", {"unknown": "value"})
    with pytest.raises(ValueError, match="opsec_profile"):
        profiles.set_profile("lab", {"opsec_profile": "unsafe"})

    saved = profiles.set_profile(
        "lab",
        {"domain": "corp.test", "ldaps": "yes", "kerberos": "0", "opsec_profile": "stealth"},
    )
    assert saved["ldaps"] is True and saved["kerberos"] is False
    assert profiles.get_profile("lab") == saved
    assert profiles.list_profiles() == [{"name": "lab", **saved}]
    assert profiles.apply_profile_to_defaults("lab")["target.domain"] == "corp.test"
    assert profiles.active_opsec("loud") == "loud"
    assert profiles.active_opsec(profile_name="lab") == "stealth"
    assert profiles.active_opsec("invalid", "missing") == "stealth"
    assert profiles.delete_profile("lab") is True
    assert profiles.delete_profile("lab") is False
    with pytest.raises(ValueError, match="Unknown profile"):
        profiles.apply_profile_to_defaults("lab")


def test_profile_cli_errors_and_secondary_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLI profile commands exercise user-facing error and clear-default paths."""
    monkeypatch.setattr(profiles, "profiles_path", lambda: tmp_path / "profiles.json")
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")
    runner = CliRunner()
    missing = runner.invoke(app, ["--format", "json", "profile", "show", "missing"])
    assert missing.exit_code == 1
    invalid = runner.invoke(app, ["--format", "json", "profile", "set", "lab", "--opsec", "bad"])
    assert invalid.exit_code == 1
    assert runner.invoke(app, ["--format", "json", "profile", "default"]).exit_code == 0
    assert runner.invoke(app, ["--format", "json", "profile", "delete", "missing"]).exit_code == 1
    unsupported = runner.invoke(app, ["--format", "json", "completions", "cmd"])
    assert unsupported.exit_code == 1
    assert json.loads(unsupported.output)["error"]["code"] == "UNSUPPORTED_SHELL"


def test_profile_and_session_human_output_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Human output exercises tables, panels, and missing-session remediation."""
    monkeypatch.setattr(profiles, "profiles_path", lambda: tmp_path / "profiles.json")
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")
    runner = CliRunner()
    assert runner.invoke(app, ["profile", "list"]).exit_code == 0
    assert (
        runner.invoke(
            app,
            [
                "profile",
                "set",
                "lab",
                "--domain",
                "corp.test",
                "--dc-ip",
                "192.0.2.10",
                "--notes",
                "x",
            ],
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["profile", "list"]).exit_code == 0
    assert runner.invoke(app, ["profile", "show", "lab"]).exit_code == 0
    assert runner.invoke(app, ["profile", "default", "lab"]).exit_code == 0
    assert runner.invoke(app, ["profile", "use", "missing"]).exit_code == 1
    assert runner.invoke(app, ["profile", "default", "missing"]).exit_code == 1
    assert runner.invoke(app, ["profile", "set", "bad name"]).exit_code == 1
    assert runner.invoke(app, ["completions", "fish"]).exit_code == 0
    assert (
        runner.invoke(app, ["session", "show", "--session", str(tmp_path / "missing")]).exit_code
        == 1
    )

    session = tmp_path / "session"
    session.mkdir()
    (session / "session.json").write_text('{"session_id":"human"}', encoding="utf-8")
    (session / "interesting.json").write_text(
        '{"top_paths":[{"score":3,"path":["a@corp","b@corp"]}]}', encoding="utf-8"
    )
    (session / "graph.json").write_text('{"summary":{"nodes":2,"edges":1}}', encoding="utf-8")
    (session / "findings.json").write_text('{"findings":[]}', encoding="utf-8")
    shown = runner.invoke(app, ["session", "show", "--session", str(session)])
    assert shown.exit_code == 0 and "Top paths" in shown.output


def test_ux_helpers_cover_empty_and_malformed_offline_inputs(tmp_path: Path) -> None:
    """UX helpers retain usable output for malformed or empty session data."""
    from adaf_attack.core.registry import Capability
    from adaf_attack.core.ux import (
        build_ready_command,
        group_capabilities_by_phase,
        session_findings_summary,
        unified_search,
    )
    from adaf_attack.core.ux_extra import format_next_actions_block, session_findings_dashboard

    cap = Capability("custom", "unexpected", "summary", False, lambda **_: {})
    assert group_capabilities_by_phase() is not None
    command = build_ready_command(
        "ldap-enum", domain="corp.test", dc_ip="192.0.2.10", username="user", extra={"x": "y"}
    )
    assert "--username user" in command and "-P x=y" in command
    assert unified_search("") == {"query": "", "capabilities": [], "count": 0}
    session = tmp_path / "session"
    session.mkdir()
    (session / "findings.json").write_text('{"findings": {}}', encoding="utf-8")
    (session / "interesting.json").write_text('{"top_paths": {}}', encoding="utf-8")
    (session / "graph.json").write_text("{}", encoding="utf-8")
    assert session_findings_summary(session)["finding_count"] == 0
    assert session_findings_dashboard(session)["findings"] == []
    assert format_next_actions_block(cap)["count"] == 0


def test_dcsync_principal_file_and_kerberos_error_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DCSync accepts an offline principal file and propagates SMB authentication errors."""
    from adaf_attack.capabilities import dcsync
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session
    from adaf_attack.core.target import Target

    principal_file = tmp_path / "principals.txt"
    principal_file.write_text("alice\n# comment\n bob \n", encoding="utf-8")
    monkeypatch.setattr(dcsync, "require_impacket", lambda _: None)

    class Smb:
        def kerberosLogin(self, *args, **kwargs) -> None:  # noqa: N802
            raise RuntimeError("offline kerberos failure")

    monkeypatch.setattr("impacket.smbconnection.SMBConnection", lambda *args, **kwargs: Smb())
    target = Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", use_kerberos=True)
    with pytest.raises(RuntimeError, match="offline kerberos"):
        dcsync.Dcsync().run(
            target,
            Session(tmp_path / "session"),
            AttackGraph(),
            principals=str(principal_file),
        )


def test_unpac_validates_credential_material_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """unPAC rejects incomplete certificate material before network operations."""
    from adaf_attack.capabilities import unpac_the_hash
    from adaf_attack.core.graph import AttackGraph
    from adaf_attack.core.session import Session
    from adaf_attack.core.target import Target

    monkeypatch.setattr(unpac_the_hash, "require_impacket", lambda _: None)
    target = Target(domain="corp.test", dc_ip="192.0.2.10", username="alice", password="pw")
    with pytest.raises(RuntimeError, match="pfx"):
        unpac_the_hash.UnpacTheHash().run(
            target, Session(tmp_path / "session"), AttackGraph(), sam="alice", key="key.pem"
        )
