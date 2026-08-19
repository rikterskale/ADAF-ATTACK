"""Focused coverage for the selected novice UX improvements."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import typer
from typer.testing import CliRunner

import adaf_attack.cli as cli
from adaf_attack.cli import app
from adaf_attack.core.novice import glossary_items
from adaf_attack.tui.app import ADAFAttackApp

runner = CliRunner()


def test_suggestions_and_why_helpers() -> None:
    suggested = cli._unknown_capability_error("unpack-the-hash")
    assert suggested.details and "unpac-the-hash" in suggested.details["suggestions"]
    generic = cli._unknown_capability_error("not-a-real-capability")
    assert generic.suggested_command == "adaf-attack capability-help"
    cap = SimpleNamespace(
        id="ldap-enum", summary="Enumerate LDAP", category="recon", destructive=False
    )
    assert "contacts the authorized target" in cli._why_text(cap)
    offline = SimpleNamespace(
        id="report", summary="Build report", category="analysis", destructive=False
    )
    assert "does not contact a target" in cli._why_text(offline)
    assert cli._redaction_changes({"gone": "value"}, {}) == []


def test_glossary_cli_all_branches() -> None:
    one = runner.invoke(app, ["--format", "json", "glossary", "dcsync"])
    assert one.exit_code == 0 and "definition" in one.output
    all_terms = runner.invoke(app, ["--format", "json", "glossary"])
    assert all_terms.exit_code == 0 and "spn" in all_terms.output
    missing = runner.invoke(app, ["--format", "json", "glossary", "missing"])
    assert missing.exit_code == 1 and "UNKNOWN_GLOSSARY_TERM" in missing.output
    assert "opsec" in glossary_items()


def test_first_destructive_use_requires_acknowledgement(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "--non-interactive",
            "run",
            "shadow-creds",
            "--domain",
            "corp.test",
            "--dc-ip",
            "10.0.0.10",
            "--force",
            "--workspace",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 1
    assert "FIRST_DESTRUCTIVE_USE_CONFIRMATION_REQUIRED" in result.output


def test_support_and_package_previews(tmp_path: Path) -> None:
    support = runner.invoke(
        app,
        ["--format", "json", "support-bundle", "--preview", "--output", str(tmp_path / "s.json")],
    )
    assert support.exit_code == 0 and '"preview": true' in support.output

    session = tmp_path / "session"
    session.mkdir()
    (session / "findings.json").write_text('{"password": "secret"}', encoding="utf-8")
    (session / "secret.pfx").write_bytes(b"not shipped")
    (session / "bad.json").write_text("not-json", encoding="utf-8")
    (session / "vault").mkdir()
    (session / "vault" / "secret.json").write_text('{"password": "skip"}', encoding="utf-8")
    package = runner.invoke(
        app,
        [
            "--format",
            "json",
            "engagement",
            "package",
            "--session",
            str(session),
            "--preview",
        ],
    )
    assert package.exit_code == 0
    assert "secret.pfx" in package.output
    missing = runner.invoke(
        app,
        [
            "--format",
            "json",
            "engagement",
            "package",
            "--session",
            str(tmp_path / "missing"),
            "--preview",
        ],
    )
    assert missing.exit_code != 0


def test_why_human_output(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "execute_capability", lambda *a, **k: {"session_path": str(tmp_path)})
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    result = runner.invoke(
        app,
        [
            "run",
            "ldap-enum",
            "--why",
            "--domain",
            "corp.test",
            "--dc-ip",
            "10.0.0.10",
            "--workspace",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0 and "Why: ldap-enum" in result.output


def test_ack_helper_interactive_confirmation(monkeypatch, tmp_path: Path) -> None:
    ctx = SimpleNamespace(ensure_object=lambda _: {"output_format": "json"})
    monkeypatch.setattr(cli.typer, "prompt", lambda *a, **k: "shadow-creds")
    cli._require_destructive_ack(ctx, "shadow-creds", tmp_path, explicit=False, interactive=True)
    assert (tmp_path / ".adaf-attack-destructive-ack.json").is_file()


def test_ack_helper_rejects_wrong_name_and_handles_bad_marker(monkeypatch, tmp_path: Path) -> None:
    ctx = SimpleNamespace(ensure_object=lambda _: {"output_format": "json"})
    marker = tmp_path / ".adaf-attack-destructive-ack.json"
    marker.write_text("not-json", encoding="utf-8")
    monkeypatch.setattr(cli.typer, "prompt", lambda *a, **k: "wrong")
    with pytest.raises(typer.Exit):
        cli._require_destructive_ack(
            ctx, "shadow-creds", tmp_path, explicit=False, interactive=True
        )


def test_ack_helper_handles_read_only_marker(monkeypatch, tmp_path: Path) -> None:
    ctx = SimpleNamespace(ensure_object=lambda _: {"output_format": "human", "no_color": True})
    original = Path.write_text

    def fail_write(self: Path, *args, **kwargs):
        if self.name == ".adaf-attack-destructive-ack.json":
            raise OSError("read-only")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_write)
    cli._require_destructive_ack(ctx, "shadow-creds", tmp_path, explicit=True, interactive=False)


def test_tui_validation_help_and_cheat_sheet() -> None:
    async def exercise() -> None:
        tui = ADAFAttackApp()
        async with tui.run_test() as pilot:
            await pilot.pause()
            validation = tui.query_one("#target-validation")
            tui.notify = Mock()  # type: ignore[method-assign]
            for domain, dc in (
                ("", ""),
                ("bad domain", ""),
                ("corp.test", ""),
                ("corp.test", "http://dc"),
                ("corp.test", "strange"),
                ("corp.test", "dc"),
                ("corp.test", "10.0.0.10"),
            ):
                tui.query_one("#domain").value = domain
                tui.query_one("#dc_ip").value = dc
                tui._validate_target_inline()
                assert str(validation.render())
            tui.action_show_cheat_sheet()
            assert tui.notify.called

    asyncio.run(exercise())
