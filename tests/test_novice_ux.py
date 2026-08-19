"""Tests for the novice-facing UX additions: interactive run, novice list, init."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from adaf_attack.cli import app
from adaf_attack.core import user_config
from adaf_attack.core.novice import (
    prompt_spec_for_option,
    required_prompts,
    safety_summary,
)
from adaf_attack.core.registry import Capability, capability_registry

runner = CliRunner()


def test_prompt_spec_covers_universal_flags() -> None:
    for flag in ("--domain", "--dc-ip", "--username", "--password"):
        spec = prompt_spec_for_option(flag)
        assert spec["label"]
        assert spec["help"]


def test_prompt_spec_falls_back_for_unknown_flag() -> None:
    spec = prompt_spec_for_option("--never-seen")
    assert "--never-seen" in spec["label"]


def test_prompt_spec_handles_param_style() -> None:
    spec = prompt_spec_for_option("-P sam=<user>")
    assert "sam" in spec["label"]
    assert "sam" in spec["help"]


def test_required_prompts_for_destructive_capability() -> None:
    import adaf_attack.capabilities  # noqa: F401

    cap = capability_registry.get("shadow-creds")
    assert cap is not None
    prompts = required_prompts(cap)
    options = {entry["option"] for entry in prompts}
    assert "--domain" in options
    assert "--dc-ip" in options
    assert "--sam" in options
    assert "--force" in options


def test_list_capabilities_novice_view_json() -> None:
    result = runner.invoke(app, ["--format", "json", "list-capabilities", "--novice"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["view"] == "novice"
    assert payload["legend"]["GREEN"].startswith("Works from saved evidence")
    assert payload["count"] > 0


def test_list_capabilities_safe_only_filters_to_green() -> None:
    result = runner.invoke(
        app, ["--format", "json", "list-capabilities", "--novice", "--safe-only"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["safe_only"] is True
    for cap in payload["capabilities"]:
        actual = capability_registry.get(cap["id"])
        assert actual is not None
        assert safety_summary(actual)["level"] == "GREEN"


def test_init_saves_defaults_via_flags(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "--non-interactive",
            "init",
            "--workspace",
            str(tmp_path / "ws"),
            "--domain",
            "corp.example",
            "--dc-ip",
            "10.0.0.10",
            "--username",
            "svc-red",
            "--skip-quickstart",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["saved"]["target.domain"] == "corp.example"
    assert payload["saved"]["target.dc_ip"] == "10.0.0.10"
    assert payload["saved"]["target.username"] == "svc-red"
    # quickstart hint suppressed
    assert not any("quickstart" in step for step in payload["next_steps"])

    stored = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert stored["target.domain"] == "corp.example"


def test_init_non_interactive_without_flags_is_noop(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")

    result = runner.invoke(app, ["--format", "json", "--non-interactive", "init"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["saved"] == {}
    assert not (tmp_path / "config.json").is_file()


def test_run_interactive_refuses_non_interactive_context() -> None:
    result = runner.invoke(
        app,
        [
            "--non-interactive",
            "run",
            "ldap-enum",
            "--interactive",
        ],
    )
    assert result.exit_code != 0
    assert "INTERACTIVE_MODE_DISABLED" in result.output


def test_run_interactive_prompts_for_required_and_aborts_on_no() -> None:
    # `ldap-enum` requires --domain and --dc-ip. Feed values, then answer No
    # to the final confirmation.
    result = runner.invoke(
        app,
        ["run", "ldap-enum", "--interactive"],
        input="corp.lab\n10.0.0.10\n\nn\n",
    )
    assert result.exit_code != 0
    assert "USER_ABORTED" in result.output or "declined" in result.output.lower()


def test_capability_dataclass_is_stable() -> None:
    # Guard: novice.py depends on Capability structure. This is a smoke test.
    cap = Capability(id="x", summary="y", destructive=False, category="analysis")
    assert safety_summary(cap)["level"] == "GREEN"
