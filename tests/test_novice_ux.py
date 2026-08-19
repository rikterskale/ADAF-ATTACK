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


# ---------------------------------------------------------------------------
# Full-coverage tests for the interactive-run helper and init human paths.
# ---------------------------------------------------------------------------


def test_required_prompts_marks_param_style_flags() -> None:
    import adaf_attack.capabilities  # noqa: F401

    cap = capability_registry.get("gpp-cpassword-hunt")
    assert cap is not None
    prompts = required_prompts(cap)
    assert prompts, "expected at least one required prompt"
    param_entry = next(entry for entry in prompts if entry["is_param"])
    assert param_entry["param_key"] == "sysvol"


def test_interactive_run_helper_rejects_unknown_capability() -> None:
    # Reach the helper's UNKNOWN_CAPABILITY branch through the CLI so we
    # do not have to fabricate a typer.Context.
    result = runner.invoke(app, ["run", "not-a-capability", "--interactive"])
    assert result.exit_code != 0
    assert "UNKNOWN_CAPABILITY" in result.output


def test_interactive_run_confirms_destructive_yes(monkeypatch) -> None:
    # Destructive capability with force NOT already provided, user answers YES.
    result = runner.invoke(
        app,
        ["run", "shadow-creds", "--interactive", "-d", "corp.lab", "--dc-ip", "10.0.0.10"],
        # order: --sam prompt (blank), --force prompt (YES), confirm (n → abort)
        input="\nYES\nn\n",
    )
    # We abort at the final confirm to avoid actually executing.
    assert result.exit_code != 0
    assert "shadow-creds" in result.output


def test_interactive_run_confirms_destructive_no() -> None:
    # Destructive capability, force NOT already, user answers NO → aborts.
    result = runner.invoke(
        app,
        ["run", "shadow-creds", "--interactive", "-d", "corp.lab", "--dc-ip", "10.0.0.10"],
        input="\nNO\n",
    )
    assert result.exit_code != 0
    assert "USER_ABORTED" in result.output or "Force" in result.output


def test_interactive_run_prompts_for_param_style() -> None:
    # gpp-cpassword-hunt requires a -P sysvol=<path> parameter.
    result = runner.invoke(
        app,
        ["run", "gpp-cpassword-hunt", "--interactive", "-d", "corp.lab", "--dc-ip", "10.0.0.10"],
        input="/mnt/sysvol\nn\n",
    )
    assert result.exit_code != 0
    assert "sysvol" in result.output.lower()


def test_interactive_run_notes_already_provided_options() -> None:
    # --domain and --dc-ip provided via flags → skipped in the prompt loop.
    result = runner.invoke(
        app,
        ["run", "ldap-enum", "--interactive", "-d", "corp.lab", "--dc-ip", "10.0.0.10"],
        input="n\n",
    )
    assert result.exit_code != 0
    assert "already provided" in result.output


def test_interactive_run_prints_glossary_hint_for_known_capability() -> None:
    # kerberoast is in novice._GLOSSARY. The helper prints the glossary line
    # while asking for --domain (not provided on the command line).
    result = runner.invoke(
        app,
        ["run", "kerberoast", "--interactive"],
        input="corp.lab\n10.0.0.10\n\nn\n",
    )
    assert result.exit_code != 0
    assert "Glossary" in result.output


def test_interactive_run_full_pipeline_yes_executes(monkeypatch) -> None:
    # Confirm YES → post-interactive assignment branch runs, then
    # execute_capability is called. We stub the runner to keep the test offline.
    import adaf_attack.cli as cli_module

    called: dict[str, object] = {}

    def fake_execute(capability: str, target, **kwargs):
        called["capability"] = capability
        called["kwargs"] = kwargs
        return {"session_path": "/tmp/session-x", "session_id": "sess-x"}

    monkeypatch.setattr(cli_module, "execute_capability", fake_execute)

    result = runner.invoke(
        app,
        ["run", "ldap-enum", "--interactive", "-d", "corp.lab", "--dc-ip", "10.0.0.10"],
        input="y\n",
    )
    assert result.exit_code == 0, result.output
    assert called["capability"] == "ldap-enum"


def test_list_capabilities_safe_only_reports_empty(monkeypatch) -> None:
    # Force safety_summary to say every capability is YELLOW so --safe-only
    # empties the list and prints the "empty" panel.
    import adaf_attack.core.novice as novice_module

    def not_green(_cap):
        return {"level": "YELLOW", "network": True, "plain": "x"}

    monkeypatch.setattr(novice_module, "safety_summary", not_green)

    result = runner.invoke(app, ["--format", "json", "list-capabilities", "--safe-only"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["filter"] == "safe-only"
    assert payload["count"] == 0


def test_init_human_mode_prints_panel_and_next_steps(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")

    result = runner.invoke(
        app,
        [
            "--non-interactive",
            "init",
            "--workspace",
            str(tmp_path / "ws"),
            "--domain",
            "corp.example",
        ],
    )
    assert result.exit_code == 0, result.output
    # Panel header and Next: block
    assert "ADAF-ATTACK init" in result.output
    assert "Saved defaults" in result.output
    assert "Next:" in result.output
    assert "quickstart" in result.output


def test_init_interactive_prompts_persist_values(tmp_path: Path, monkeypatch) -> None:
    # No --non-interactive flag → prompt path runs and reads from stdin.
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")

    result = runner.invoke(
        app,
        ["init"],
        input=f"{tmp_path / 'ws'}\ncorp.tty\n10.0.0.9\nsvc\n",
    )
    assert result.exit_code == 0, result.output
    stored = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert stored["target.domain"] == "corp.tty"
    assert stored["target.dc_ip"] == "10.0.0.9"
    assert stored["target.username"] == "svc"


def test_init_reports_saved_errors_from_set_key(tmp_path: Path, monkeypatch) -> None:
    import adaf_attack.core.user_config as user_config_module

    def deny_set(*_args, **_kwargs):
        raise PermissionError("locked")

    monkeypatch.setattr(user_config_module, "set_key", deny_set)

    result = runner.invoke(
        app,
        ["--non-interactive", "init", "--workspace", str(tmp_path / "ws")],
    )
    assert result.exit_code == 0, result.output
    assert "could not be saved" in result.output.lower()


def test_init_human_no_saved_defaults_message(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(user_config, "config_path", lambda: tmp_path / "config.json")
    result = runner.invoke(app, ["--non-interactive", "init", "--skip-quickstart"])
    assert result.exit_code == 0, result.output
    assert "No defaults saved" in result.output


def test_interactive_run_force_already_skips_prompt_and_forwards(monkeypatch) -> None:
    # --force already provided → the helper skips the destructive prompt and
    # execute_capability is invoked with force=True after confirmation.
    import adaf_attack.cli as cli_module

    captured: dict[str, object] = {}

    def fake_execute(capability: str, target, **kwargs):
        captured["capability"] = capability
        captured["force"] = kwargs.get("force")
        return {"session_path": "/tmp/s", "session_id": "s"}

    monkeypatch.setattr(cli_module, "execute_capability", fake_execute)

    result = runner.invoke(
        app,
        [
            "run",
            "shadow-creds",
            "--interactive",
            "--force",
            "-d",
            "corp.lab",
            "--dc-ip",
            "10.0.0.10",
        ],
        # --sam prompt (short value), final confirmation (yes)
        input="alice\ny\n",
    )
    assert result.exit_code == 0, result.output
    assert captured["capability"] == "shadow-creds"
    assert captured["force"] is True


def test_interactive_run_yes_force_sets_flag_and_merges_params(monkeypatch) -> None:
    # Destructive cap without --force flag: user types YES at the force
    # prompt, confirming with yes at the end. execute_capability sees
    # force=True and any -P params captured during the interactive session.
    import adaf_attack.cli as cli_module

    captured: dict[str, object] = {}

    def fake_execute(capability: str, target, **kwargs):
        captured["capability"] = capability
        captured["force"] = kwargs.get("force")
        # -P style params land in **kwargs by their key.
        captured["template"] = kwargs.get("template")
        return {"session_path": "/tmp/s", "session_id": "s"}

    monkeypatch.setattr(cli_module, "execute_capability", fake_execute)

    result = runner.invoke(
        app,
        [
            "run",
            "template-mod",
            "--interactive",
            "-d",
            "corp.lab",
            "--dc-ip",
            "10.0.0.10",
        ],
        # template-mod requires -P template=<name> and --force. Order of
        # prompts: template (-P), then --force, then confirm.
        input="User\nYES\ny\n",
    )
    assert result.exit_code == 0, result.output
    assert captured["force"] is True
    assert captured["template"] == "User"
