"""Behavioral tests for critical/high production and UX remediations."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from adaf_attack.cli import app
from adaf_attack.core.capability_help_data import capability_option_spec
from adaf_attack.core.cli_argv import hoist_global_options
from adaf_attack.core.execution_policy import safety_for_operation
from adaf_attack.core.registry import capability_registry, load_builtin_capabilities
from adaf_attack.core.ux import build_ready_command
from adaf_attack.tui.app import ADAFAttackApp

runner = CliRunner()


def test_hoist_format_after_subcommand() -> None:
    assert hoist_global_options(["run", "ldap-enum", "--format", "json"]) == [
        "--format",
        "json",
        "run",
        "ldap-enum",
    ]


def test_cli_accepts_format_after_run() -> None:
    result = runner.invoke(
        app, ["run", "nosuchcap", "--domain", "x", "--dc-ip", "1.1.1.1", "--format", "json"]
    )
    assert result.exit_code != 0
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "UNKNOWN_CAPABILITY"


def test_offline_run_does_not_require_domain() -> None:
    result = runner.invoke(app, ["--format", "json", "run", "attack-paths", "--dry-run"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["capability"]["id"] == "attack-paths"


def test_hidden_commands_are_listed_in_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("home", "help-me", "start-here", "start-demo", "tui"):
        assert name in result.output


def test_unknown_command_does_not_suggest_command_surface() -> None:
    result = runner.invoke(app, ["nosuchcommand"])
    assert result.exit_code != 0
    text = f"{result.output}{result.stderr}{result.exception}"
    assert "Did you mean: command" not in text
    assert "adaf-attack guide" in text


def test_list_capabilities_json_is_compact_by_default() -> None:
    result = runner.invoke(app, ["--format", "json", "list-capabilities"])
    payload = json.loads(result.output)
    assert "operator_contract" not in payload["capabilities"][0]
    assert "id" in payload["capabilities"][0]


def test_campaign_analysis_is_registered() -> None:
    load_builtin_capabilities()
    assert capability_registry.get("campaign-analysis") is not None


def test_bloodhound_import_spec_is_offline_artifact() -> None:
    spec = capability_option_spec("bloodhound-import", False)
    assert "--artifact" in spec.required
    assert "--domain" not in spec.required


def test_rbcd_enum_does_not_require_force_in_help() -> None:
    spec = capability_option_spec("rbcd", False)
    assert "--force" not in spec.required
    assert "--set-on" in spec.optional


def test_copy_ready_ldap_enum_includes_domain() -> None:
    command = build_ready_command("ldap-enum")
    assert "--domain" in command
    assert "--dc-ip" in command


def test_computer_takeover_write_is_mutating() -> None:
    load_builtin_capabilities()
    cap = capability_registry.get("computer-takeover")
    assert cap is not None
    observe = safety_for_operation(cap, {})
    write = safety_for_operation(
        cap, {"write_target": "WS01$", "attribute": "dNSHostName", "value": "x"}
    )
    assert observe.requires_force is False
    assert write.requires_force is True


def test_tui_quit_is_not_bare_q() -> None:
    keys = [binding.key for binding in ADAFAttackApp.BINDINGS if hasattr(binding, "key")]
    assert "q" not in keys
    assert any(getattr(binding, "key", "") == "ctrl+q" for binding in ADAFAttackApp.BINDINGS)


def test_load_impacket_example_prefers_injected_module(monkeypatch: Any) -> None:
    import sys
    from types import ModuleType

    from adaf_attack.core.impacket_helper import ImpacketMissingError
    from adaf_attack.core.impacket_scripts import load_impacket_example

    module = ModuleType("impacket.examples.getST")

    class GetST:
        marker = "injected"

    module.GETST = GetST  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "impacket.examples.getST", module)
    assert load_impacket_example("getST.py", "GETST") is GetST
    with pytest.raises(ImpacketMissingError, match="getST.py:MISSING"):
        load_impacket_example("getST.py", "MISSING")


class _LockoutConn:
    def __init__(self, by_attr: dict[str, list[Any]]) -> None:
        self.by_attr = by_attr
        self.entries: list[Any] = []

    def search(self, base: str, search_filter: str, **kwargs: Any) -> None:
        del base, search_filter
        attrs = list(kwargs.get("attributes") or [])
        for key, entries in self.by_attr.items():
            if key in attrs or key in str(attrs):
                self.entries = entries
                return
        self.entries = self.by_attr.get("default", [])


def test_lockout_policy_tolerates_missing_attributes() -> None:
    from adaf_attack.core.lockout import read_domain_lockout_policy

    class Conn:
        def __init__(self) -> None:
            self.entries: list[Any] = [SimpleNamespace()]

        def search(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs

    policy = read_domain_lockout_policy(Conn(), "DC=corp,DC=test")
    assert policy["lockout_threshold"] == 0
    assert policy["observation_window_seconds"] == 0


def test_lockout_pdc_pso_and_effective_threshold() -> None:
    from adaf_attack.core.lockout import (
        account_lockout_state,
        domain_has_pso,
        effective_lockout_threshold,
        locate_pdc_emulator,
    )

    pdc = _LockoutConn(
        {
            "fSMORoleOwner": [
                SimpleNamespace(fSMORoleOwner="CN=NTDS Settings,CN=DC01,CN=Servers,DC=corp,DC=test")
            ],
            "dNSHostName": [SimpleNamespace(dNSHostName="dc01.corp.test")],
        }
    )
    assert locate_pdc_emulator(pdc, "DC=corp,DC=test") == "dc01.corp.test"
    with pytest.raises(RuntimeError, match="PDC emulator"):
        locate_pdc_emulator(_LockoutConn({}), "DC=corp,DC=test")

    pso_conn = _LockoutConn({"cn": [SimpleNamespace(cn="PSO1")]})
    assert domain_has_pso(pso_conn, "DC=corp,DC=test") is True
    assert domain_has_pso(_LockoutConn({}), "DC=corp,DC=test") is False

    missing = _LockoutConn({})
    with pytest.raises(RuntimeError, match="Account not found"):
        account_lockout_state(missing, "DC=corp,DC=test", "alice", require_pso=False)

    user = _LockoutConn(
        {
            "badPwdCount": [
                SimpleNamespace(badPwdCount=2, badPasswordTime=0, **{"msDS-ResultantPSO": None})
            ],
        }
    )
    bad, ts, pso = account_lockout_state(user, "DC=corp,DC=test", "alice", require_pso=False)
    assert bad == 2 and ts is None and pso is None

    require = _LockoutConn(
        {
            "badPwdCount": [SimpleNamespace(badPwdCount=0, badPasswordTime=0)],
        }
    )
    with pytest.raises(RuntimeError, match="msDS-ResultantPSO"):
        account_lockout_state(require, "DC=corp,DC=test", "alice", require_pso=True)

    pso_user = _LockoutConn(
        {
            "badPwdCount": [
                SimpleNamespace(
                    badPwdCount=1,
                    badPasswordTime=0,
                    **{"msDS-ResultantPSO": "CN=PSO,DC=corp,DC=test"},
                )
            ],
            "msDS-LockoutThreshold": [SimpleNamespace(**{"msDS-LockoutThreshold": 3})],
        }
    )
    bad, _ts, pso_thr = account_lockout_state(
        pso_user, "DC=corp,DC=test", "alice", require_pso=True
    )
    assert bad == 1 and pso_thr == 3
    assert effective_lockout_threshold(5, None) == 5
    assert effective_lockout_threshold(5, 3) == 3
    assert effective_lockout_threshold(0, 4) == 4
    assert effective_lockout_threshold(5, 0) == 0


def test_verify_install_artifact_script(tmp_path: Path) -> None:
    import hashlib
    import subprocess
    import sys

    wheel = tmp_path / "adaf_attack-0.10.1-py3-none-any.whl"
    wheel.write_bytes(b"demo-wheel")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    (tmp_path / "SHA256SUMS").write_text(f"{digest}  {wheel.name}\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "scripts/verify_install_artifact.py", "--artifact", str(wheel)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
