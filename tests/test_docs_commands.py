"""Documentation-command contract (Release Readiness §2 / §5).

Keeps the docs from rotting against the CLI:

* Every ``adaf-attack <command>`` shown in a fenced code block of README.md or
  docs/*.md resolves to a real registered command.
* Every capability referenced via ``run`` / ``plan`` / ``capability-help``
  resolves to a registered capability id.
* A safe, offline subset of the documented commands actually executes (exit 0),
  so the quickstart a new user copy-pastes really works.

A renamed or removed command/capability that the docs still mention fails here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

import adaf_attack.capabilities  # noqa: F401  # register every capability
from adaf_attack.cli import app
from adaf_attack.core.registry import capability_registry

runner = CliRunner()

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOC_FILES = [_REPO_ROOT / "README.md", *sorted((_REPO_ROOT / "docs").glob("*.md"))]

_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
# Match an adaf-attack invocation and capture the first command token plus the
# rest of that same line. Horizontal-whitespace separators only, so `rest` never
# runs past the newline into the next command. Tolerates venv prefixes and the
# module form (adaf_attack.cli).
_INVOKE = re.compile(r"(?:adaf-attack|adaf_attack\.cli)[ \t]+([a-z][a-z0-9-]+)([^\n]*)")

# Commands that are safe to actually run: no network, no target, no writes
# outside a temp dir. Kept small and deterministic on purpose.
_OFFLINE_RUNNABLE = {
    "doctor": ["doctor"],
    "list-capabilities": ["list-capabilities"],
    "paths": ["paths"],
    "workflow-profiles": ["workflow-profiles"],
    "errors": ["errors"],
}


def _registered_commands() -> set[str]:
    names: set[str] = set()
    for command in app.registered_commands:
        if command.name:
            names.add(command.name)
        elif command.callback is not None:
            names.add(command.callback.__name__.replace("_", "-"))
    for group in app.registered_groups:
        if group.name:
            names.add(group.name)
    return names


def _documented_invocations() -> list[tuple[str, str, str]]:
    """Return (command, rest_of_line, source_doc) for each adaf-attack call in docs."""
    found: list[tuple[str, str, str]] = []
    for doc in _DOC_FILES:
        if not doc.is_file():
            continue
        text = doc.read_text(encoding="utf-8")
        for block in _FENCE.findall(text):
            for command, rest in _INVOKE.findall(block):
                found.append((command, rest.strip(), doc.name))
    return found


def test_documentation_exists_and_mentions_the_cli() -> None:
    invocations = _documented_invocations()
    assert invocations, "no adaf-attack commands found in README/docs code blocks"


def test_every_documented_command_is_real() -> None:
    commands = _registered_commands()
    unknown = sorted(
        {f"{cmd} ({doc})" for cmd, _rest, doc in _documented_invocations() if cmd not in commands}
    )
    assert not unknown, f"docs reference commands that do not exist: {unknown}"


def test_every_documented_capability_is_real() -> None:
    cap_ids = {cap.id for cap in capability_registry.list()}
    offenders: list[str] = []
    for command, rest, doc in _documented_invocations():
        if command not in {"run", "plan", "capability-help"}:
            continue
        tokens = rest.split()
        if not tokens or tokens[0].startswith(("-", "<")):
            continue  # no id, a flag, or a <placeholder>
        cap = tokens[0]
        if cap not in cap_ids:
            offenders.append(f"{command} {cap} ({doc})")
    assert not offenders, f"docs reference capabilities that do not exist: {sorted(offenders)}"


def test_documented_offline_commands_execute() -> None:
    documented = {cmd for cmd, _rest, _doc in _documented_invocations()}
    ran_any = False
    for command, argv in _OFFLINE_RUNNABLE.items():
        if command not in documented:
            continue
        ran_any = True
        result = runner.invoke(app, ["--format", "json", *argv])
        assert result.exit_code == 0, f"documented `adaf-attack {command}` failed: {result.output}"
        assert json.loads(result.output).get("ok") is True, f"`{command}` returned ok!=true"
    assert ran_any, "expected at least one documented offline command to be runnable"
