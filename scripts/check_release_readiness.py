#!/usr/bin/env python3
"""Executable new-user release-readiness standard (docs/RELEASE_READINESS.md).

A release is *not* ready merely because the coverage gate passed. Coverage proves
lines executed under test; it does not prove that a stranger can install the
tool, diagnose their own problems, exercise every feature, recover from a bad
run, or find the answer in the docs. This script turns that standard into a
build-breaking gate with two independent layers:

1. **Behavioral** - drive the *installed* ``adaf-attack`` artifact the way a new
   user would (console entry point, no repo checkout assumed) and assert each of
   the five pillars actually holds:

       1. Proven installation      - the artifact installs clean and its entry
                                     points run.
       2. Guided troubleshooting   - ``doctor`` names every gap with a
                                     copy-pasteable fix; degraded optional
                                     tooling warns, it does not fail.
       3. Full-feature validation  - the advertised capability surface is
                                     reachable and the documented offline
                                     commands really run.
       4. Tested recovery paths    - destructive actions refuse without
                                     ``--force``.
       5. Documentation            - the install/troubleshoot/use/undo docs
                                     exist and every command they show is real.

2. **Binding** - parse ``.github/workflows/ci.yml`` and assert each pillar is
   still wired to a live CI job/step and its enforcing contract test. This is the
   spine that keeps the standard from quietly rotting back into a coverage
   number: delete the enforcement and this gate goes red.

Run standalone against an installed package::

    python scripts/check_release_readiness.py --repo-root .

Exit code is 0 only when every check in every pillar passes. Set
``ADAF_CLI`` to override how the CLI is invoked (default: the ``adaf-attack``
console script, falling back to ``python -m adaf_attack.cli``).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# CLI invocation - talk to the installed artifact, like a new user does.
# --------------------------------------------------------------------------- #


def _cli_argv() -> list[str]:
    """Resolve how to invoke the tool: console script, else module form."""
    override = os.environ.get("ADAF_CLI")
    if override:
        argv = shlex.split(override)
        if not argv:
            raise ValueError("ADAF_CLI must contain an executable")
        return argv
    console = shutil.which("adaf-attack")
    if console:
        return [console]
    return [sys.executable, "-m", "adaf_attack.cli"]


_ARGV = _cli_argv()


@dataclass
class Cmd:
    """Result of a CLI invocation."""

    code: int
    out: str
    err: str

    def json(self) -> Any:
        return json.loads(self.out)


# Deterministic output regardless of runner: no ANSI colour, no width-based
# wrapping. Rich otherwise colourises error text on CI (splitting tokens like
# ``--force`` with escape codes) and wraps at the terminal width.
_CLI_ENV = {**os.environ, "NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "200"}
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def run_cli(*args: str, env: dict[str, str] | None = None) -> Cmd:
    try:
        proc = subprocess.run(
            [*_ARGV, *args],
            capture_output=True,
            text=True,
            env=env if env is not None else _CLI_ENV,
            timeout=120,
        )
    except FileNotFoundError as exc:
        return Cmd(127, "", f"CLI executable was not found: {exc}")
    except subprocess.TimeoutExpired as exc:
        return Cmd(124, exc.stdout or "", f"CLI timed out after 120 seconds: {exc}")
    return Cmd(proc.returncode, proc.stdout, proc.stderr)


# --------------------------------------------------------------------------- #
# Check plumbing.
# --------------------------------------------------------------------------- #


@dataclass
class Pillar:
    key: str
    title: str
    checks: list[tuple[str, Callable[[], None]]] = field(default_factory=list)

    def check(self, name: str) -> Callable[[Callable[[], None]], Callable[[], None]]:
        def register(fn: Callable[[], None]) -> Callable[[], None]:
            self.checks.append((name, fn))
            return fn

        return register


REPO_ROOT = Path(__file__).resolve().parents[1]


def _require(condition: object, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# --------------------------------------------------------------------------- #
# Pillar 1 - Proven installation.
# --------------------------------------------------------------------------- #

installation = Pillar("installation", "Proven installation")


@installation.check("pip check reports a consistent environment")
def _pip_check() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    _require(proc.returncode == 0, f"pip check failed: {proc.stdout}{proc.stderr}")


@installation.check("entry points run (--version, list-capabilities, paths)")
def _entry_points() -> None:
    version = run_cli("--format", "json", "--version")
    _require(version.code == 0, f"--version failed: {version.err or version.out}")
    _require(version.json().get("ok") is True, "--version json not ok")
    _require(isinstance(version.json().get("version"), str), "version is not a string")

    caps = run_cli("--format", "json", "list-capabilities")
    _require(caps.code == 0, f"list-capabilities failed: {caps.err or caps.out}")

    paths = run_cli("--format", "json", "paths")
    _require(paths.code == 0, f"paths failed: {paths.err or paths.out}")
    _require(
        {"platform", "data", "config", "workspace"} <= paths.json().keys(),
        "paths json is missing workspace locations",
    )


# --------------------------------------------------------------------------- #
# Pillar 2 - Guided troubleshooting.
# --------------------------------------------------------------------------- #

troubleshooting = Pillar("troubleshooting", "Guided troubleshooting")


@troubleshooting.check("doctor JSON carries a stable, actionable contract")
def _doctor_contract() -> None:
    result = run_cli("--format", "json", "doctor", "--explain")
    _require(result.code == 0, f"doctor exited {result.code}: {result.err or result.out}")
    payload = result.json()
    _require(
        {"ok", "version", "checks", "next_step"} <= payload.keys(),
        "doctor payload is missing top-level contract keys",
    )
    _require(isinstance(payload["checks"], list), "doctor checks is not a list")
    check_ids: set[str] = set()
    for check in payload["checks"]:
        _require(check["id"] not in check_ids, f"doctor check id is duplicated: {check['id']}")
        check_ids.add(check["id"])
        _require(
            check["status"] in {"ok", "warning", "error"},
            f"doctor check has unknown status: {check}",
        )
        _require(
            {"id", "status", "value", "remediation"} <= check.keys(),
            f"doctor check missing contract keys: {check}",
        )
        # Every non-OK check must hand the user a copy-pasteable fix - they must
        # never have to read source to learn what to install.
        if check["status"] != "ok":
            remediation = check["remediation"]
            _require(
                isinstance(remediation, str) and remediation.strip(),
                f"doctor check '{check['id']}' is {check['status']} without remediation",
            )


@troubleshooting.check("error catalog exposes actionable recovery")
def _error_catalog_contract() -> None:
    result = run_cli("--format", "json", "errors")
    _require(result.code == 0, f"errors failed: {result.err or result.out}")
    payload = result.json()
    entries = payload.get("errors")
    _require(isinstance(entries, list) and entries, "error catalog is empty")
    for entry in entries:
        _require(
            {"code", "message", "remediation", "suggested_command"} <= entry.keys(),
            f"error catalog entry is incomplete: {entry}",
        )
        _require(entry["code"].isupper(), f"error code is not uppercase: {entry['code']}")
        _require(entry["message"].strip(), f"error has no message: {entry['code']}")
        _require(entry["remediation"].strip(), f"error has no remediation: {entry['code']}")


@troubleshooting.check("degraded optional tooling warns, it does not fail")
def _doctor_optional_is_warning() -> None:
    # With only the base wheel installed, the external CLI tools (ntlmrelayx,
    # certipy) are absent. doctor must still exit ok: missing *optional* tooling
    # is a warning with a fix, never a blocking error.
    result = run_cli("--format", "json", "doctor")
    payload = result.json()
    _require(payload["ok"] is True, "doctor reported not-ok on a base install")
    _require(result.code == 0, f"doctor exited non-zero on a base install: {result.code}")
    errors = [c for c in payload["checks"] if c["status"] == "error"]
    _require(not errors, f"unexpected blocking doctor errors on a base install: {errors}")


@troubleshooting.check("human doctor renders remediation verbatim (markup intact)")
def _doctor_human_verbatim() -> None:
    payload = run_cli("--format", "json", "doctor", "--explain").json()
    warnings = [c for c in payload["checks"] if c["status"] != "ok"]
    if not warnings:
        return  # nothing to render on this host; contract is vacuously satisfied
    human = run_cli("doctor", "--explain")
    _require(human.code == 0, f"human doctor failed: {human.err or human.out}")
    # The pip extras token must survive Rich markup, e.g. adaf-attack[kerberos].
    _require(
        "adaf-attack[" in human.out or "pip install" in human.out,
        "human doctor --explain swallowed the remediation text",
    )


# --------------------------------------------------------------------------- #
# Pillar 3 - Full-feature validation.
# --------------------------------------------------------------------------- #

features = Pillar("features", "Full-feature validation")


@features.check("every advertised capability is reachable via capability-help")
def _capabilities_reachable() -> None:
    caps = run_cli("--format", "json", "list-capabilities").json()
    _require(caps["count"] == len(caps["capabilities"]), "list-capabilities count mismatch")
    _require(caps["capabilities"], "no capabilities advertised")
    _require(
        {"id", "category", "summary", "destructive"} <= caps["capabilities"][0].keys(),
        "capability metadata is missing contract keys",
    )
    failures: list[str] = []
    for capability in caps["capabilities"]:
        cap_id = capability["id"]
        helped = run_cli("--format", "json", "capability-help", cap_id)
        if helped.code != 0:
            failures.append(f"{cap_id}: exit {helped.code}: {helped.err.strip()}")
            continue
        help_payload = helped.json()
        if (
            help_payload.get("ok") is not True
            or help_payload.get("capability", {}).get("id") != cap_id
        ):
            failures.append(f"{cap_id}: invalid capability-help payload")
    _require(not failures, "capability-help failures:\n  - " + "\n  - ".join(failures))


@features.check("documented offline commands actually execute")
def _documented_offline_runs() -> None:
    # A new user copy-pastes the quickstart; the safe offline subset must work.
    for argv in (
        ["doctor"],
        ["doctor", "--profile", "user-readiness"],
        ["list-capabilities"],
        ["paths"],
        ["workflow-profiles"],
    ):
        result = run_cli("--format", "json", *argv)
        _require(result.code == 0, f"documented `{' '.join(argv)}` failed: {result.err}")
        _require(result.json().get("ok") is True, f"`{' '.join(argv)}` returned ok != true")
    with tempfile.TemporaryDirectory(prefix="adaf-readiness-demo-") as root:
        result = run_cli("--format", "json", "demo", "--workspace", root)
        _require(result.code == 0, f"packaged demo failed: {result.err or result.out}")
        _require(result.json().get("ok") is True, "packaged demo returned ok != true")
    with tempfile.TemporaryDirectory(prefix="adaf-readiness-quickstart-") as root:
        result = run_cli("--format", "json", "quickstart", "--workspace", root)
        _require(result.code == 0, f"quickstart failed: {result.err or result.out}")
        payload = result.json()
        _require(payload.get("ok") is True, "quickstart returned ok != true")
        _require(payload.get("stage") == "complete", "quickstart did not complete all stages")


@features.check("offline engagement product surfaces execute from a clean demo")
def _offline_product_surfaces() -> None:
    with tempfile.TemporaryDirectory(prefix="adaf-readiness-surfaces-") as root:
        surface_env = {
            **_CLI_ENV,
            "ADAF_ATTACK_CONFIG_DIR": str(Path(root) / "config"),
            "ADAF_ATTACK_DATA_DIR": str(Path(root) / "data"),
            "ADAF_ATTACK_WORKSPACE": str(Path(root) / "workspace"),
        }
        demo = run_cli("--format", "json", "demo", "--workspace", root)
        _require(demo.code == 0, f"demo failed: {demo.err or demo.out}")
        session = demo.json().get("session_path")
        _require(isinstance(session, str) and session, "demo did not return session_path")
        commands = (
            ["engagement", "dashboard", "--session", session],
            ["engagement", "asset", "USER@alice@CORP.LOCAL", "--session", session],
            ["engagement", "identity", "USER@alice@CORP.LOCAL", "--session", session],
            ["engagement", "tier0", "--session", session],
            ["engagement", "blast-radius", "USER@alice@CORP.LOCAL", "--session", session],
            ["engagement", "domain", "--session", session],
            ["engagement", "investigation", "--session", session],
            ["cleanup-status", "--session", session],
        )
        for command in commands:
            result = run_cli("--format", "json", *command, env=surface_env)
            _require(result.code == 0, f"`{' '.join(command)}` failed: {result.err or result.out}")
            payload = result.json()
            _require(isinstance(payload, dict), f"`{' '.join(command)}` returned non-object JSON")
            _require(
                payload.get("ok", True) is True,
                f"`{' '.join(command)}` returned ok != true",
            )
        for command in (
            ["engagement", "mission-save", "tier-0-paths"],
            ["engagement", "mission-saved"],
            ["engagement", "mission-remove", "tier-0-paths"],
        ):
            result = run_cli("--format", "json", *command, env=surface_env)
            _require(result.code == 0, f"`{' '.join(command)}` failed: {result.err or result.out}")
            _require(result.json().get("ok") is True, f"`{' '.join(command)}` returned ok != true")


# --------------------------------------------------------------------------- #
# Pillar 4 - Tested recovery paths.
# --------------------------------------------------------------------------- #

recovery = Pillar("recovery", "Tested recovery paths")


@recovery.check("destructive cleanup refuses to run without --force")
def _cleanup_requires_force() -> None:
    result = run_cli(
        "--format",
        "json",
        "cleanup",
        "--session",
        "output/does-not-exist",
        "--domain",
        "corp.example",
        "--dc-ip",
        "10.0.0.10",
    )
    _require(result.code != 0, "cleanup ran without --force (must refuse)")
    combined = strip_ansi(f"{result.out}\n{result.err}")
    _require("--force" in combined, f"cleanup refusal did not mention --force: {combined}")


# --------------------------------------------------------------------------- #
# Pillar 5 - Documentation.
# --------------------------------------------------------------------------- #

documentation = Pillar("documentation", "Documentation")

_REQUIRED_DOCS = (
    "README.md",
    "CHANGELOG.md",
    "RELEASE.md",
    "CONTRIBUTING.md",
    "docs/RELEASE_READINESS.md",
    "docs/RELEASE_EVIDENCE.md",
    "docs/KNOWN_LIMITATIONS.md",
    "docs/TROUBLESHOOTING.md",
    "docs/MACOS.md",
    "docs/KALI.md",
    "docs/WINDOWS.md",
    "docs/LINUX_NOVICE_USABILITY_GUIDE.md",
    "docs/WINDOWS_NOVICE_USABILITY_GUIDE.md",
    "docs/FEATURE_MATRIX.md",
    "docs/USER_READINESS.md",
    "docs/VENDOR_SCORECARD.md",
)

_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_INVOKE = re.compile(r"(?:adaf-attack|adaf_attack\.cli)[ \t]+([a-z][a-z0-9-]+)([^\n]*)")


@documentation.check("install / troubleshoot / use / undo docs exist")
def _docs_exist() -> None:
    missing = [d for d in _REQUIRED_DOCS if not (REPO_ROOT / d).is_file()]
    _require(not missing, f"required docs missing: {missing}")


@documentation.check("every documented command and capability is real")
def _docs_reference_real_surface() -> None:
    commands = _registered_commands()
    cap_ids = {
        c["id"] for c in run_cli("--format", "json", "list-capabilities").json()["capabilities"]
    }

    doc_files = [REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").glob("*.md"))]
    unknown_cmds: set[str] = set()
    unknown_caps: set[str] = set()
    for doc in doc_files:
        if not doc.is_file():
            continue
        for block in _FENCE.findall(doc.read_text(encoding="utf-8")):
            for command, rest in _INVOKE.findall(block):
                tokens = (command + rest).split()
                path: list[str] = []
                for token in tokens:
                    if token.startswith(("-", "<")):
                        break
                    candidate = " ".join([*path, token])
                    if candidate not in commands:
                        break
                    path.append(token)
                command_path = " ".join(path)
                if command_path not in commands:
                    unknown_cmds.add(f"{command_path or command} ({doc.name})")
                if command_path in {"run", "plan", "capability-help"}:
                    remaining = tokens[len(path) :]
                    if (
                        remaining
                        and not remaining[0].startswith(("-", "<"))
                        and remaining[0] not in cap_ids
                    ):
                        unknown_caps.add(f"{command_path} {remaining[0]} ({doc.name})")
    _require(not unknown_cmds, f"docs reference commands that do not exist: {sorted(unknown_cmds)}")
    _require(
        not unknown_caps, f"docs reference capabilities that do not exist: {sorted(unknown_caps)}"
    )


def _registered_commands() -> set[str]:
    """The authoritative set of top-level command names from the installed app.

    Imported in-process (the verifier runs under the same venv the artifact is
    installed into) rather than scraped from ``--help`` text, whose Rich layout
    varies by terminal width and colour and cannot be parsed portably.
    """
    import adaf_attack.capabilities  # noqa: F401  # register every capability
    from adaf_attack.cli import app

    names: set[str] = set()

    def visit(current: Any, prefix: tuple[str, ...] = ()) -> None:
        for command in current.registered_commands:
            name = command.name or (
                command.callback.__name__.replace("_", "-")
                if command.callback is not None
                else None
            )
            if name:
                names.add(" ".join((*prefix, name)))
        for group in current.registered_groups:
            if group.name and group.typer_instance is not None:
                path = (*prefix, group.name)
                names.add(" ".join(path))
                visit(group.typer_instance, path)

    visit(app)
    _require(names, "no commands registered on the installed app")
    return names


# --------------------------------------------------------------------------- #
# Binding layer - the standard must stay wired to live CI enforcement.
# --------------------------------------------------------------------------- #

binding = Pillar("binding", "Standard is bound to live CI enforcement")

# Each pillar -> the CI jobs, step-name fragments, and contract tests that must
# stay present. If any of these enforcement points is deleted, this gate fails,
# so the five-pillar standard can never silently degrade to a coverage number.
_PILLAR_BINDINGS: dict[str, dict[str, Any]] = {
    "Proven installation": {
        "jobs": [
            "package",
            "artifact-smoke",
            "kali-installer",
            "windows-installer",
            "release-readiness",
        ],
        "steps": ["Install and exercise the clean distribution"],
        "tests": [
            ("tests/test_install_contracts.py", ["test_install_and_documentation_contracts"])
        ],
    },
    "Guided troubleshooting": {
        "jobs": ["tests", "operator-workflow", "release-readiness"],
        "steps": ["Validate operator-facing CLI contract"],
        "tests": [
            ("tests/test_cli_contract.py", ["test_doctor_json_has_stable_remediation_contract"]),
            (
                "tests/test_actionable_error_contract.py",
                ["test_catalog_entries_have_complete_recovery_contracts"],
            ),
        ],
    },
    "Full-feature validation": {
        "jobs": ["operator-workflow", "release-readiness"],
        "steps": ["Sweep offline operator review workflow"],
        "tests": [("tests/test_release_contracts.py", ["test_every_capability_is_reachable"])],
    },
    "Tested recovery paths": {
        "jobs": ["tests", "release-readiness"],
        "steps": [],
        "tests": [
            (
                "tests/test_release_contracts.py",
                ["test_destructive_capabilities_declare_rollback_or_are_exempt"],
            ),
            (
                "tests/test_rollback_matrix.py",
                ["test_matrix_covers_exactly_the_destructive_capabilities_with_rollback"],
            ),
        ],
    },
    "Documentation": {
        "jobs": ["workflow-contract", "release-readiness"],
        "steps": [],
        "tests": [
            ("tests/test_docs_commands.py", ["test_every_documented_command_is_real"]),
        ],
    },
}


def _load_workflow() -> dict[str, Any]:
    import yaml

    text = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


@binding.check("release-readiness is a required, gated CI job")
def _job_is_gated() -> None:
    workflow = _load_workflow()
    jobs = workflow["jobs"]
    _require("release-readiness" in jobs, "release-readiness job is not defined in ci.yml")
    gate_needs = set(jobs["ci-gate"]["needs"])
    _require(
        "release-readiness" in gate_needs,
        "ci-gate does not require the release-readiness job",
    )
    # ci-gate must actually assert this lane succeeded, not merely depend on it.
    gate_src = " ".join(step.get("run", "") for step in jobs["ci-gate"]["steps"])
    _require(
        "needs.release-readiness.result" in gate_src,
        "ci-gate does not assert release-readiness succeeded",
    )


@binding.check("every pillar maps to live jobs, steps, and contract tests")
def _pillars_are_wired() -> None:
    import yaml

    workflow = _load_workflow()
    jobs = workflow["jobs"]
    all_step_names: set[str] = set()
    for job in jobs.values():
        for step in job.get("steps", []) or []:
            all_step_names.add(step.get("name", ""))
    # Also look inside any called reusable workflows (jobs with `uses:`).
    for job in jobs.values():
        uses = job.get("uses") if isinstance(job, dict) else None
        if not uses or not isinstance(uses, str) or not uses.startswith("./"):
            continue
        called = REPO_ROOT / uses.removeprefix("./")
        if not called.is_file():
            continue
        called_wf = yaml.safe_load(called.read_text(encoding="utf-8"))
        for called_job in (called_wf.get("jobs") or {}).values():
            for step in called_job.get("steps", []) or []:
                all_step_names.add(step.get("name", ""))
    problems: list[str] = []
    for pillar, spec in _PILLAR_BINDINGS.items():
        for job in spec["jobs"]:
            if job not in jobs:
                problems.append(f"{pillar}: CI job '{job}' is gone")
        for fragment in spec["steps"]:
            if not any(fragment in name for name in all_step_names):
                problems.append(f"{pillar}: CI step '{fragment}' is gone")
        for test_path, required in spec["tests"]:
            path = REPO_ROOT / test_path
            if not path.is_file():
                problems.append(f"{pillar}: contract test '{test_path}' is gone")
                continue
            src = path.read_text(encoding="utf-8")
            for name in required:
                if name not in src:
                    problems.append(f"{pillar}: contract '{test_path}::{name}' is gone")
    _require(not problems, "release-readiness enforcement drifted:\n  - " + "\n  - ".join(problems))


# --------------------------------------------------------------------------- #
# Runner.
# --------------------------------------------------------------------------- #

_PILLARS = [installation, troubleshooting, features, recovery, documentation, binding]


def main() -> int:
    global REPO_ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(REPO_ROOT),
        help="Repository root (for docs and workflow binding checks).",
    )
    parser.add_argument(
        "--skip-binding",
        action="store_true",
        help="Skip the CI-binding layer (behavioral checks only).",
    )
    args = parser.parse_args()

    REPO_ROOT = Path(args.repo_root).resolve()

    print(f"Release-readiness standard - driving: {' '.join(_ARGV)}\n")
    failures: list[str] = []
    for pillar in _PILLARS:
        if pillar is binding and args.skip_binding:
            continue
        print(f"== {pillar.title} ==")
        for name, fn in pillar.checks:
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - report, don't crash the gate
                print(f"  FAIL  {name}")
                detail = str(exc).strip() or exc.__class__.__name__
                for line in detail.splitlines():
                    print(f"        {line}")
                failures.append(f"[{pillar.title}] {name}: {detail.splitlines()[0]}")
            else:
                print(f"  PASS  {name}")
        print()

    if failures:
        print(f"RELEASE NOT READY - {len(failures)} check(s) failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("AUTOMATED READINESS PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
