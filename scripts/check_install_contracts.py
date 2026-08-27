#!/usr/bin/env python3
"""Actionable contracts for installation workflows and onboarding documentation."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path.relative_to(ROOT)}: expected a YAML mapping")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _check_action_pins() -> None:
    for workflow_path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = _load_yaml(workflow_path)
        for job_name, job in workflow.get("jobs", {}).items():
            for step in job.get("steps", []):
                uses = step.get("uses")
                if uses:
                    _require(
                        re.fullmatch(r"[^@]+@[0-9a-f]{40}", uses) is not None,
                        f"{workflow_path.name}:{job_name}: action is not pinned by full SHA: {uses}",
                    )


def _check_workflow_dependencies() -> None:
    """Ensure every job-level ``needs`` reference is local to its workflow.

    Reusable workflows run in their own job namespace. A called workflow must
    not refer to caller-only jobs such as ``package`` or ``scripts``; those
    dependencies belong on the caller's ``uses`` job instead.
    """
    for workflow_path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = _load_yaml(workflow_path)
        jobs = workflow.get("jobs") or {}
        job_names = set(jobs)
        for job_name, job in jobs.items():
            raw_needs = job.get("needs", []) if isinstance(job, dict) else []
            if isinstance(raw_needs, str):
                needs = [raw_needs]
            elif isinstance(raw_needs, list):
                needs = raw_needs
            else:
                _require(
                    False,
                    f"{workflow_path.name}:{job_name}: needs must be a string or list",
                )
                continue
            unknown = sorted(str(item) for item in needs if str(item) not in job_names)
            _require(
                not unknown,
                f"{workflow_path.name}:{job_name}: needs unknown local jobs {unknown}",
            )


def _resolve_job(jobs: dict[str, Any], name: str) -> dict[str, Any]:
    """Return the effective job definition, following one `uses:` hop if needed."""
    import yaml as _yaml
    job = jobs[name]
    if isinstance(job, dict) and job.get("uses"):
        uses = str(job["uses"])
        if uses.startswith("./"):
            called = ROOT / uses.removeprefix("./")
            called_wf = _yaml.safe_load(called.read_text(encoding="utf-8"))
            called_jobs = called_wf.get("jobs") or {}
            # Reusable file typically has one job; return the first non-called job.
            for _called_name, called_job in called_jobs.items():
                return called_job
    return job


def _check_ci() -> None:
    path = ROOT / ".github" / "workflows" / "ci.yml"
    workflow = _load_yaml(path)
    jobs = workflow["jobs"]
    required = {
        "lint",
        "typecheck",
        "tests",
        "security",
        "codeql",
        "scripts",
        "workflow-contract",
        "package",
        "artifact-smoke",
        "kali-installer",
        "operator-workflow",
        "release-readiness",
        "windows-installer",
        "private-index-smoke",
        "ci-gate",
    }
    _require(
        required <= jobs.keys(), f"ci.yml missing required jobs: {sorted(required - jobs.keys())}"
    )
    _require(
        workflow["concurrency"]["cancel-in-progress"] is True,
        "ci.yml must cancel superseded runs",
    )
    gate_needs = set(jobs["ci-gate"]["needs"])
    _require(
        gate_needs == required - {"ci-gate"},
        f"ci-gate needs mismatch: expected {sorted(required - {'ci-gate'})}, got {sorted(gate_needs)}",
    )
    includes = _resolve_job(jobs, "artifact-smoke")["strategy"]["matrix"]["include"]
    systems = {entry["os"] for entry in includes}
    _require(
        {"ubuntu-24.04", "windows-2022", "macos-14"} <= systems,
        f"artifact-smoke must cover Ubuntu, Windows, and macOS; got {sorted(systems)}",
    )
    kinds = {entry["artifact"] for entry in includes}
    _require(kinds == {"wheel", "sdist"}, f"artifact-smoke must cover wheel and sdist; got {kinds}")
    kali_image = _resolve_job(jobs, "kali-installer")["container"]["image"]
    _require(
        re.fullmatch(r"kalilinux/kali-rolling@sha256:[0-9a-f]{64}", kali_image) is not None,
        f"kali-installer must pin the container manifest digest, got {kali_image}",
    )
    _require(
        set(jobs["tests"]["strategy"]["matrix"]["os"])
        == {"ubuntu-24.04", "windows-2022", "macos-14"},
        "source tests must cover Ubuntu, Windows, and macOS",
    )
    _require(
        set(jobs["tests"]["strategy"]["matrix"]["python-version"])
        == {"3.11", "3.12", "3.13", "3.14"},
        "source tests must cover Python 3.11, 3.12, 3.13, and 3.14",
    )
    ci_text = path.read_text(encoding="utf-8")
    # Also pull in reusable workflows that ci.yml delegates to.
    aggregated_text = ci_text
    for job in jobs.values():
        if isinstance(job, dict) and isinstance(job.get("uses"), str) and job["uses"].startswith("./"):
            called = ROOT / job["uses"].removeprefix("./")
            if called.is_file():
                aggregated_text += "\n" + called.read_text(encoding="utf-8")
    _require(
        "0.10.0" not in ci_text, "ci.yml hardcodes the project version; derive it from metadata"
    )
    _require(
        "scripts/smoke_distribution.py" in aggregated_text,
        "ci workflows must use the shared clean-distribution smoke script",
    )
    for job_name, job in jobs.items():
        for step in job.get("steps", []):
            shell = step.get("shell", "")
            _require(
                not (isinstance(shell, str) and "matrix." in shell),
                f"ci.yml:{job_name}:{step.get('name', '<unnamed>')}: "
                f"matrix expressions are unsupported in shell: {shell}",
            )
    windows_steps = _resolve_job(jobs, "windows-installer")["steps"]
    lifecycle_shells = {
        step.get("shell")
        for step in windows_steps
        if "scripts\\Test-WindowsInstaller.ps1" in step.get("run", "")
    }
    _require(
        {"powershell", "pwsh"} <= lifecycle_shells,
        "windows-installer must invoke Test-WindowsInstaller.ps1 with static "
        "powershell and pwsh shells",
    )
    _require(
        (ROOT / "scripts" / "Test-WindowsInstaller.ps1").is_file(),
        "missing shared Windows installer lifecycle helper",
    )

    release_contracts = {
        "tests/test_release_contracts.py": (
            "test_every_capability_is_reachable",
            "test_destructive_capabilities_declare_rollback_or_are_exempt",
        ),
        "tests/test_rollback_matrix.py": (
            "test_execute_cleanup_reverts_ldap_kind",
            "test_matrix_covers_exactly_the_destructive_capabilities_with_rollback",
        ),
        "tests/test_docs_commands.py": (
            "test_every_documented_command_is_real",
            "test_every_documented_capability_is_real",
        ),
        "tests/test_install_contracts.py": ("test_install_and_documentation_contracts",),
        "tests/test_doctor_profiles.py": (
            "test_offline_profile_is_local_and_has_scoped_contract",
            "test_support_bundle_redacts_sensitive_values",
        ),
        "tests/test_actionable_error_contract.py": (
            "test_catalog_entries_have_complete_recovery_contracts",
            "test_common_runner_failures_map_to_actionable_codes",
        ),
    }
    for relative, names in release_contracts.items():
        source = (ROOT / relative).read_text(encoding="utf-8")
        for name in names:
            _require(name in source, f"{relative}: missing required contract test {name}")

    codeql = _load_yaml(ROOT / ".github" / "workflows" / "codeql.yml")
    analyze = next(
        step
        for step in codeql["jobs"]["analyze"]["steps"]
        if "codeql-action/analyze@" in step.get("uses", "")
    )
    _require(analyze["with"]["upload"] is False, "CodeQL upload must remain disabled for this repo")


def _check_published_workflow() -> None:
    path = ROOT / ".github" / "workflows" / "published-artifact-smoke.yml"
    _require(path.is_file(), "missing scheduled/manual published-artifact smoke workflow")
    text = path.read_text(encoding="utf-8")
    _require(re.search(r"(?m)^\s+schedule:", text) is not None, f"{path.name}: missing schedule")
    _require(
        re.search(r"(?m)^\s+workflow_dispatch:", text) is not None,
        f"{path.name}: missing workflow_dispatch",
    )
    _require("gh release download" in text, f"{path.name}: must download GitHub release assets")
    _require(
        "scripts/smoke_distribution.py" in text,
        f"{path.name}: must run the same distribution smoke contract as CI",
    )
    _require(
        "release-manifest.json" in text,
        f"{path.name}: must validate the published release manifest",
    )


def _markdown_files() -> list[Path]:
    return [
        ROOT / "README.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "CHANGELOG.md",
        *sorted((ROOT / "docs").glob("*.md")),
    ]


def _check_markdown_links() -> None:
    link_pattern = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
    failures: list[str] = []
    for doc in _markdown_files():
        text = doc.read_text(encoding="utf-8")
        for raw_target in link_pattern.findall(text):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            if target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            file_target = target.split("#", 1)[0]
            if not file_target:
                continue
            resolved = (doc.parent / file_target).resolve()
            if not resolved.exists():
                failures.append(f"{doc.relative_to(ROOT)} -> {target}")
    _require(not failures, "broken local Markdown links:\n  - " + "\n  - ".join(failures))


def _check_docs() -> None:
    required_files = (
        "README.md",
        "CHANGELOG.md",
        "RELEASE.md",
        "docs/WINDOWS_NOVICE_USABILITY_GUIDE.md",
        "docs/LINUX_NOVICE_USABILITY_GUIDE.md",
        "docs/MACOS.md",
        "docs/TROUBLESHOOTING.md",
        "docs/KNOWN_LIMITATIONS.md",
        "docs/RELEASE_READINESS.md",
        "docs/RELEASE_EVIDENCE.md",
        "docs/USER_READINESS.md",
        "docs/FEATURE_MATRIX.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/operator_ux.yml",
        "docs/SUPPORTED_PLATFORMS.md",
        "requirements-operator.txt",
        "requirements-runtime.txt",
        "scripts/install-approved-wheel.py",
        "scripts/generate_release_manifest.py",
        "scripts/build-release-wheelhouse.py",
        "tests/test_doctor_profiles.py",
    )
    for relative in required_files:
        _require(
            (ROOT / relative).is_file(),
            f"required install/documentation surface missing: {relative}",
        )

    placeholders = (
        "Follow the recommended isolated source-install path.",
        "No clean windows journey",
        "No clean linux journey",
        "unavailable-source-archive-no-git-metadata",
    )
    for doc in _markdown_files():
        text = doc.read_text(encoding="utf-8")
        for placeholder in placeholders:
            _require(
                placeholder not in text,
                f"{doc.relative_to(ROOT)} still contains placeholder boilerplate: {placeholder!r}",
            )

    for relative in (
        "docs/WINDOWS_NOVICE_USABILITY_GUIDE.md",
        "docs/LINUX_NOVICE_USABILITY_GUIDE.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        expected = f"canonical_path: {relative}"
        _require(expected in text, f"{relative}: canonical_path must be {relative}")
        for heading in (
            "Prerequisites",
            "Download or clone",
            "Install",
            "Verify",
            "First safe offline run",
            "Stop or cancel",
            "Upgrade and downgrade",
            "Uninstall and data preservation",
            "Troubleshooting",
            "Support boundaries",
        ):
            _require(
                f"## {heading}" in text, f"{relative}: missing required section '## {heading}'"
            )

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for heading in (
        "Prerequisites",
        "Recommended release install",
        "Source checkout and development install",
        "Verify the installation",
        "First safe offline success",
        "Offline and air-gapped installation",
        "Upgrade and downgrade",
        "Uninstall",
        "Troubleshooting",
    ):
        _require(f"## {heading}" in readme, f"README.md: missing install section '## {heading}'")
    for link in (
        "docs/WINDOWS_NOVICE_USABILITY_GUIDE.md",
        "docs/LINUX_NOVICE_USABILITY_GUIDE.md",
        "docs/MACOS.md",
        "docs/TROUBLESHOOTING.md",
        "docs/KNOWN_LIMITATIONS.md",
        "docs/USER_READINESS.md",
        "docs/SUPPORTED_PLATFORMS.md",
        "docs/RELEASE_EVIDENCE.md",
        "SECURITY.md",
        "CHANGELOG.md",
    ):
        _require(link in readme, f"README.md: missing prominent link to {link}")
    for phrase in (
        "When lost",
        "adaf-attack guide",
        "adaf-attack paths",
        "support-bundle",
        "Who this is for",
        "Not on PyPI",
    ):
        _require(phrase in readme, f"README.md: missing operator spine phrase {phrase!r}")


def _check_release_evidence_template() -> None:
    """Release managers need a complete MANUAL evidence pack, not a stub."""
    path = ROOT / "docs" / "RELEASE_EVIDENCE.md"
    text = path.read_text(encoding="utf-8")
    for heading in (
        "## 1. First-ten-minutes (new operator)",
        "## 2. Published-artifact smoke",
        "## 3. Air-gapped wheelhouse",
        "## 4. Readiness summary attachment",
        "## 5. Security disclosure path check",
    ):
        _require(heading in text, f"RELEASE_EVIDENCE.md missing section {heading!r}")
    for token in (
        "guide --workspace ./quickstart",
        "doctor --profile user-readiness",
        "Signer / attestor",
    ):
        _require(token in text, f"RELEASE_EVIDENCE.md missing required token {token!r}")
    release_md = (ROOT / "RELEASE.md").read_text(encoding="utf-8")
    _require(
        "Release manager checklist" in release_md,
        "RELEASE.md must include a non-author release manager checklist",
    )
    _require(
        "docs/RELEASE_EVIDENCE.md" in release_md,
        "RELEASE.md must link the MANUAL evidence pack",
    )


def _check_windows_installer_error_codes() -> None:
    """Windows installer JSON failures must map to stable operator codes."""
    text = (ROOT / "scripts" / "Install-AdafAttack.ps1").read_text(encoding="utf-8")
    for token in (
        "function Resolve-AdafInstallerError",
        "function Fail-Adaf",
        "PYTHON_UNSUPPORTED",
        "PATH_NOT_FOUND",
        "EXECUTION_POLICY_BLOCKED",
        "PROXY_TLS_FAILED",
        "INSTALLER_OWNERSHIP",
        "INSTALLER_FAILURE",
    ):
        _require(token in text, f"Install-AdafAttack.ps1 missing {token!r}")


def _check_metadata_and_versions() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    optional = project["optional-dependencies"]
    full = " ".join(optional["full"])
    operator = " ".join(optional["operator"])
    _require(
        "dev" not in full and "dev" not in operator,
        "production full/operator extras include dev tools",
    )
    _require(
        {"tui", "kerberos", "reports"} <= set(re.findall(r"[a-z]+", operator)),
        "operator extra must include tui, kerberos, and reports",
    )

    version = project["version"]
    _require(
        project["requires-python"] == ">=3.11,<3.15",
        "pyproject requires-python must match the CI-tested Python 3.11-3.14 contract",
    )
    runtime_requirements = {}
    for line in (ROOT / "requirements-runtime.txt").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "==" in line:
            name, pinned = line.split("==", 1)
            runtime_requirements[name.lower().replace("_", "-")] = pinned
    project_requirements = {
        item.split("==", 1)[0].lower().replace("_", "-"): item.split("==", 1)[1]
        for item in project["dependencies"]
        if "==" in item
    }
    _require(
        project_requirements == runtime_requirements,
        "pyproject runtime dependencies must exactly match requirements-runtime.txt",
    )
    operator_lock = {}
    for line in (ROOT / "requirements-operator.txt").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "==" in line:
            name, pinned = line.split("==", 1)
            operator_lock[name.lower().replace("_", "-")] = pinned
    expected_operator = {}
    for extra_name in ("tui", "kerberos", "reports", "certipy"):
        for requirement in optional[extra_name]:
            if "==" in requirement:
                name, pinned = requirement.split("==", 1)
                expected_operator[name.lower().replace("_", "-")] = pinned
    _require(
        operator_lock == expected_operator,
        "requirements-operator.txt must exactly match pinned production extras",
    )
    init_text = (ROOT / "src" / "adaf_attack" / "__init__.py").read_text(encoding="utf-8")
    init_match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    _require(
        init_match is not None and init_match.group(1) == version,
        "pyproject and __version__ differ",
    )
    for relative in (
        "CHANGELOG.md",
        "RELEASE.md",
        "docs/WINDOWS_NOVICE_USABILITY_GUIDE.md",
        "docs/LINUX_NOVICE_USABILITY_GUIDE.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        _require(version in text, f"{relative}: current version {version} is not documented")

    stale_versions = []
    version_pattern = re.compile(r"adaf_attack-(\d+\.\d+\.\d+)")
    for doc in _markdown_files():
        for found in version_pattern.findall(doc.read_text(encoding="utf-8")):
            if found != version:
                stale_versions.append(f"{doc.relative_to(ROOT)}: {found}")
    _require(
        not stale_versions, "stale hardcoded release versions in docs: " + ", ".join(stale_versions)
    )

    manifest_script = (ROOT / "scripts" / "generate_release_manifest.py").read_text(
        encoding="utf-8"
    )
    _require(
        "requires_python" in manifest_script and '"wheelhouse"' in manifest_script,
        "release manifest must record the Python and wheelhouse contracts",
    )
    bootstrap = (ROOT / "scripts" / "install-approved-wheel.py").read_text(encoding="utf-8")
    _require(
        '"--manifest"' in bootstrap,
        "approved bootstrap must support release manifest verification",
    )

    requirements = (ROOT / "requirements-ci.txt").read_text(encoding="utf-8")
    ruff_match = re.search(r"(?m)^ruff==([0-9.]+)", requirements)
    _require(ruff_match is not None, "requirements-ci.txt does not pin Ruff")
    ruff_version = ruff_match.group(1)
    precommit = _load_yaml(ROOT / ".pre-commit-config.yaml")
    ruff_revision = next(
        repo["rev"] for repo in precommit["repos"] if "ruff-pre-commit" in repo["repo"]
    )
    _require(
        ruff_revision == f"v{ruff_version}",
        f".pre-commit-config.yaml Ruff {ruff_revision} differs from requirements-ci {ruff_version}",
    )
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    _require(
        f"ruff=={ruff_version}" in contributing,
        f"CONTRIBUTING.md must name the locked Ruff version {ruff_version}",
    )




def _check_changelog_version() -> None:
    """CHANGELOG's most recent versioned heading must match pyproject version."""
    import re
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, flags=re.MULTILINE)
    _require(version_match is not None, "pyproject.toml is missing a `version` line")
    assert version_match
    version = version_match.group(1)
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.search(r"^##\s+(\d+\.\d+\.\d+)", changelog, flags=re.MULTILINE)
    _require(heading is not None, "CHANGELOG.md has no versioned `## X.Y.Z` heading")
    assert heading
    changelog_version = heading.group(1)
    _require(
        changelog_version == version,
        f"CHANGELOG top version ({changelog_version!r}) does not match pyproject "
        f"({version!r}); either bump one or move new entries under `## Unreleased`.",
    )


def _check_front_matter() -> None:
    """Novice guides must expose stable front-matter for the docs pipeline."""
    required_keys = ("guide_id", "guide_schema_version", "platform", "canonical_path")
    guides = (
        "docs/WINDOWS_NOVICE_USABILITY_GUIDE.md",
        "docs/LINUX_NOVICE_USABILITY_GUIDE.md",
    )
    for relative in guides:
        text = (ROOT / relative).read_text(encoding="utf-8")
        _require(text.startswith("---\n"), f"{relative}: missing leading `---` front-matter block")
        end = text.find("\n---\n", 4)
        _require(end != -1, f"{relative}: front-matter block is not terminated")
        block = text[4:end]
        for key in required_keys:
            _require(f"{key}:" in block, f"{relative}: front-matter missing `{key}:`")
        _require(
            f"canonical_path: {relative}" in block,
            f"{relative}: front-matter canonical_path must match the file path",
        )


def _check_precommit_pins() -> None:
    """Delegate to scripts/check_precommit_pins.py for the actual comparison."""
    import subprocess
    import sys as _sys
    result = subprocess.run(
        [_sys.executable, "scripts/check_precommit_pins.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    _require(result.returncode == 0, f"pre-commit / CI pin drift:\n{result.stderr.strip()}")


def main() -> int:
    checks = (
        _check_action_pins,
        _check_workflow_dependencies,
        _check_ci,
        _check_published_workflow,
        _check_markdown_links,
        _check_docs,
        _check_release_evidence_template,
        _check_windows_installer_error_codes,
        _check_metadata_and_versions,
        _check_changelog_version,
        _check_front_matter,
        _check_precommit_pins,
    )
    failures: list[str] = []
    for check in checks:
        try:
            check()
        except AssertionError as exc:
            failures.append(str(exc))
    if failures:
        print("Install/documentation contract failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("Install and documentation contracts passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
