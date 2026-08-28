from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_install_and_documentation_contracts() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_install_contracts.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_workflow_needs_reference_local_jobs() -> None:
    for workflow_path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        jobs = workflow.get("jobs", {})
        job_names = set(jobs)
        for job_name, job in jobs.items():
            raw_needs = job.get("needs", []) if isinstance(job, dict) else []
            needs = [raw_needs] if isinstance(raw_needs, str) else raw_needs
            assert isinstance(needs, list), f"{workflow_path.name}:{job_name} has invalid needs"
            assert set(needs) <= job_names, (
                f"{workflow_path.name}:{job_name} references caller-only or unknown jobs: "
                f"{sorted(set(needs) - job_names)}"
            )


def test_windows_installer_is_powershell_51_compatible_and_lifecycle_aware() -> None:
    script = (ROOT / "scripts" / "Install-AdafAttack.ps1").read_text(encoding="utf-8")
    assert "?." not in script, "PowerShell 7-only null-conditional syntax is not supported"
    for token in (
        "PythonVersion",
        "3.11",
        "Package",
        "Uninstall",
        "RemoveWorkspace",
        "install.json",
        "previous_workspace",
        "path_added",
        "install_complete",
        "Existing $venv uses",
        "Refusing to modify unowned virtual environment",
    ):
        assert token in script, f"Windows installer is missing lifecycle contract token: {token}"


def test_windows_installer_workflow_uses_static_shells() -> None:
    reusable = ROOT / ".github" / "workflows" / "_windows-installer.yml"
    text = reusable.read_text(encoding="utf-8") if reusable.exists() else ""
    text += "\n" + (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "shell: ${{ matrix." not in text
    assert "shell: powershell" in text
    assert "shell: pwsh" in text
    assert text.count(r"scripts\Test-WindowsInstaller.ps1") == 2


def test_kali_installer_keeps_non_kali_guard_and_supports_artifacts() -> None:
    script = (ROOT / "scripts" / "install-kali.sh").read_text(encoding="utf-8")
    for token in (
        '!= "kali"',
        "--package",
        "--uninstall",
        "--remove-workspace",
        "pip check",
        "ADAF_ATTACK_INSTALLER_V1",
        "Refusing to remove unowned",
        "not selected interpreter",
    ):
        assert token in script, f"Kali installer is missing lifecycle contract token: {token}"


def test_artifact_matrix_is_focused() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job = workflow["jobs"]["artifact-smoke"]
    if isinstance(job, dict) and job.get("uses", "").startswith("./"):
        reusable_path = ROOT / job["uses"].removeprefix("./")
        reusable = yaml.safe_load(reusable_path.read_text())
        job = next(iter(reusable["jobs"].values()))
    matrix = job["strategy"]["matrix"]["include"]
    assert 4 <= len(matrix) <= 6, (
        "artifact smoke should stay focused, not duplicate the test matrix"
    )


def test_artifact_smoke_runs_exact_guided_first_success_contract() -> None:
    script = (ROOT / "scripts" / "smoke_distribution.py").read_text(encoding="utf-8")
    for token in (
        '"ready"',
        '"readiness"',
        '"quickstart"',
        '"guide"',
        '"--workspace"',
        '"--session"',
        '"suggested_command"',
    ):
        assert token in script, f"artifact smoke is missing first-ten contract token: {token}"
