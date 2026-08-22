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
