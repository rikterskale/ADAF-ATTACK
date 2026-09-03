from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load_release_readiness_script() -> ModuleType:
    path = ROOT / "scripts" / "check_release_readiness.py"
    name = "adaf_test_check_release_readiness"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_release_docs_do_not_claim_overall_ten() -> None:
    release = (ROOT / "RELEASE.md").read_text(encoding="utf-8")
    assert "overall **10/10**" not in release
    published = (ROOT / "docs" / "RELEASE_EVIDENCE_0.10.1.md").read_text(encoding="utf-8")
    assert "Manual evidence not captured" in published
    template = (ROOT / "docs" / "RELEASE_EVIDENCE.md").read_text(encoding="utf-8")
    assert "Do **not** claim an overall 10/10" in template


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


def test_windows_lifecycle_selects_current_or_explicit_wheel() -> None:
    script = (ROOT / "scripts" / "Test-WindowsInstaller.ps1").read_text(encoding="utf-8")
    assert "[string]$Package" in script
    assert "pyproject.toml" in script
    assert "dist\\adaf_attack-$version-*.whl" in script
    assert "dist\\*.whl" not in script


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


def test_release_readiness_ci_uses_a_writable_runner_path_root() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert '--writable-root "$RUNNER_TEMP/adaf-readiness-paths"' in workflow


def test_release_readiness_uses_active_console_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_release_readiness_script()
    monkeypatch.delenv("ADAF_CLI", raising=False)
    monkeypatch.setattr(module.sysconfig, "get_path", lambda name: str(tmp_path))
    console_name = "adaf-attack.exe" if module.os.name == "nt" else "adaf-attack"
    assert module._cli_argv() == [str(tmp_path / console_name)]


def test_release_readiness_allocates_and_cleans_implicit_writable_root() -> None:
    module = _load_release_readiness_script()
    with module._writable_root(None) as root:
        assert root.is_dir()
        environment = module._readiness_path_environment(root)
        assert environment["ADAF_ATTACK_DATA_DIR"] == str(root / "data")
        assert environment["ADAF_ATTACK_CONFIG_DIR"] == str(root / "config")
        assert environment["ADAF_ATTACK_WORKSPACE"] == str(root / "workspace")
    assert not root.exists()


def test_release_readiness_cli_inherits_explicit_path_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_release_readiness_script()
    module._READINESS_PATH_ENV = module._readiness_path_environment(tmp_path)
    captured: dict[str, dict[str, str]] = {}

    class Result:
        returncode = 0
        stdout = "{}"
        stderr = ""

    def fake_run(*args, **kwargs):
        captured["env"] = kwargs["env"]
        return Result()

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    try:
        module.run_cli("--format", "json", "paths")
    finally:
        module._READINESS_PATH_ENV = {}

    assert captured["env"] == {
        **module._CLI_ENV,
        "ADAF_ATTACK_DATA_DIR": str(tmp_path / "data"),
        "ADAF_ATTACK_CONFIG_DIR": str(tmp_path / "config"),
        "ADAF_ATTACK_WORKSPACE": str(tmp_path / "workspace"),
    }


def test_release_readiness_ignores_unrelated_pip_conflicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_release_readiness_script()

    class Result:
        returncode = 1
        stdout = "unrelated-tool 1.0 has requirement typer==1.0, but you have typer 2.0.\n"
        stderr = ""

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: Result())
    monkeypatch.setattr(
        module,
        "distribution_closure",
        lambda: {"adaf-attack", "typer"},
    )
    module._pip_check()


def test_release_readiness_rejects_adaf_dependency_conflicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_release_readiness_script()

    class Result:
        returncode = 1
        stdout = "adaf-attack 0.10.1 has requirement typer==0.27.1, but you have typer 0.23.1.\n"
        stderr = ""

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: Result())
    monkeypatch.setattr(module, "distribution_closure", lambda: {"adaf-attack", "typer"})
    with pytest.raises(AssertionError, match="ADAF dependencies"):
        module._pip_check()
