from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("shell_name", ["pwsh", "powershell"])
def test_windows_installer_can_probe_python_in_a_unicode_bracketed_path(
    tmp_path: Path, shell_name: str
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows installer requires Windows")
    shell = shutil.which(shell_name)
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    interpreter_root = tmp_path / "python café 漢字 [probe]"
    venv.EnvBuilder(with_pip=False).create(interpreter_root)
    checkout = tmp_path / "checkout"
    (checkout / ".venv").mkdir(parents=True)
    # Stop after a successful probe, before installation or persistent settings.
    result = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(ROOT / "scripts" / "Install-AdafAttack.ps1"),
            "-RepoRoot",
            str(checkout),
            "-Package",
            "unused.whl",
            "-Python",
            str(interpreter_root / "Scripts/python.exe"),
            "-Json",
        ],
        env={**os.environ, "LOCALAPPDATA": str(tmp_path / "local-data")},
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout.splitlines()[-1])
    assert payload["error"]["code"] == "INSTALLER_OWNERSHIP", result.stdout + result.stderr
    assert not (tmp_path / "local-data" / "adaf-attack" / "install.json").exists()


@pytest.mark.parametrize("shell_name", ["pwsh", "powershell"])
def test_windows_launcher_and_ownership_preserve_unicode_paths(
    tmp_path: Path, shell_name: str
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows launcher requires Windows")
    shell = shutil.which(shell_name)
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    console = Path(sys.executable).parent / "adaf-attack.exe"
    if not console.is_file():
        pytest.skip("Installed console entry point is unavailable")
    directory = tmp_path / "café 漢字 [launch]"
    driver = tmp_path / "launcher-test.ps1"
    driver.write_text(
        """
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:ADAF_TEST_INSTALLER, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Installer parse failed' }
$functions = $ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -in @('Write-AdafLauncher', 'Write-AdafOwnership')
}, $true)
foreach ($function in $functions) {
    . ([scriptblock]::Create($function.Extent.Text))
}
Write-AdafLauncher $env:ADAF_TEST_CONSOLE $env:ADAF_TEST_DIRECTORY
Write-AdafOwnership @{workspace=$env:ADAF_TEST_DIRECTORY} (
    Join-Path $env:ADAF_TEST_DIRECTORY 'install.json')
""",
        encoding="ascii",
    )
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File", str(driver)],
        env={
            **os.environ,
            "ADAF_TEST_INSTALLER": str(ROOT / "scripts" / "Install-AdafAttack.ps1"),
            "ADAF_TEST_CONSOLE": str(console),
            "ADAF_TEST_DIRECTORY": str(directory),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    marker = json.loads((directory / "install.json").read_text(encoding="utf-8"))
    assert marker["workspace"] == str(directory)
    assert (directory / "adaf-attack.exe").read_bytes() == console.read_bytes()
    shim = directory / "adaf-attack.cmd"
    shim.read_text(encoding="ascii")
    for arguments, expected_code in (("--format json --version", 0), ("no-such-command", 2)):
        invocation = subprocess.run(
            f'cmd.exe /d /s /c ""{shim}" {arguments}"',
            capture_output=True,
            encoding="utf-8",
            env={**os.environ, "PYTHONUTF8": "1"},
            timeout=30,
            check=False,
        )
        assert invocation.returncode == expected_code, invocation.stdout + invocation.stderr
        if expected_code == 0:
            assert json.loads(invocation.stdout)["ok"] is True


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize("shell_name", ["pwsh", "powershell"])
def test_windows_installer_missing_python_explains_recovery(
    tmp_path: Path, json_output: bool, shell_name: str
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows installer requires Windows")
    shell = shutil.which(shell_name)
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    arguments = [
        shell,
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(ROOT / "scripts" / "Install-AdafAttack.ps1"),
        "-Python",
        "adaf-test-missing-python-executable",
    ]
    if json_output:
        arguments.append("-Json")
    result = subprocess.run(
        arguments,
        env={**os.environ, "LOCALAPPDATA": str(tmp_path)},
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1
    if json_output:
        payload = json.loads(result.stdout)
        assert payload["ok"] is False
        assert payload["error"]["code"] == "PYTHON_UNSUPPORTED"
        assert "full path" in payload["error"]["remediation"]
        assert payload["error"]["recovery_command"]
    else:
        output = result.stdout + result.stderr
        assert "PYTHON_UNSUPPORTED" in output
        assert "Next step:" in output
        assert "full path" in output
        assert "Recovery: adaf-attack doctor --profile user-readiness --explain" in output
    assert not (tmp_path / "adaf-attack").exists()


@pytest.mark.parametrize("shell_name", ["pwsh", "powershell"])
@pytest.mark.parametrize(
    "field", ["venv", "shim", "shim_dir", "workspace", "repo_root", "launcher"]
)
def test_windows_uninstall_rejects_corrupt_ownership_before_removing_data(
    tmp_path: Path, shell_name: str, field: str
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows installer requires Windows")
    shell = shutil.which(shell_name)
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    install_root = tmp_path / "adaf-attack"
    repo_root = tmp_path / "checkout"
    venv = repo_root / ".venv"
    shim_dir = install_root / "bin"
    workspace = install_root / "workspaces"
    unrelated = tmp_path / "unrelated-data"
    for directory in (venv, shim_dir, workspace, unrelated):
        directory.mkdir(parents=True)
        (directory / "preserve.txt").write_text("operator data", encoding="utf-8")
    shim = shim_dir / "adaf-attack.cmd"
    shim.write_text("owned shim", encoding="utf-8")
    marker = {
        "repo_root": str(repo_root),
        "venv": str(venv),
        "shim": str(shim),
        "shim_dir": str(shim_dir),
        "workspace": str(workspace),
        "path_added": False,
        "install_complete": True,
    }
    marker[field] = "" if field == "repo_root" else str(unrelated)
    marker_path = install_root / "install.json"
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    result = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(ROOT / "scripts" / "Install-AdafAttack.ps1"),
            "-Uninstall",
            "-RemoveWorkspace",
            "-Json",
        ],
        env={**os.environ, "LOCALAPPDATA": str(tmp_path)},
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert json.loads(result.stdout)["error"]["code"] == "INSTALLER_OWNERSHIP"
    assert marker_path.is_file()
    assert shim.read_text(encoding="utf-8") == "owned shim"
    for directory in (venv, shim_dir, workspace, unrelated):
        assert (directory / "preserve.txt").read_text(encoding="utf-8") == "operator data"


@pytest.mark.parametrize("shell_name", ["pwsh", "powershell"])
@pytest.mark.parametrize("remove_workspace", [False, True])
def test_windows_uninstall_preserves_data_unless_explicitly_requested(
    tmp_path: Path, shell_name: str, remove_workspace: bool
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows installer requires Windows")
    shell = shutil.which(shell_name)
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    local_data = tmp_path / "local café 漢字 [review]"
    install_root = local_data / "adaf-attack"
    repo_root = tmp_path / "checkout café 漢字 [review]"
    venv = repo_root / ".venv"
    shim_dir = install_root / "bin"
    workspace = install_root / "workspaces"
    for directory in (venv, shim_dir, workspace):
        directory.mkdir(parents=True)
    sentinel = workspace / "preserve.txt"
    sentinel.write_text("operator data", encoding="utf-8")
    shim = shim_dir / "adaf-attack.cmd"
    shim.write_text("owned shim", encoding="utf-8")
    launcher = shim_dir / "adaf-attack.exe"
    launcher.write_bytes(b"owned launcher")
    marker_path = install_root / "install.json"
    marker_path.write_text(
        json.dumps(
            {
                "repo_root": str(repo_root),
                "venv": str(venv),
                "shim": str(shim),
                "shim_dir": str(shim_dir),
                "launcher": str(launcher),
                "workspace": str(workspace),
                "path_added": False,
                "install_complete": True,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    arguments = [
        shell,
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(ROOT / "scripts" / "Install-AdafAttack.ps1"),
        "-Uninstall",
    ]
    if remove_workspace:
        arguments.append("-RemoveWorkspace")
    result = subprocess.run(
        arguments,
        env={**os.environ, "LOCALAPPDATA": str(local_data)},
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not venv.exists()
    assert not shim.exists()
    assert not launcher.exists()
    assert not marker_path.exists()
    assert not shim_dir.exists()
    assert repo_root.is_dir()
    if remove_workspace:
        assert not workspace.exists()
    else:
        assert sentinel.read_text(encoding="utf-8") == "operator data"


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
    assert 4 <= len(matrix) <= 8, (
        "artifact smoke should stay focused, not duplicate the test matrix"
    )
    for operating_system in ("ubuntu-24.04", "windows-2022", "macos-14"):
        assert {row["extras"] for row in matrix if row["os"] == operating_system} >= {
            "base",
            "full",
        }


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
