---
guide_id: windows-novice-usability
guide_schema_version: 1
platform: windows
canonical_path: docs/WINDOWS_NOVICE_USABILITY_GUIDE.md
project_name: ADAF-ATTACK
target_release: 0.10.0
support_status: hosted_ci_artifact_and_installer_smoke
primary_shells: ["Windows PowerShell 5.1", "PowerShell 7"]
maintainer_source_of_truth: pyproject.toml
---

# ADAF-ATTACK Windows new-user guide

Use ADAF-ATTACK only under written authorization. The safe first run below is
offline and does not contact Active Directory.

## Prerequisites

- 64-bit Windows 10/11 or Windows Server
- Python 3.11-3.14 from python.org, including the `py` launcher
- Windows PowerShell 5.1 or PowerShell 7
- Git when using a source checkout
- Access to this private repository or an approved release wheel

Check the launcher before installing:

```powershell
py -0p
py -3.11 --version
```

## Download or clone

For the release path, download the approved `.whl` from the private GitHub
release. To use the installer, clone or extract the matching source release:

```powershell
git clone <approved-repository-url> ADAF-ATTACK
Set-Location .\ADAF-ATTACK
```

The working directory must contain `pyproject.toml` and `scripts`.

## Install

Place the wheel in `dist`, then run the PowerShell 5.1-compatible installer:

```powershell
.\scripts\Install-AdafAttack.ps1 `
  -Package .\dist\adaf_attack-0.10.0-py3-none-any.whl `
  -Extras full `
  -Python py `
  -PythonVersion 3.11
```

For an authorized source checkout before a release asset exists:

```powershell
.\scripts\Install-AdafAttack.ps1 -Extras full -Python py -PythonVersion 3.11
```

The installer creates `.venv`, `%LOCALAPPDATA%\adaf-attack\bin\adaf-attack.cmd`,
an ownership record, and `%LOCALAPPDATA%\adaf-attack\workspaces`. It adds only
its shim directory to the user PATH. Open a new terminal after installation.

## Verify

```powershell
adaf-attack --version
adaf-attack doctor --explain
adaf-attack list-capabilities
adaf-attack paths
```

If the command is not found in the current window, either open a new terminal or
run `.\.venv\Scripts\adaf-attack.exe` for the immediate verification.

## First safe offline run

```powershell
adaf-attack --format json doctor --explain
adaf-attack --format json list-capabilities
adaf-attack --format json paths
```

Each result should contain `"ok": true`. `paths` identifies the workspace where
future `session.json`, `events.jsonl`, findings, and reports are written. These
commands create no target artifacts.

## Stop or cancel

Press `Ctrl+C` once. Wait for the command to stop and preserve its session
directory; do not delete evidence while a process is still writing. Onboarding
commands above finish on their own.

## Upgrade and downgrade

Download the exact approved wheel, then rerun the installer. It upgrades or
downgrades the existing venv and runs `pip check`:

```powershell
.\scripts\Install-AdafAttack.ps1 `
  -Package .\dist\adaf_attack-0.10.0-py3-none-any.whl `
  -Extras full `
  -Python py `
  -PythonVersion 3.11
adaf-attack --version
```

## Uninstall and data preservation

The default uninstall removes only installer-owned components: `.venv`, the
shim, its exact user PATH entry, and its owned environment variable. It
preserves workspaces:

```powershell
.\scripts\Install-AdafAttack.ps1 -Uninstall
```

Delete workspace evidence only after retention approval:

```powershell
.\scripts\Install-AdafAttack.ps1 -Uninstall -RemoveWorkspace
```

Verify with `Get-Command adaf-attack -ErrorAction SilentlyContinue` in a new
terminal and inspect `%LOCALAPPDATA%\adaf-attack\workspaces`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Script execution is disabled | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use an approved process-scope policy. |
| SmartScreen marks downloaded scripts | Verify source/signature, then `Unblock-File .\scripts\Install-AdafAttack.ps1`. |
| Wrong Python is selected | Use `py -0p`, then pass `-Python <full-python.exe-path>`. |
| `adaf-attack` is not found | Open a new terminal; verify the exact shim directory in user PATH. |
| pip reports proxy/certificate errors | Configure the approved proxy and CA; do not use `--trusted-host` as a blanket bypass. |
| Optional tooling conflicts | Keep Certipy or other conflicting tools in a separate venv and rerun `doctor --explain`. |

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for full diagnostics and offline
installation guidance.

## Support boundaries

Hosted CI exercises wheel installation on Windows and the installer under
Windows PowerShell 5.1/Python 3.11 and PowerShell 7/Python 3.14. It does not
prove live AD connectivity, endpoint security policy compatibility, scheduled
task credentials, or destructive capability rollback in your environment.
