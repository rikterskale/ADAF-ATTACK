# Windows support — ADAF-ATTACK

ADAF-ATTACK runs on **Windows 10/11 and Windows Server** with Python 3.11-3.14.

## Quick install

```powershell
# From a normal PowerShell in the repo root
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned   # if needed
.\scripts\Install-AdafAttack.ps1 `
  -Package .\dist\adaf_attack-0.10.1-py3-none-any.whl `
  -Extras full
```

This will:

1. Create `.venv` under the repo
2. Install the wheel (or authorized source checkout) with the production `full` extras
3. Drop a user PATH shim at `%LOCALAPPDATA%\adaf-attack\bin\adaf-attack.cmd`
4. Set `ADAF_ATTACK_WORKSPACE=%LOCALAPPDATA%\adaf-attack\workspaces`

Open a **new** terminal, then run the first-ten spine (no domain controller):

```powershell
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace .\quickstart
adaf-attack --format json guide --workspace .\quickstart --session .\quickstart\demo-session
adaf-attack --format json paths
```

Expect doctor `"ready": true` and a copy-ready `suggested_command` from `guide`.
**When lost:** `adaf-attack guide`. New operators should prefer the
[Windows novice guide](WINDOWS_NOVICE_USABILITY_GUIDE.md).

The script supports Windows PowerShell 5.1 and PowerShell 7. Select a specific
interpreter with `-Python C:\Path\python.exe`, or use the launcher with
`-Python py -PythonVersion 3.13`. It rejects Python older than 3.11 before
creating the environment.

Pass `-Json` when invoking the installer from automation. Failures are emitted
as a stable JSON object with `code`, `message`, `remediation`, and
`suggested_command` fields.

## Upgrade and uninstall

Rerun the installer with the exact approved wheel to upgrade or downgrade.
Uninstall removes the installer-owned venv, shim, exact PATH entry, and
`ADAF_ATTACK_WORKSPACE` value while preserving evidence:

```powershell
.\scripts\Install-AdafAttack.ps1 -Uninstall
```

Delete the owned workspace only after evidence-retention approval:

```powershell
.\scripts\Install-AdafAttack.ps1 -Uninstall -RemoveWorkspace
```

## PowerShell module

```powershell
Import-Module .\scripts\AdafAttack.psm1

Invoke-AdafDoctor
Invoke-AdafList
Invoke-AdafRun -Capability ldap-enum -Domain corp.local -DcIp 10.0.0.10 -Username alice -Password 'P@ssw0rd'
Get-AdafSessions
```

## Paths

| Item | Default (Windows) |
|------|-------------------|
| Data | `%LOCALAPPDATA%\adaf-attack` |
| Workspaces | `%LOCALAPPDATA%\adaf-attack\workspaces` |
| Config | `%LOCALAPPDATA%\adaf-attack\config` |
| PATH shim | `%LOCALAPPDATA%\adaf-attack\bin` |

Override workspace:

```powershell
$env:ADAF_ATTACK_WORKSPACE = "D:\redteam\adaf-workspaces"
# or
adaf-attack run ldap-enum ... --workspace D:\redteam\adaf-workspaces
```

## Scheduled task (service-style)

Classic NT services need extra packaging. For recurring internal jobs, use a **Scheduled Task**:

```powershell
.\scripts\Register-AdafAttackTask.ps1 `
  -Capability ldap-enum `
  -Domain corp.local `
  -DcIp 10.0.0.10 `
  -Username svc_adaf `
  -PasswordFile C:\secure\svc_adaf.pass `
  -IntervalMinutes 1440
```

Remove:

```powershell
.\scripts\Unregister-AdafAttackTask.ps1 -TaskName ADAF-ATTACK-ldap-enum
```

Run the task under a dedicated AD account with least privilege for the intended capabilities. Prefer a password file ACLed to that account over embedding secrets in the task XML.

## Notes

- **LDAP / Kerberos** from Windows works with `ldap3` + Impacket the same as on Linux.
- **Textual TUI** (`adaf-attack start`) works in Windows Terminal; legacy `conhost` is a poorer experience.
- Line endings: session JSON/JSONL are written with `\n` for cross-platform portability.
- If SmartScreen blocks scripts, unblock: `Unblock-File .\scripts\*.ps1`
- For PATH, launcher, proxy/CA, offline, and PEP 668 guidance, see
  [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
