# Windows support — ADAF-ATTACK

ADAF-ATTACK runs on **Windows 10/11 and Windows Server** with Python 3.11+.

## Quick install

```powershell
# From an elevated or normal PowerShell in the repo root
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned   # if needed
.\scripts\Install-AdafAttack.ps1 -Extras full
```

This will:

1. Create `.venv` under the repo
2. `pip install -e ".[full]"`
3. Drop a user PATH shim at `%LOCALAPPDATA%\adaf-attack\bin\adaf-attack.cmd`
4. Set `ADAF_ATTACK_WORKSPACE=%LOCALAPPDATA%\adaf-attack\workspaces`

Open a **new** terminal, then:

```powershell
adaf-attack doctor
adaf-attack paths
adaf-attack list-capabilities
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
