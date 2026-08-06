<#
.SYNOPSIS
  Register a Windows Scheduled Task that runs an ADAF-ATTACK capability on a schedule.

.DESCRIPTION
  Uses Scheduled Tasks (not a classic NT service) so no pywin32 dependency is required.
  Suitable for recurring internal enum jobs under a dedicated service account.

.PARAMETER TaskName
  Scheduled task name. Default: ADAF-ATTACK-<Capability>

.PARAMETER Capability
  Capability ID to run.

.PARAMETER Domain / DcIp / Username
  Target parameters. Password should be provided via DPAPI file or run-as account, not plaintext in task if avoidable.

.PARAMETER PasswordFile
  Optional path to a UTF-8 file containing the password (ACLed to the run-as user).

.PARAMETER IntervalMinutes
  Repeat interval. Default 1440 (daily).

.EXAMPLE
  .\scripts\Register-AdafAttackTask.ps1 -Capability ldap-enum -Domain corp.local -DcIp 10.0.0.10 -Username svc_adaf -PasswordFile C:\secure\svc.pass
#>
[CmdletBinding()]
param(
    [string]$TaskName,
    [Parameter(Mandatory = $true)][string]$Capability,
    [Parameter(Mandatory = $true)][string]$Domain,
    [Parameter(Mandatory = $true)][string]$DcIp,
    [string]$Username,
    [string]$PasswordFile,
    [int]$IntervalMinutes = 1440,
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$Workspace
)

$ErrorActionPreference = "Stop"

if (-not $TaskName) { $TaskName = "ADAF-ATTACK-$Capability" }

$venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    throw "Venv not found at $venvPython — run Install-AdafAttack.ps1 first."
}

$argList = [System.Collections.Generic.List[string]]::new()
$argList.Add("-m")
$argList.Add("adaf_attack.cli")
$argList.Add("run")
$argList.Add($Capability)
$argList.Add("-d"); $argList.Add($Domain)
$argList.Add("--dc-ip"); $argList.Add($DcIp)
if ($Username) { $argList.Add("-u"); $argList.Add($Username) }
if ($Workspace) { $argList.Add("--workspace"); $argList.Add($Workspace) }

# Wrapper script expands password file at runtime so the task XML need not embed secrets
$wrapperDir = Join-Path $env:LOCALAPPDATA "adaf-attack\tasks"
New-Item -ItemType Directory -Force -Path $wrapperDir | Out-Null
$wrapper = Join-Path $wrapperDir "$TaskName.ps1"

$wrapperBody = @"
`$ErrorActionPreference = 'Stop'
`$py = '$venvPython'
`$args = @('$($argList -join "','")')
"@
if ($PasswordFile) {
    $wrapperBody += @"

`$pass = Get-Content -LiteralPath '$PasswordFile' -Raw -Encoding UTF8
`$pass = `$pass.Trim()
`$args += @('-p', `$pass)
"@
}
$wrapperBody += @"

& `$py `$args
"@
Set-Content -Path $wrapper -Value $wrapperBody -Encoding UTF8

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$wrapper`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration ([TimeSpan]::MaxValue)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Write-Host "[✓] Registered scheduled task: $TaskName" -ForegroundColor Green
Write-Host "    Wrapper: $wrapper"
Write-Host "    Remove:  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
