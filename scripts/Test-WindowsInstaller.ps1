<#
.SYNOPSIS
  Exercise the Windows artifact installer lifecycle in CI.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,

    [Parameter(Mandatory = $false)]
    [switch]$PreexistingConfig
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:LOCALAPPDATA = Join-Path $env:RUNNER_TEMP "adaf-localappdata"
$wheel = @(Get-ChildItem (Join-Path $RepoRoot "dist\*.whl"))
if ($wheel.Count -ne 1) {
    throw "Expected exactly one wheel, found $($wheel.Count)"
}

$python = (Get-Command python).Source
$shimDir = Join-Path $env:LOCALAPPDATA "adaf-attack\bin"
$previousWorkspace = Join-Path $env:RUNNER_TEMP "preexisting-workspace"
if ($PreexistingConfig) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$shimDir", "User")
    [Environment]::SetEnvironmentVariable(
        "ADAF_ATTACK_WORKSPACE",
        $previousWorkspace,
        "User"
    )
}

$installer = Join-Path $RepoRoot "scripts\Install-AdafAttack.ps1"
& $installer `
    -RepoRoot $RepoRoot `
    -Package $wheel[0].FullName `
    -Extras base `
    -Python $python `
    -SkipCompletion

$venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
& $venvPython -m pip check
if ($LASTEXITCODE -ne 0) { throw "pip check failed" }

$shim = Join-Path $shimDir "adaf-attack.cmd"
if (-not (Test-Path $shim)) { throw "Installer PATH shim missing: $shim" }
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$shimDir*") {
    throw "Installer shim directory missing from user PATH"
}
$workspace = [Environment]::GetEnvironmentVariable("ADAF_ATTACK_WORKSPACE", "User")
if (-not $workspace) { throw "Installer did not set ADAF_ATTACK_WORKSPACE" }
$env:Path = "$shimDir;$env:Path"

& adaf-attack --version
if ($LASTEXITCODE -ne 0) { throw "Installer-created shim failed" }
& adaf-attack --format json doctor --explain | ConvertFrom-Json | ForEach-Object {
    if (-not $_.ok) { throw "doctor reported failure" }
}
& adaf-attack list-capabilities
if ($LASTEXITCODE -ne 0) { throw "list-capabilities failed through shim" }
& adaf-attack paths
if ($LASTEXITCODE -ne 0) { throw "paths failed through shim" }

New-Item -ItemType Directory -Force $workspace | Out-Null
$sentinel = Join-Path $workspace "preserve-me.txt"
Set-Content $sentinel "operator data"

# Re-running the installer is the supported in-place upgrade path.
& $installer `
    -RepoRoot $RepoRoot `
    -Package $wheel[0].FullName `
    -Extras base `
    -Python $python `
    -SkipCompletion
& $installer -Uninstall
if (Test-Path $shim) { throw "Uninstall left the PATH shim behind" }
if (-not (Test-Path $sentinel)) { throw "Default uninstall deleted workspace data" }

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$restoredWorkspace = [Environment]::GetEnvironmentVariable(
    "ADAF_ATTACK_WORKSPACE",
    "User"
)
if ($PreexistingConfig) {
    if ($userPath -notlike "*$shimDir*") {
        throw "Uninstall removed a pre-existing PATH entry"
    }
    if ($restoredWorkspace -ne $previousWorkspace) {
        throw "Uninstall did not restore the previous workspace environment value"
    }
} else {
    if ($userPath -like "*$shimDir*") {
        throw "Uninstall left its user PATH entry behind"
    }
    if ($restoredWorkspace) {
        throw "Uninstall left its owned workspace environment variable behind"
    }
}

& $installer `
    -RepoRoot $RepoRoot `
    -Package $wheel[0].FullName `
    -Extras base `
    -Python $python `
    -SkipCompletion
& $installer -Uninstall -RemoveWorkspace
if (Test-Path $workspace) { throw "Explicit workspace removal did not delete data" }
