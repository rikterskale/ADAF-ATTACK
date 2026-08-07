<#
.SYNOPSIS
  Install ADAF-ATTACK on Windows (Python venv + editable install).

.DESCRIPTION
  Creates a virtual environment, installs the package with selected extras,
  and optionally adds a user-level shim directory to PATH.

.PARAMETER RepoRoot
  Path to the cloned ADAF-ATTACK repository.

.PARAMETER Extras
  Pip extras to install. Default: full (dev,tui,kerberos).

.PARAMETER Python
  Python launcher. Default: py -3.11 (falls back to python).

.EXAMPLE
  .\scripts\Install-AdafAttack.ps1 -RepoRoot C:\src\ADAF-ATTACK
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,

    [Parameter(Mandatory = $false)]
    [ValidateSet("dev", "tui", "kerberos", "full")]
    [string]$Extras = "full",

    [Parameter(Mandatory = $false)]
    [string]$Python = "py"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "[+] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[✓] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

if (-not (Test-Path (Join-Path $RepoRoot "pyproject.toml"))) {
    throw "RepoRoot does not look like ADAF-ATTACK: $RepoRoot"
}

$venv = Join-Path $RepoRoot ".venv"
$pythonExe = $null

Write-Step "Resolving Python..."
try {
    if ($Python -eq "py") {
        $ver = & py -3.11 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $ver) { $pythonExe = $ver.Trim() }
    }
} catch { }

if (-not $pythonExe) {
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue)?.Source
}
if (-not $pythonExe) {
    throw "Python 3.11+ not found. Install from https://www.python.org/downloads/ and ensure 'py' or 'python' is on PATH."
}
Write-Ok "Using $pythonExe"

Write-Step "Creating venv at $venv"
& $pythonExe -m venv $venv
$venvPython = Join-Path $venv "Scripts\python.exe"
$venvPip = Join-Path $venv "Scripts\pip.exe"

Write-Step "Upgrading pip"
& $venvPython -m pip install --upgrade pip wheel setuptools

$extraSpec = switch ($Extras) {
    "full"     { ".[full]" }
    "dev"      { ".[dev]" }
    "tui"      { ".[dev,tui]" }
    "kerberos" { ".[dev,kerberos]" }
}

Write-Step "Installing adaf-attack $extraSpec"
Push-Location $RepoRoot
try {
    & $venvPip install -e $extraSpec
} finally {
    Pop-Location
}

$shimDir = Join-Path $env:LOCALAPPDATA "adaf-attack\bin"
New-Item -ItemType Directory -Force -Path $shimDir | Out-Null
$shim = Join-Path $shimDir "adaf-attack.cmd"
@(
    "@echo off"
    "`"$venvPython`" -m adaf_attack.cli %*"
) | Set-Content -Path $shim -Encoding ASCII

# Prefer console_script if present
$scriptsAdaf = Join-Path $venv "Scripts\adaf-attack.exe"
if (Test-Path $scriptsAdaf) {
    @(
        "@echo off"
        "`"$scriptsAdaf`" %*"
    ) | Set-Content -Path $shim -Encoding ASCII
}

Write-Step "User PATH shim → $shimDir"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$shimDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$shimDir", "User")
    Write-Ok "Added to user PATH (open a new terminal)"
} else {
    Write-Ok "Already on user PATH"
}

# Default workspace under LOCALAPPDATA
$ws = Join-Path $env:LOCALAPPDATA "adaf-attack\workspaces"
New-Item -ItemType Directory -Force -Path $ws | Out-Null
[Environment]::SetEnvironmentVariable("ADAF_ATTACK_WORKSPACE", $ws, "User")
Write-Ok "ADAF_ATTACK_WORKSPACE=$ws"

Write-Step "Installing PowerShell tab-completion for adaf-attack"
try {
    & $scriptsAdaf --install-completion powershell 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "PowerShell completion installed (reload profile to use)"
    } else {
        Write-Warn "Could not auto-install completion. Run 'adaf-attack --install-completion powershell' manually."
    }
} catch {
    Write-Warn "Could not auto-install completion: $($_.Exception.Message)"
}

Write-Host ""
Write-Ok "Install complete."
Write-Host "  Activate:  $venv\Scripts\Activate.ps1"
Write-Host "  Or use:    adaf-attack doctor   (new terminal after PATH refresh)"
Write-Host "  Module:    Import-Module .\scripts\AdafAttack.psm1"
