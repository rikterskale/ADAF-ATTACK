<#
.SYNOPSIS
  Install, upgrade, or uninstall ADAF-ATTACK on Windows PowerShell 5.1+.

.DESCRIPTION
  Creates a repository-local virtual environment, installs a release artifact or
  source checkout, and owns one user PATH shim plus ADAF_ATTACK_WORKSPACE.
  Uninstall preserves workspaces unless -RemoveWorkspace is explicitly supplied.

.PARAMETER Package
  Wheel or source-distribution path. When omitted, installs from RepoRoot.

.PARAMETER Python
  Python command or full executable path. "py" selects PythonVersion.

.PARAMETER PythonVersion
  Version passed to the Windows py launcher. Default: 3.11.

.EXAMPLE
  .\scripts\Install-AdafAttack.ps1 -Package .\dist\adaf_attack-0.10.0-py3-none-any.whl

.EXAMPLE
  .\scripts\Install-AdafAttack.ps1 -Uninstall

.EXAMPLE
  .\scripts\Install-AdafAttack.ps1 -Json -Package .\dist\adaf_attack-0.10.0-py3-none-any.whl
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,

    [Parameter(Mandatory = $false)]
    [ValidateSet("base", "dev", "tui", "kerberos", "reports", "full")]
    [string]$Extras = "full",

    [Parameter(Mandatory = $false)]
    [string]$Python = "py",

    [Parameter(Mandatory = $false)]
    [ValidatePattern("^\d+\.\d+$")]
    [string]$PythonVersion = "3.11",

    [Parameter(Mandatory = $false)]
    [string]$Package,

    [Parameter(Mandatory = $false)]
    [switch]$Editable,

    [Parameter(Mandatory = $false)]
    [switch]$SkipCompletion,

    [Parameter(Mandatory = $false)]
    [switch]$Uninstall,

    [Parameter(Mandatory = $false)]
    [switch]$RemoveWorkspace,

    [Parameter(Mandatory = $false)]
    [switch]$Json
)

$ErrorActionPreference = "Stop"
$global:AdafJsonInstallerErrors = $Json
trap {
    $message = $_.Exception.Message
    $remediation = "Check Python 3.11-3.13, artifact access, permissions, and rerun with -Json for machine-readable diagnostics."
    if ($global:AdafJsonInstallerErrors) {
        [pscustomobject]@{
            ok = $false
            error = [pscustomobject]@{
                code = "INSTALLER_FAILURE"
                message = $message
                remediation = $remediation
            }
        } | ConvertTo-Json -Depth 4 -Compress
    } else {
        Write-Error $message
        Write-Error "Next step: $remediation"
    }
    exit 1
}
$minimumPython = [Version]"3.11"
$maximumPython = [Version]"3.14"
$installRoot = Join-Path $env:LOCALAPPDATA "adaf-attack"
$shimDir = Join-Path $installRoot "bin"
$shim = Join-Path $shimDir "adaf-attack.cmd"
$markerPath = Join-Path $installRoot "install.json"
$workspace = Join-Path $installRoot "workspaces"
$existingMarker = $null
if (Test-Path $markerPath -PathType Leaf) {
    $existingMarker = Get-Content -Raw $markerPath | ConvertFrom-Json
}
$preservePriorOwnership = $existingMarker -and $existingMarker.install_complete

function Write-Step([string]$Message) { Write-Host "[+] $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "[!] $Message" -ForegroundColor Yellow }

function Remove-OwnedPathEntry([string]$Entry) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { return }
    $kept = @(
        $userPath.Split(";") | Where-Object {
            $_ -and -not [string]::Equals(
                $_.TrimEnd("\"),
                $Entry.TrimEnd("\"),
                [StringComparison]::OrdinalIgnoreCase
            )
        }
    )
    [Environment]::SetEnvironmentVariable("Path", ($kept -join ";"), "User")
}

function Invoke-Native([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $Command $($Arguments -join ' ')"
    }
}

if ($Uninstall) {
    if (-not (Test-Path $markerPath -PathType Leaf)) {
        throw "No installer ownership record exists at $markerPath. Nothing was removed."
    }
    $marker = $existingMarker
    Write-Step "Removing installer-owned virtual environment and shim"
    if (Test-Path $marker.venv) {
        Remove-Item -Recurse -Force $marker.venv
    }
    if (Test-Path $marker.shim) {
        Remove-Item -Force $marker.shim
    }
    if ($marker.path_added) {
        Remove-OwnedPathEntry $marker.shim_dir
    }

    $ownedWorkspace = [string]$marker.workspace
    $currentWorkspace = [Environment]::GetEnvironmentVariable("ADAF_ATTACK_WORKSPACE", "User")
    if ([string]::Equals($currentWorkspace, $ownedWorkspace, [StringComparison]::OrdinalIgnoreCase)) {
        $previousWorkspace = $null
        if ($marker.PSObject.Properties.Name -contains "previous_workspace") {
            $previousWorkspace = $marker.previous_workspace
        }
        [Environment]::SetEnvironmentVariable(
            "ADAF_ATTACK_WORKSPACE",
            $previousWorkspace,
            "User"
        )
    }
    if ($RemoveWorkspace) {
        if ($ownedWorkspace -and (Test-Path $ownedWorkspace)) {
            Remove-Item -Recurse -Force $ownedWorkspace
            Write-Ok "Removed workspace data: $ownedWorkspace"
        }
    } else {
        Write-Ok "Preserved workspace data: $ownedWorkspace"
    }
    Remove-Item -Force $markerPath
    if ((Test-Path $shimDir) -and -not (Get-ChildItem -Force $shimDir)) {
        Remove-Item -Force $shimDir
    }
    Write-Ok "Uninstall complete. Open a new terminal to refresh PATH."
    exit 0
}

if (-not (Test-Path $RepoRoot -PathType Container)) {
    throw "RepoRoot does not exist: $RepoRoot"
}
if (-not $Package -and -not (Test-Path (Join-Path $RepoRoot "pyproject.toml"))) {
    throw "RepoRoot does not look like ADAF-ATTACK: $RepoRoot"
}
if ((Test-Path $shim -PathType Leaf) -and -not $existingMarker) {
    throw "Refusing to overwrite unowned shim: $shim. Move it or remove it explicitly."
}

$pythonCommand = $Python.Trim()
$pythonPrefix = @()
if ($pythonCommand -match "^(py(?:\.exe)?)\s+(.+)$") {
    $pythonCommand = $Matches[1]
    $pythonPrefix = @($Matches[2].Split(" ", [StringSplitOptions]::RemoveEmptyEntries))
}
$resolvedPython = Get-Command $pythonCommand -ErrorAction SilentlyContinue
if (-not $resolvedPython) {
    throw "Python command not found: $pythonCommand. Install Python 3.11-3.13 or pass -Python with a full path."
}
if ($resolvedPython.Source) {
    $pythonCommand = $resolvedPython.Source
}
if ((Split-Path $pythonCommand -Leaf) -match "^py(?:\.exe)?$" -and $pythonPrefix.Count -eq 0) {
    $pythonPrefix = @("-$PythonVersion")
}

Write-Step "Validating Python 3.11 through 3.13"
$probeArgs = @($pythonPrefix) + @(
    "-c",
    "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}|{sys.executable}')"
)
$probeOutput = & $pythonCommand @probeArgs
if ($LASTEXITCODE -ne 0) {
    throw "Python probe failed with exit code $LASTEXITCODE`: $pythonCommand $($pythonPrefix -join ' ')"
}
$probe = [string]($probeOutput | Select-Object -Last 1)
$probeParts = $probe.Trim().Split("|")
if ($probeParts.Count -ne 2) {
    throw "Could not parse Python version and executable from: $probe"
}
$detectedVersion = [Version]$probeParts[0]
if ($detectedVersion -lt $minimumPython -or $detectedVersion -ge $maximumPython) {
    throw "Python $detectedVersion is unsupported. ADAF-ATTACK requires Python 3.11 through 3.13."
}
$pythonExe = $probeParts[1]
Write-Ok "Using Python $detectedVersion at $pythonExe"

$venv = Join-Path $RepoRoot ".venv"
$venvPython = Join-Path $venv "Scripts\python.exe"
if ((Test-Path $venv) -and -not $existingMarker) {
    throw "Refusing to modify unowned virtual environment: $venv. Move it or remove it explicitly."
}
if ($existingMarker -and -not [string]::Equals(
    ([string]$existingMarker.venv).TrimEnd("\"),
    $venv.TrimEnd("\"),
    [StringComparison]::OrdinalIgnoreCase
)) {
    throw "This installer already owns a different environment: $($existingMarker.venv). Uninstall it first."
}
if (-not $existingMarker) {
    New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
    @{
        repo_root = (Resolve-Path $RepoRoot).Path
        venv = $venv
        shim = $shim
        shim_dir = $shimDir
        path_added = $false
        workspace = $workspace
        previous_workspace = [Environment]::GetEnvironmentVariable(
            "ADAF_ATTACK_WORKSPACE",
            "User"
        )
        install_complete = $false
    } | ConvertTo-Json | Set-Content -Path $markerPath -Encoding ASCII
    $existingMarker = Get-Content -Raw $markerPath | ConvertFrom-Json
}
Write-Step "Creating or refreshing virtual environment at $venv"
if (-not (Test-Path $venvPython)) {
    Invoke-Native $pythonExe @("-m", "venv", $venv)
} else {
    $selectedBase = & $pythonExe -c "import os, sys; print(os.path.normcase(os.path.realpath(sys.base_prefix)))"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not identify the selected Python base interpreter."
    }
    $existingBase = & $venvPython -c "import os, sys; print(os.path.normcase(os.path.realpath(sys.base_prefix)))"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not identify the existing virtual environment interpreter."
    }
    if (-not [string]::Equals(
        ([string]$selectedBase).Trim(),
        ([string]$existingBase).Trim(),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Existing $venv uses $existingBase, not selected interpreter $selectedBase. Uninstall first or select the matching Python."
    }
}
Invoke-Native $venvPython @("-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel")

if ($Package) {
    $installTarget = (Resolve-Path $Package).Path
} else {
    $installTarget = (Resolve-Path $RepoRoot).Path
}
if ($Extras -ne "base") {
    $installTarget = "$installTarget[$Extras]"
}
$installArgs = @("-m", "pip", "install", "--upgrade")
if ($Editable) {
    if ($Package) { throw "-Editable cannot be combined with -Package." }
    $installArgs += "--editable"
}
$installArgs += $installTarget
Write-Step "Installing $installTarget"
Invoke-Native $venvPython $installArgs
Invoke-Native $venvPython @("-m", "pip", "check")

$scriptsAdaf = Join-Path $venv "Scripts\adaf-attack.exe"
if (-not (Test-Path $scriptsAdaf -PathType Leaf)) {
    throw "Installation completed without the expected console entry point: $scriptsAdaf"
}

New-Item -ItemType Directory -Force -Path $shimDir | Out-Null
@(
    "@echo off"
    "`"$scriptsAdaf`" %*"
) | Set-Content -Path $shim -Encoding ASCII

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @()
if ($userPath) { $pathEntries = @($userPath.Split(";")) }
$pathOwned = $false
foreach ($entry in $pathEntries) {
    if ([string]::Equals(
        $entry.TrimEnd("\"),
        $shimDir.TrimEnd("\"),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        $pathOwned = $true
    }
}
$pathAdded = -not $pathOwned
if ($preservePriorOwnership) {
    $pathAdded = [bool]$existingMarker.path_added
}
if (-not $pathOwned) {
    $newUserPath = $shimDir
    if ($userPath) { $newUserPath = "$userPath;$shimDir" }
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
}

New-Item -ItemType Directory -Force -Path $workspace | Out-Null
$previousWorkspace = [Environment]::GetEnvironmentVariable("ADAF_ATTACK_WORKSPACE", "User")
if ($existingMarker.PSObject.Properties.Name -contains "previous_workspace") {
    $previousWorkspace = $existingMarker.previous_workspace
}
[Environment]::SetEnvironmentVariable("ADAF_ATTACK_WORKSPACE", $workspace, "User")

@{
    repo_root = (Resolve-Path $RepoRoot).Path
    venv = $venv
    shim = $shim
    shim_dir = $shimDir
    path_added = $pathAdded
    workspace = $workspace
    previous_workspace = $previousWorkspace
    install_complete = $true
} | ConvertTo-Json | Set-Content -Path $markerPath -Encoding ASCII

if (-not $SkipCompletion) {
    Write-Step "Installing PowerShell completion"
    & $scriptsAdaf --install-completion powershell
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Completion installation failed with exit code $LASTEXITCODE. Run 'adaf-attack --install-completion powershell' after opening a new terminal."
    }
}

Write-Ok "Install complete."
Write-Host "  Activate now: $venv\Scripts\Activate.ps1"
Write-Host "  New terminal:  adaf-attack doctor --explain"
Write-Host "  Workspace:     $workspace"
Write-Host "  Uninstall:     .\scripts\Install-AdafAttack.ps1 -Uninstall"
