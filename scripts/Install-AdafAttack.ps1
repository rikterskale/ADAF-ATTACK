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
  .\scripts\Install-AdafAttack.ps1 -Package .\dist\adaf_attack-0.10.1-py3-none-any.whl

.EXAMPLE
  .\scripts\Install-AdafAttack.ps1 -Uninstall

.EXAMPLE
  .\scripts\Install-AdafAttack.ps1 -Json -Package .\dist\adaf_attack-0.10.1-py3-none-any.whl
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$RepoRoot,

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
    [string]$Manifest,

    [Parameter(Mandatory = $false)]
    [string]$Sha256,

    [Parameter(Mandatory = $false)]
    [string]$FindLinks,

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

function Resolve-AdafInstallerError([string]$Message) {
    $lower = $Message.ToLowerInvariant()
    if ($lower -match 'executionpolicy|running scripts is disabled|unauthorizedaccess' -and $lower -match 'script') {
        return [pscustomobject]@{
            code = "EXECUTION_POLICY_BLOCKED"
            remediation = "Set the narrowest approved CurrentUser RemoteSigned policy, Unblock-File this script, then retry with -Json."
        }
    }
    if ($lower -match 'python .*unsupported|requires python 3\.11|could not parse python version|python command not found|python probe failed') {
        return [pscustomobject]@{
            code = "PYTHON_UNSUPPORTED"
            remediation = "Install Python 3.11-3.14, pass -Python with a full path or -Python py -PythonVersion 3.13, then retry."
        }
    }
    if ($lower -match 'externally-managed-environment|pep 668|break-system-packages') {
        return [pscustomobject]@{
            code = "VENV_REQUIRED"
            remediation = "Use this installer (it creates an isolated venv) or create a venv manually before installing the wheel."
        }
    }
    if ($lower -match 'certificate|ssl|tls|proxy') {
        return [pscustomobject]@{
            code = "PROXY_TLS_FAILED"
            remediation = "Configure the organization CA with pip --cert / pip.ini, or install from an approved wheelhouse with --no-index."
        }
    }
    if ($lower -match 'unowned|ownership|refusing to') {
        return [pscustomobject]@{
            code = "INSTALLER_OWNERSHIP"
            remediation = "Inspect %LOCALAPPDATA%\adaf-attack\install.json and restore its original paths if damaged. For an unowned environment, use a separate checkout."
        }
    }
    if ($lower -match 'path|shim|console entry point|not found') {
        return [pscustomobject]@{
            code = "PATH_NOT_FOUND"
            remediation = "Open a new terminal after install, or invoke .\.venv\Scripts\adaf-attack.exe directly, then rerun doctor."
        }
    }
    return [pscustomobject]@{
        code = "INSTALLER_FAILURE"
        remediation = "Check Python 3.11-3.14, artifact access, permissions, and rerun with -Json for machine-readable diagnostics."
    }
}

function Fail-Adaf(
    [string]$Code,
    [string]$Message,
    [string]$Remediation
) {
    if ($global:AdafJsonInstallerErrors) {
        [pscustomobject]@{
            ok = $false
            error = [pscustomobject]@{
                code = $Code
                message = $Message
                remediation = $Remediation
                suggested_command = "adaf-attack doctor --profile user-readiness --explain"
                recovery_command = "adaf-attack doctor --profile user-readiness --explain"
            }
        } | ConvertTo-Json -Depth 4 -Compress
    } else {
        # The installer uses Stop globally; emit every recovery line before exiting.
        Write-Error "Error [$Code]: $Message" -ErrorAction Continue
        Write-Error "Next step: $Remediation" -ErrorAction Continue
        Write-Error "Recovery: adaf-attack doctor --profile user-readiness --explain" -ErrorAction Continue
    }
    exit 1
}

trap {
    $message = $_.Exception.Message
    $resolved = Resolve-AdafInstallerError $message
    Fail-Adaf -Code $resolved.code -Message $message -Remediation $resolved.remediation
}
if (-not $RepoRoot) {
    # Windows PowerShell 5.1 may evaluate parameter defaults before PSScriptRoot is set.
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
$minimumPython = [Version]"3.11"
$maximumPython = [Version]"3.15"
$installRoot = Join-Path $env:LOCALAPPDATA "adaf-attack"
$shimDir = Join-Path $installRoot "bin"
$shim = Join-Path $shimDir "adaf-attack.cmd"
$launcher = Join-Path $shimDir "adaf-attack.exe"
$markerPath = Join-Path $installRoot "install.json"
$workspace = Join-Path $installRoot "workspaces"
$existingMarker = $null
if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
    $existingMarker = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8 | ConvertFrom-Json
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

function Write-AdafOwnership([object]$Record, [string]$Path) {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, ($Record | ConvertTo-Json), $utf8)
}

function Write-AdafLauncher([string]$Console, [string]$Directory) {
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    # The installed executable embeds its interpreter path as Unicode. Copy it
    # intact; cmd expands dp0 at runtime, without decoding a literal user path.
    Copy-Item -LiteralPath $Console -Destination (Join-Path $Directory "adaf-attack.exe") -Force
    @('@echo off', '@setlocal DisableDelayedExpansion', '@"%~dp0adaf-attack.exe" %*') |
        Set-Content -LiteralPath (Join-Path $Directory "adaf-attack.cmd") -Encoding ASCII
}

function Assert-OwnedUninstallPath([string]$Recorded, [string]$Expected) {
    if (-not $Recorded -or -not [System.IO.Path]::IsPathRooted($Recorded)) {
        throw "Refusing to remove an invalid installer ownership path: $Recorded"
    }
    $recordedPath = [System.IO.Path]::GetFullPath($Recorded).TrimEnd("\")
    $expectedPath = [System.IO.Path]::GetFullPath($Expected).TrimEnd("\")
    if (-not [string]::Equals($recordedPath, $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside installer ownership: $Recorded (expected $Expected)"
    }
}

if ($Uninstall) {
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw "No installer ownership record exists at $markerPath. Nothing was removed."
    }
    $marker = $existingMarker
    # Validate the entire record before deleting anything or changing user settings.
    if (-not $marker.repo_root -or -not [System.IO.Path]::IsPathRooted([string]$marker.repo_root)) {
        throw "Refusing to remove an environment with an invalid installer ownership root."
    }
    Assert-OwnedUninstallPath ([string]$marker.venv) (Join-Path $marker.repo_root ".venv")
    Assert-OwnedUninstallPath ([string]$marker.shim) $shim
    Assert-OwnedUninstallPath ([string]$marker.shim_dir) $shimDir
    Assert-OwnedUninstallPath ([string]$marker.workspace) $workspace
    if ($marker.PSObject.Properties.Name -contains "launcher") {
        Assert-OwnedUninstallPath ([string]$marker.launcher) $launcher
    }
    Write-Step "Removing installer-owned virtual environment and shim"
    if (Test-Path -LiteralPath $marker.venv) {
        Remove-Item -LiteralPath $marker.venv -Recurse -Force
    }
    if (Test-Path -LiteralPath $marker.shim) {
        Remove-Item -LiteralPath $marker.shim -Force
    }
    if (($marker.PSObject.Properties.Name -contains "launcher") -and
        (Test-Path -LiteralPath $launcher)) {
        Remove-Item -LiteralPath $launcher -Force
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
        if ($ownedWorkspace -and (Test-Path -LiteralPath $ownedWorkspace)) {
            Remove-Item -LiteralPath $ownedWorkspace -Recurse -Force
            Write-Ok "Removed workspace data: $ownedWorkspace"
        }
    } else {
        Write-Ok "Preserved workspace data: $ownedWorkspace"
    }
    Remove-Item -LiteralPath $markerPath -Force
    if ((Test-Path -LiteralPath $shimDir) -and -not (Get-ChildItem -LiteralPath $shimDir -Force)) {
        Remove-Item -LiteralPath $shimDir -Force
    }
    Write-Ok "Uninstall complete. Open a new terminal to refresh PATH."
    exit 0
}

if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) {
    throw "RepoRoot does not exist: $RepoRoot"
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if ($Editable -and $Package) {
    Fail-Adaf -Code "INSTALLER_ARGUMENT" -Message "-Editable cannot be combined with -Package." -Remediation "Use -Package for an approved artifact, or -Editable for a source checkout."
}
if ($FindLinks) {
    if (-not (Test-Path -LiteralPath $FindLinks -PathType Container)) {
        Fail-Adaf -Code "INSTALLER_ARGUMENT" -Message "Wheelhouse directory does not exist: $FindLinks" -Remediation "Pass -FindLinks with an existing complete approved wheelhouse directory."
    }
    $FindLinks = (Resolve-Path -LiteralPath $FindLinks).Path
}
if (-not $Package -and -not (Test-Path -LiteralPath (Join-Path $RepoRoot "pyproject.toml"))) {
    throw "RepoRoot does not look like ADAF-ATTACK: $RepoRoot"
}
if ((Test-Path -LiteralPath $shim -PathType Leaf) -and -not $existingMarker) {
    throw "Refusing to overwrite unowned shim: $shim. Move it or remove it explicitly."
}
if ((Test-Path -LiteralPath $launcher) -and
    (-not $existingMarker -or $existingMarker.launcher -ne $launcher)) {
    throw "Refusing to overwrite unowned launcher: $launcher. Move it or remove it explicitly."
}

$pythonCommand = $Python.Trim()
$pythonPrefix = @()
if ($pythonCommand -match "^(py(?:\.exe)?)\s+(.+)$") {
    $pythonCommand = $Matches[1]
    $pythonPrefix = @($Matches[2].Split(" ", [StringSplitOptions]::RemoveEmptyEntries))
}
if (Test-Path -LiteralPath $pythonCommand -PathType Leaf) {
    $pythonCommand = (Resolve-Path -LiteralPath $pythonCommand).Path
    $resolvedPython = Get-Item -LiteralPath $pythonCommand
} else {
    $resolvedPython = Get-Command $pythonCommand -ErrorAction SilentlyContinue
}
if (-not $resolvedPython) {
    Fail-Adaf -Code "PYTHON_UNSUPPORTED" -Message "Python command not found: $pythonCommand." -Remediation "Install Python 3.11-3.14 or pass -Python with a full path, then retry."
}
if ($resolvedPython.Source) {
    $pythonCommand = $resolvedPython.Source
}
if ((Split-Path $pythonCommand -Leaf) -match "^py(?:\.exe)?$" -and $pythonPrefix.Count -eq 0) {
    $pythonPrefix = @("-$PythonVersion")
}

Write-Step "Validating Python 3.11 through 3.14"
$probeArgs = @($pythonPrefix) + @(
    "-c",
    "import json, sys; print(json.dumps({'version': f'{sys.version_info.major}.{sys.version_info.minor}', 'executable': sys.executable}))"
)
$probeOutput = & $pythonCommand @probeArgs
if ($LASTEXITCODE -ne 0) {
    throw "Python probe failed with exit code $LASTEXITCODE`: $pythonCommand $($pythonPrefix -join ' ')"
}
$probe = [string]($probeOutput | Select-Object -Last 1)
try { $probeParts = $probe.Trim() | ConvertFrom-Json } catch {
    throw "Could not parse Python version and executable from: $probe"
}
if (-not $probeParts.version -or -not $probeParts.executable) {
    throw "Could not parse Python version and executable from: $probe"
}
$detectedVersion = [Version]$probeParts.version
if ($detectedVersion -lt $minimumPython -or $detectedVersion -ge $maximumPython) {
    Fail-Adaf -Code "PYTHON_UNSUPPORTED" -Message "Python $detectedVersion is unsupported. ADAF-ATTACK requires Python 3.11 through 3.14." -Remediation "Install Python 3.11-3.14 or pass -Python with a supported interpreter, then retry."
}
$pythonExe = [string]$probeParts.executable
Write-Ok "Using Python $detectedVersion at $pythonExe"

$venv = Join-Path $RepoRoot ".venv"
$venvPython = Join-Path $venv "Scripts\python.exe"
if ((Test-Path -LiteralPath $venv) -and -not $existingMarker) {
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
    $ownership = @{
        repo_root = $RepoRoot
        venv = $venv
        shim = $shim
        shim_dir = $shimDir
        launcher = $launcher
        path_added = $false
        workspace = $workspace
        previous_workspace = [Environment]::GetEnvironmentVariable(
            "ADAF_ATTACK_WORKSPACE",
            "User"
        )
        install_complete = $false
    }
    Write-AdafOwnership $ownership $markerPath
    $existingMarker = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8 | ConvertFrom-Json
}
Write-Step "Creating or refreshing virtual environment at $venv"
if (-not (Test-Path -LiteralPath $venvPython)) {
    Invoke-Native $pythonExe @("-m", "venv", $venv)
} else {
    $selectedBaseJson = & $pythonExe -c "import json, os, sys; print(json.dumps(os.path.normcase(os.path.realpath(sys.base_prefix))))"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not identify the selected Python base interpreter."
    }
    $existingBaseJson = & $venvPython -c "import json, os, sys; print(json.dumps(os.path.normcase(os.path.realpath(sys.base_prefix))))"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not identify the existing virtual environment interpreter."
    }
    $selectedBase = $selectedBaseJson | ConvertFrom-Json
    $existingBase = $existingBaseJson | ConvertFrom-Json
    if (-not [string]::Equals(
        ([string]$selectedBase).Trim(),
        ([string]$existingBase).Trim(),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Existing $venv uses $existingBase, not selected interpreter $selectedBase. Uninstall first or select the matching Python."
    }
}
if ($Package) {
    $installTarget = (Resolve-Path -LiteralPath $Package).Path
    $verifyScript = Join-Path $PSScriptRoot "verify_install_artifact.py"
    $verifyArgs = @($verifyScript, "--artifact", $installTarget)
    if ($Manifest) {
        $verifyArgs += @("--manifest", (Resolve-Path -LiteralPath $Manifest).Path)
    }
    if ($Sha256) {
        $verifyArgs += @("--sha256", $Sha256)
    }
    Write-Step "Verifying package digest"
    Invoke-Native $pythonExe $verifyArgs
} else {
    $installTarget = $RepoRoot
}
$installTarget = ([System.Uri]$installTarget).AbsoluteUri
$projectRequirement = "adaf-attack"
if ($Extras -ne "base") { $projectRequirement = "adaf-attack[$Extras]" }
if ($Editable) {
    $installTarget = "$installTarget#egg=$projectRequirement"
} else {
    $installTarget = "$projectRequirement @ $installTarget"
}
$installArgs = @("-m", "pip", "install", "--upgrade")
if ($FindLinks) {
    $installArgs += @("--no-index", "--find-links", $FindLinks)
}
if ($Editable) {
    $installArgs += "--editable"
}
$installArgs += $installTarget
Write-Step "Installing $installTarget"
Invoke-Native $venvPython $installArgs
Invoke-Native $venvPython @("-m", "pip", "check")

$scriptsAdaf = Join-Path $venv "Scripts\adaf-attack.exe"
if (-not (Test-Path -LiteralPath $scriptsAdaf -PathType Leaf)) {
    Fail-Adaf -Code "PATH_NOT_FOUND" -Message "Installation completed without the expected console entry point: $scriptsAdaf" -Remediation "Inspect the venv Scripts directory, open a new terminal, or invoke the venv adaf-attack.exe directly."
}

Write-AdafLauncher $scriptsAdaf $shimDir

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

$ownership = @{
    repo_root = $RepoRoot
    venv = $venv
    shim = $shim
    shim_dir = $shimDir
    launcher = $launcher
    path_added = $pathAdded
    workspace = $workspace
    previous_workspace = $previousWorkspace
    install_complete = $true
}
Write-AdafOwnership $ownership $markerPath

if (-not $SkipCompletion) {
    Write-Step "Installing PowerShell completion"
    & $scriptsAdaf --install-completion powershell
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Completion installation failed with exit code $LASTEXITCODE. Run 'adaf-attack --install-completion powershell' after opening a new terminal."
    }
}

Write-Ok "Install complete."
Write-Host "  Activate now: $venv\Scripts\Activate.ps1"
Write-Host "  Verify:        adaf-attack doctor --profile user-readiness"
Write-Host "  Next:          adaf-attack guide"
Write-Host "  Workspace:     $workspace"
Write-Host "  Uninstall:     .\scripts\Install-AdafAttack.ps1 -Uninstall"
