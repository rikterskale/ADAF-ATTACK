# ADAF-ATTACK PowerShell helpers
# Import-Module .\scripts\AdafAttack.psm1

function Get-AdafAttackRepoRoot {
    $root = $PSScriptRoot
    if (Test-Path (Join-Path $root "..\pyproject.toml")) {
        return (Resolve-Path (Join-Path $root "..")).Path
    }
    return (Get-Location).Path
}

function Get-AdafAttackPython {
    $repo = Get-AdafAttackRepoRoot
    $venvPy = Join-Path $repo ".venv\Scripts\python.exe"
    if (Test-Path $venvPy) { return $venvPy }
    $cmd = Get-Command adaf-attack -ErrorAction SilentlyContinue
    if ($cmd) { return $null }  # use shim on PATH
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) { return $py.Source }
    throw "adaf-attack Python not found. Run Install-AdafAttack.ps1 first."
}

function Invoke-AdafAttack {
    <#
    .SYNOPSIS
      Run adaf-attack with the repo venv or PATH shim.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )
    $py = Get-AdafAttackPython
    if ($py) {
        & $py -m adaf_attack.cli @Args
    } else {
        & adaf-attack @Args
    }
}

function Invoke-AdafDoctor { Invoke-AdafAttack doctor }
function Invoke-AdafPaths  { Invoke-AdafAttack paths }
function Invoke-AdafList   { Invoke-AdafAttack list-capabilities }

function Invoke-AdafRun {
    <#
    .SYNOPSIS
      Wrapper for `adaf-attack run`.

    .EXAMPLE
      Invoke-AdafRun -Capability ldap-enum -Domain corp.local -DcIp 10.0.0.10 -Username alice -Password 'P@ss'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Capability,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$DcIp,
        [string]$Username,
        [string]$Password,
        [string]$Hashes,
        [switch]$Ldaps,
        [switch]$Force,
        [switch]$IncludeSecrets,
        [string]$Workspace
    )
    $argList = @("run", $Capability, "-d", $Domain, "--dc-ip", $DcIp)
    if ($Username) { $argList += @("-u", $Username) }
    if ($Password) { $argList += @("-p", $Password) }
    if ($Hashes)   { $argList += @("--hashes", $Hashes) }
    if ($Ldaps)    { $argList += "--ldaps" }
    if ($Force)    { $argList += "--force" }
    if ($IncludeSecrets) { $argList += "--include-secrets" }
    if ($Workspace) { $argList += @("--workspace", $Workspace) }
    Invoke-AdafAttack @argList
}

function Get-AdafWorkspace {
    $envWs = $env:ADAF_ATTACK_WORKSPACE
    if ($envWs) { return $envWs }
    return (Join-Path $env:LOCALAPPDATA "adaf-attack\workspaces")
}

function Get-AdafSessions {
    $ws = Get-AdafWorkspace
    if (-not (Test-Path $ws)) { return @() }
    Get-ChildItem -Path $ws -Directory | Sort-Object Name -Descending
}

Export-ModuleMember -Function @(
    "Invoke-AdafAttack",
    "Invoke-AdafDoctor",
    "Invoke-AdafPaths",
    "Invoke-AdafList",
    "Invoke-AdafRun",
    "Get-AdafWorkspace",
    "Get-AdafSessions"
)
