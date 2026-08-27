[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PytestArgs
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$runtimeTemp = Join-Path $repoRoot ".pytest-runtime"
$pytestBase = Join-Path $repoRoot ".pytest-local"
$localAppData = Join-Path $runtimeTemp "AppData\Local"
$workspace = Join-Path $runtimeTemp "workspaces"

# Keep pytest, ADAF-ATTACK config, workspace, and Python temporary files
# inside the repository. This avoids locked-down or redirected Windows paths
# such as pytest-of-USER and %LOCALAPPDATA%.
# If a prior run left .pytest-local locked (common on Windows), fall back to a
# unique basetemp under the redirected TEMP so coverage gates can still run.
New-Item -ItemType Directory -Force -Path `
    $runtimeTemp, $localAppData, $workspace | Out-Null
try {
    New-Item -ItemType Directory -Force -Path $pytestBase | Out-Null
    $probe = Join-Path $pytestBase (".write-probe-" + [guid]::NewGuid().ToString("N"))
    [System.IO.File]::WriteAllText($probe, "ok")
    Remove-Item -Force $probe
} catch {
    $pytestBase = Join-Path $runtimeTemp ("basetemp-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $pytestBase | Out-Null
    Write-Warning "Repo .pytest-local is not writable; using $pytestBase"
}
$env:TEMP = $runtimeTemp
$env:TMP = $runtimeTemp
$env:LOCALAPPDATA = $localAppData
$env:ADAF_ATTACK_WORKSPACE = $workspace

$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    $python = "python"
}

& $python -m pytest --basetemp $pytestBase @PytestArgs
exit $LASTEXITCODE
