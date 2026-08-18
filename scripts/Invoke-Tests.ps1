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
New-Item -ItemType Directory -Force -Path `
    $runtimeTemp, $pytestBase, $localAppData, $workspace | Out-Null
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
