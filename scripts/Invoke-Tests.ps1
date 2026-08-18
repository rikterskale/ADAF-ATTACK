[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PytestArgs
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$runtimeTemp = Join-Path $repoRoot ".pytest-runtime"
$pytestBase = Join-Path $repoRoot ".pytest-local"

# Keep pytest and Python temporary files inside the repository. This avoids
# locked-down or redirected Windows %TEMP% locations such as pytest-of-USER.
New-Item -ItemType Directory -Force -Path $runtimeTemp, $pytestBase | Out-Null
$env:TEMP = $runtimeTemp
$env:TMP = $runtimeTemp

$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    $python = "python"
}

& $python -m pytest --basetemp $pytestBase @PytestArgs
exit $LASTEXITCODE
