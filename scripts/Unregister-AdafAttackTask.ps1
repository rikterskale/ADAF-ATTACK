[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TaskName
)
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Write-Host "Removed task $TaskName"
