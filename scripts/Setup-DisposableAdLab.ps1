#requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates safe, disposable ADAF-ATTACK baseline accounts in an AD lab.

.DESCRIPTION
    Run only on a freshly created, isolated lab domain controller. This script
    creates test-only users, a group, and a harmless HTTP SPN. It refuses names
    that do not look like a lab domain and never changes production objects.
#>
[CmdletBinding()]
param(
    [string]$DomainDnsName = "lab.example",
    [string]$NetbiosName = "LAB",
    [string]$LabOuName = "ADAF-Lab"
)

$ErrorActionPreference = "Stop"
if ($DomainDnsName -notmatch "(^|\.)lab(\.|$)|\.test$") {
    throw "Refusing non-lab domain '$DomainDnsName'. Use a disposable .lab or .test domain."
}
Import-Module ActiveDirectory
$domain = Get-ADDomain
if ($domain.DNSRoot -ne $DomainDnsName) {
    throw "This host belongs to '$($domain.DNSRoot)', not '$DomainDnsName'. Run on the intended lab DC."
}

$password = Read-Host "Enter a temporary password for ADAF lab users" -AsSecureString
$baseDn = $domain.DistinguishedName
$ou = Get-ADOrganizationalUnit -LDAPFilter "(&(objectClass=organizationalUnit)(ou=$LabOuName))" -SearchBase $baseDn -ErrorAction SilentlyContinue
if (-not $ou) {
    $ou = New-ADOrganizationalUnit -Name $LabOuName -Path $baseDn -Description "Disposable ADAF-ATTACK validation fixtures"
}
$path = $ou.DistinguishedName

function Ensure-LabUser([string]$Name, [string]$Sam, [string]$Description) {
    $user = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue
    if (-not $user) {
        $user = New-ADUser -Name $Name -SamAccountName $Sam -UserPrincipalName "$Sam@$DomainDnsName" `
            -AccountPassword $password -Enabled $true -Path $path -Description $Description -PassThru
    }
    return $user
}

$operator = Ensure-LabUser "ADAF Operator" "adaf-operator" "Disposable read-only validation account"
$service = Ensure-LabUser "ADAF Service" "adaf-service" "Disposable SPN fixture account"
$group = Get-ADGroup -Filter "SamAccountName -eq 'ADAF-Lab-Readers'" -ErrorAction SilentlyContinue
if (-not $group) {
    $group = New-ADGroup -Name "ADAF-Lab-Readers" -SamAccountName "ADAF-Lab-Readers" `
        -GroupScope Global -GroupCategory Security -Path $path -Description "Disposable ADAF validation group"
}
Add-ADGroupMember -Identity $group -Members $operator -ErrorAction SilentlyContinue
Set-ADUser -Identity $service -ServicePrincipalNames @{Add="HTTP/adaf-web.$DomainDnsName"}

Write-Host "Disposable ADAF lab fixtures are ready." -ForegroundColor Green
Write-Host "Domain: $DomainDnsName"
Write-Host "Operator: $NetbiosName\adaf-operator"
Write-Host "SPN: HTTP/adaf-web.$DomainDnsName"
Write-Host "Reset the VM snapshot when the validation is complete."
