<#
    .SYNOPSIS
    Populates the Active Directory Domain with test data.
#>

[CmdletBinding()]
param()

New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_2016 -Value 14393

If ([int](Get-WmiObject -Class Win32_OperatingSystem).BuildNumber -lt $BUILD_NUMBER_WINDOWS_2016) {
    Write-Error -Message "This must be run on Windows Server 2016 or newer! Aborting."
    Return 
}

If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error -Message "This must be run as Administrator! Aborting."
    Return
}

If (-not (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
    Write-Error "You must install the domain first!"
    Return
}

$DomainName = "DC=tamemycerts-tests,DC=local"

New-ADOrganizationalUnit `
    -Name "TameMyCerts Users" `
    -Path $DomainName `
    -ProtectedFromAccidentalDeletion $True

$SecurePassword = "P@ssw0rd" | ConvertTo-SecureString -AsPlainText -Force

(1..3) | ForEach-Object -Process {

    New-ADUser `
        -SamAccountName "TestUser$($_)" `
        -UserPrincipalName "testuser$($_)@tamemycerts-tests.local" `
        -Name "Test User $($_)" `
        -GivenName "Test" `
        -Surname "User $($_)" `
        -Path "OU=TameMyCerts Users,$DomainName" `
        -Enabled $True `
        -AccountPassword $SecurePassword

}

New-ADOrganizationalUnit `
    -Name "TameMyCerts Groups" `
    -Path $DomainName `
    -ProtectedFromAccidentalDeletion $True


"An allowed Group",
"A forbidden Group" | ForEach-Object -Process {

    New-ADGroup `
        -Name "$($_)" `
        -SamAccountName $($_).Replace(" ", "") `
        -GroupCategory Security `
        -GroupScope Global `
        -DisplayName $($_) `
        -Path "OU=TameMyCerts Groups,$DomainName" `
        -Description $($_)

}

Get-ADGroup -Identity "AnallowedGroup" | Add-ADGroupMember -Members "TestUser1"
Get-ADGroup -Identity "AnallowedGroup" | Add-ADGroupMember -Members "TestUser2"
Get-ADGroup -Identity "AforbiddenGroup" | Add-ADGroupMember -Members "TestUser2"
Disable-ADAccount -Identity "TestUser3"
Get-ADUser -Identity "TestUser4" | Move-ADObject -TargetPath "CN=Users,$DomainName"