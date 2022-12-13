<#
    .SYNOPSIS
    Populates the Active Directory Domain with test data.
#>

#Requires -Modules ActiveDirectory

[CmdletBinding()]
param()

$DomainName = "DC=tamemycerts-tests,DC=local"

New-ADOrganizationalUnit `
    -Name "TameMyCerts Users" `
    -Path $DomainName `
    -ProtectedFromAccidentalDeletion $True

$SecurePassword = "P@ssw0rd" | ConvertTo-SecureString -AsPlainText -Force

(1..5) | ForEach-Object -Process {

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