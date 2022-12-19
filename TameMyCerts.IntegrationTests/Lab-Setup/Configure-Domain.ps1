<#
    .SYNOPSIS
    Populates the Active Directory Domain with test data.
#>

#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $DomainName = "DC=tamemycerts-tests,DC=local"
)

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

New-ADOrganizationalUnit `
    -Name "TameMyCerts Users" `
    -Path $DomainName `
    -ProtectedFromAccidentalDeletion $True

# The user doesnt really matter as this is a throw-away lab
Add-Type -AssemblyName System.Web
$Password = [System.Web.Security.Membership]::GeneratePassword(16,0) | ConvertTo-SecureString -AsPlainText -Force

(1..5) | ForEach-Object -Process {

    New-ADUser `
        -SamAccountName "TestUser$($_)" `
        -UserPrincipalName "testuser$($_)@tamemycerts-tests.local" `
        -Name "Test User $($_)" `
        -GivenName "Test" `
        -Surname "User $($_)" `
        -Path "OU=TameMyCerts Users,$DomainName" `
        -Enabled $True `
        -AccountPassword $Password

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

"co", "company", "department", "departmentNumber", "description", "displayName", "division", "employeeID", "employeeNumber", "employeeType", "facsimileTelephoneNumber", "gecos", 
"homePhone", "homePostalAddress", "info", "l", "mail", "middleName", "mobile",  "otherMailbox", "otherMobile", "otherPager", "otherTelephone", "pager", "personalTitle", 
"postalAddress", "postalCode", "postOfficeBox", "st", "street", "streetAddress", "telephoneNumber", "title" | ForEach-Object -Process {

    Set-ADUser -Identity TestUser1 -Add @{$_ = "v-$_"}

}

Set-ADUser -Identity TestUser1 -Add @{c = "DE"}