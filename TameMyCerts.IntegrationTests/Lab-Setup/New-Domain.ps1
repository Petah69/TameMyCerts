[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $DomainName = "tamemycerts-tests.local",

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $DomainNetbiosName = "TAMEMYCERTS",

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $FunctionalLevel = "WinThreshold",

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Password = "P@ssw0rd"
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

# TODO: Maybe we want to convert a DHCP address into a fixed one here

Install-WindowsFeature `
    -Name AD-Domain-Services `
    -IncludeAllSubFeature `
    -IncludeManagementTools

$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force

$ForestProperties = @{

    DomainName = $DomainName
    DomainNetbiosName = $DomainNetbiosName
    SafeModeAdministratorPassword = $SecurePassword
    ForestMode = $FunctionalLevel
    DomainMode = $FunctionalLevel
    CreateDnsDelegation = $False
    InstallDns = $True
    DatabasePath = "$env:SystemRoot\NTDS"
    LogPath = "$env:SystemRoot\NTDS"
    SysvolPath = "$env:SystemRoot\SYSVOL"
    NoRebootOnCompletion = $False
    Force = $True

}

Import-Module ADDSDeployment

Install-ADDSForest @ForestProperties

# TODO: DC Deployment is slow, probably due to DNS settings
# TODO: How can we convert the original DNS Settins to a forwarder after the domain has been set up (so that we can download from the PS gallery)