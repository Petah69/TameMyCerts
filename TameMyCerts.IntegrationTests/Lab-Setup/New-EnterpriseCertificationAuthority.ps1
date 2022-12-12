<#
    .SYNOPSIS
    Deploys the Enterprise certification authority we will run our integration tests against.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CaName = "TEST-CA"
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

[void](Remove-Item -Path "$($env:SystemRoot)\capolicy.inf" -Force -ErrorAction SilentlyContinue)
        
[System.IO.File]::WriteAllText(
    "$($env:SystemRoot)\capolicy.inf",
    (Get-Content -Path "$(Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)\capolicy.inf" -Encoding UTF8 -Raw),
    [System.Text.Encoding]::GetEncoding('iso-8859-1')
    )

$CaDbDir = "$($env:SystemRoot)\System32\CertLog"
$CaDbLogDir = "$($env:SystemRoot)\System32\CertLog"

[void](New-Item -Path $CaDbDir -ItemType Directory -ErrorAction SilentlyContinue)
[void](New-Item -Path $CaDbLogDir -ItemType Directory -ErrorAction SilentlyContinue)

$CaDeploymentParameters = @{
    CACommonName = $CaName
    DatabaseDirectory = $CaDbDir
    LogDirectory = $CaDbLogDir
    HashAlgorithm = "SHA256"
    CryptoProviderName = "RSA#Microsoft Software Key Storage Provider"
    OverwriteExistingKey = $True
    OverwriteExistingDatabase = $True
    Force = $True
    CAType = "EnterpriseRootCA"
    KeyLength = 4096
    ValidityPeriod = "Years"
    ValidityPeriodUnits = 50
}

Install-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools

Install-AdcsCertificationAuthority @CaDeploymentParameters

[void](& certutil -setreg CA\LogLevel 4)
[void](& certutil -setreg CA\ValidityPeriodUnits 50)
[void](& certutil -setreg Policy\EditFlags +EDITF_ATTRIBUTEENDDATE)

# Though this is insecure, we enable the flag in the lab to test the logic inside TameMyCerts
[void](& certutil -setreg Policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2)

Restart-Service -Name CertSvc