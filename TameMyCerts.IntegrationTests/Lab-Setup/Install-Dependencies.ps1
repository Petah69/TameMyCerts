<#
    .SYNOPSIS
    Installs all required dependencies we need for testing.
#>

#Requires -Modules PowerShellGet

[CmdletBinding()]
param()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

Install-Module -Name "PSCertificateEnrollment" -MinimumVersion 1.0.7 -Force
Install-Module -Name "Pester" -Force -SkipPublisherCheck