<#
    .SYNOPSIS
    Installs all required dependencies we need for testing.
#>
[CmdletBinding()]
param()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

Install-Module -Name "PSCertificateEnrollment" -Force
Install-Module -Name "Pester" -Force -SkipPublisherCheck