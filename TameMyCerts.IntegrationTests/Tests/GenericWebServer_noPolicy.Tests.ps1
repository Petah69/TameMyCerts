BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

}

Describe 'GenericWebServer_noPolicy.Tests' {

    It 'Given no policy is defined, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer_noPolicy"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCode | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given no policy is defined, flag is enabled, and SAN extension is present, no certificate is issued' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:GenericWebServer_noPolicy","saN:upn=Administrator@tamemycerts-tests.local"
            # This also tests if request attributes are handled case-insensitive

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2 | Should -Be $EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2
        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.NTE_FAIL
    }

    It 'Given no policy is defined, flag is enabled, and StartDate extension is present, a certificate is issued with correct date' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $CultureInfo = 'en-US' -as [Globalization.CultureInfo]
        $NextYear = (Get-Date).year +1
        $DayOfWeek = (Get-Date -Year $NextYear -Month 1 -Day 1).ToString("ddd", $CultureInfo)

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:GenericWebServer_noPolicy","StartDate:$DayOfWeek, 1 Jan $NextYear 00:00:00 GMT"

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTEENDDATE | Should -Be $EditFlag.EDITF_ATTRIBUTEENDDATE
        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCode | Should -Be $WinError.ERROR_SUCCESS

        $Result.Certificate.NotBefore | Should -Be (Get-Date -Date "$NextYear-01-01 00:00:00Z")
    }
}