BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

}

Describe 'GenericWebServer_emptyPolicy_Audit.Tests' {

    It 'Given a request is not compliant but policy is in Audit mode, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -KeyLength 2048
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer_emptyPolicy_Audit"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCode | Should -Be $WinError.ERROR_SUCCESS
    }
}