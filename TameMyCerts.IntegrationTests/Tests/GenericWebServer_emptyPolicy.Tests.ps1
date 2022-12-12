BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

}

Describe 'GenericWebServer_emptyPolicy.Tests' {

    It 'Given a request is not compliant, no certificate is issued (RDN type not defined)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -KeyLength 2048
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer_emptyPolicy"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERT_E_INVALID_NAME
    }
}