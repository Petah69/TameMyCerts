BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

}

Describe 'GenericWebServer_noPolicy.Tests' {

    It 'Given no policy is defined, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.adcslabor.de"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer_noPolicy"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCode | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.adcslabor.de"
    }
}