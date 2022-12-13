BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

}

Describe 'GenericWebServer_ECDSA.Tests' {

    It 'Given a request is not compliant, no certificate is issued (key is not ECC)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer_ECDSA"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
    }

}