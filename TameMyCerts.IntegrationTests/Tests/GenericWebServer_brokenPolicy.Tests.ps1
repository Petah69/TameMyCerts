BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

}

Describe 'GenericWebServer_brokenPolicy.Tests' {

    It 'Given the policy file is broken, no certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -KeyLength 2048
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer_brokenPolicy"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.NTE_FAIL
    }
}