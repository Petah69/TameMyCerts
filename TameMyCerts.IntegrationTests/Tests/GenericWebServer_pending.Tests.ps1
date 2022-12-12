BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"
}

Describe 'GenericWebServer_pending.Tests' {

    It 'Given a pending request is resubmitted by an admin, it is issued' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.adcslabor.de"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer_pending"

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_UNDER_SUBMISSION
        $Result1.StatusCode | Should -Be $WinError.ERROR_SUCCESS
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCode | Should -Be $WinError.ERROR_SUCCESS
        $Result2.Certificate.Subject | Should -Be "CN=www.intra.adcslabor.de"
    }

}