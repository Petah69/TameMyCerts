BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "Computer_Online_SubjectDN"
}

Describe 'Computer_Online_SubjectDN.Tests' {

    It 'Given a Subject RDN from DS mapping is enabled and not all attributes are populated, a certificate with desired content is issued' {

        $Csr = New-CertificateRequest -Subject "CN="
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate -MachineContext

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=$($env:COMPUTERNAME)$" # would be UPN
    }

}