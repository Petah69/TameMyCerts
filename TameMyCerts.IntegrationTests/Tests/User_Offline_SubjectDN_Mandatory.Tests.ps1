BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"
}

Describe 'User_Offline_SubjectDN_Mandatory.Tests' {

    It 'Given a Subject RDN from DS mapping is enabled and all mandatory attributes are populated, a certificate with desired content is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser1@tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "User_Offline_SubjectDN_Mandatory"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "E=v-mail, CN=v-displayName, OU=v-department, O=v-company, L=v-l, S=v-st, C=DE"
    }

    It 'Given a Subject RDN from DS mapping is enabled and not all mandatory attributes are populated, no certificate is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser2@tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "User_Offline_SubjectDN_Mandatory"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED

    }

}