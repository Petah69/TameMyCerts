BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"
}

Describe 'User_Offline_DsMapping.Tests' {

    It 'Given a user is not found, a certificate is not issued' {

        $Csr = New-CertificateRequest -Upn "NonExistingUser@tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "User_Offline_DsMapping"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }

    It 'Given a user is found, a certificate is issued' {

        $Csr = New-CertificateRequest -Upn "TestUser1@tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "User_Offline_DsMapping"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCode | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given a user is found but disabled, a certificate is not issued' {

        $Csr = New-CertificateRequest -Upn "TestUser3@tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "User_Offline_DsMapping"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERTSRV_E_TEMPLATE_DENIED
    }



}