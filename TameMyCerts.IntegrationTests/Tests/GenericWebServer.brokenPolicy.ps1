BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

}

Describe 'GenericWebServer.Tests' {

    It 'Given a request is compliant, a certificate is issued (commonName only)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCode | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given a request is compliant, a certificate is issued (commonName and iPAddress)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -IP "192.168.101.1"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCode | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given a request is compliant, a certificate is issued (commonName and dNSName)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -Dns "www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCode | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given a request is not compliant, no certificate is issued (key too small)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -KeyLength 1024
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
    }

    It 'Given a request is not compliant, no certificate is issued (key too large)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -KeyLength 4096
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
    }

    It 'Given a request is not compliant, no certificate is issued (key is not RSA)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -KeyAlgorithm ECDSA_P256
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
    }


    It 'Given a request is not compliant, no certificate is issued (no commonName)' {

        $Csr = New-CertificateRequest -Dns "www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (countryName invalid)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local,C=UK"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (commonName not allowed)' {

        $Csr = New-CertificateRequest -Subject "CN=www.sparkasse-bueckeburg.de"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (commonName forbidden)' {

        $Csr = New-CertificateRequest -Subject "CN=wwpornw.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (iPAddress not allowed)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -IP "192.168.0.1"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (dNSName not allowed)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -Dns "www.sparkasse-bueckeburg.de"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (userPrincipalName not defined)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -Upn "Administrator@intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (commonName too short)' {

        $Csr = New-CertificateRequest -Subject "CN=,C=DE"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCode | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a denied request is resubmitted by an admin, it is issued' {

        $Csr = New-CertificateRequest -Subject "CN=,C=DE"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCode | Should -Be $WinError.CERT_E_INVALID_NAME
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCode | Should -Be $WinError.ERROR_SUCCESS
    }
}