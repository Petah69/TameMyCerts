BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

}

Describe 'GenericWebServer.Tests' {

    It 'Given a request is compliant, a certificate is issued (commonName only)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given a request is compliant, a certificate is issued (commonName and iPAddress)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -IP "192.168.101.1"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given a request is compliant, a certificate is issued (commonName and dNSName)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -Dns "www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        $Result.Certificate.Subject | Should -Be "CN=www.intra.tamemycerts-tests.local"
    }

    It 'Given a request is not compliant, no certificate is issued (key too small)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -KeyLength 1024
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
    }

    It 'Given a request is not compliant, no certificate is issued (key too large)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -KeyLength 4096
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
    }

    It 'Given a request is not compliant, no certificate is issued (key is not RSA)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -KeyAlgorithm ECDSA_P256
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERTSRV_E_KEY_LENGTH
    }


    It 'Given a request is not compliant, no certificate is issued (no commonName)' {

        $Csr = New-CertificateRequest -Dns "www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (countryName invalid)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local,C=UK"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (commonName not allowed)' {

        $Csr = New-CertificateRequest -Subject "CN=www.sparkasse-bueckeburg.de"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (commonName forbidden)' {

        $Csr = New-CertificateRequest -Subject "CN=wwpornw.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (iPAddress not allowed)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -IP "192.168.0.1"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (dNSName not allowed)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -Dns "www.sparkasse-bueckeburg.de"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (userPrincipalName not defined)' {

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local" -Upn "Administrator@intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a request is not compliant, no certificate is issued (commonName too short)' {

        $Csr = New-CertificateRequest -Subject "CN=,C=DE"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
    }

    It 'Given a denied request is resubmitted by an admin, a certificate is issued' {

        $Csr = New-CertificateRequest -Subject "CN=,C=DE"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "GenericWebServer"

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.CERT_E_INVALID_NAME
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }

    It 'Given flag is enabled, and SAN attribute is present, no certificate is issued' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:GenericWebServer","saN:upn=Administrator@tamemycerts-tests.local"
            # This also tests if request attributes are handled case-insensitive

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2 | Should -Be $EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2
        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.NTE_FAIL
    }

    It 'Given flag is enabled, and StartDate attribute is present, a certificate is issued with correct date' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $CultureInfo = 'en-US' -as [Globalization.CultureInfo]
        $NextYear = (Get-Date).year +1
        $DayOfWeek = (Get-Date -Year $NextYear -Month 1 -Day 1).ToString("ddd", $CultureInfo)

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:GenericWebServer","StartDate:$DayOfWeek, 1 Jan $NextYear 00:00:00 GMT"

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTEENDDATE | Should -Be $EditFlag.EDITF_ATTRIBUTEENDDATE
        $Result.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS

        $Result.Certificate.NotBefore | Should -Be (Get-Date -Date "$NextYear-01-01 00:00:00Z")
    }

    It 'Given flag is enabled, and StartDate extension is invalid, no certificate is issued' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:GenericWebServer","StartDate:Mon, 1 Dec 2022 00:00:00 GMT"

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTEENDDATE | Should -Be $EditFlag.EDITF_ATTRIBUTEENDDATE
        $Result.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result.StatusCodeInt | Should -Be $WinError.ERROR_INVALID_TIME
    }

    It 'Given a denied request due to invalid StartDate is resubmitted by an administrator, a certificate is issued' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules\TameMyCerts.Policy"
        $EditFlags = (Get-ItemProperty -Path $RegistryRoot -Name EditFlags).EditFlags

        $Csr = New-CertificateRequest -Subject "CN=www.intra.tamemycerts-tests.local"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString `
            -RequestAttributes "CertificateTemplate:GenericWebServer","StartDate:Mon, 1 Dec 2022 00:00:00 GMT"

        (& certutil -config $ConfigString -resubmit $Result1.RequestId)

        $Result2 = Get-IssuedCertificate -ConfigString $ConfigString -RequestId $Result1.RequestId

        $EditFlags -band $EditFlag.EDITF_ATTRIBUTEENDDATE | Should -Be $EditFlag.EDITF_ATTRIBUTEENDDATE
        $Result1.Disposition | Should -Be $CertCli.CR_DISP_DENIED
        $Result1.StatusCodeInt | Should -Be $WinError.ERROR_INVALID_TIME
        $Result2.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result2.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
    }
}