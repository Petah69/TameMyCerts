BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    $CertificateTemplate = "User_Offline_Sid_Add"

    Import-Module -Name ActiveDirectory
}

Describe 'User_Offline_Sid_Add.Tests' {

    It 'Given a SID extension is requested, a certificate with SID extension is issued' {

        $MySelf = Get-ADUser -Identity $env:Username

        $Csr = New-CertificateRequest -Subject "CN=$($MySelf.Name)"
        $Result1 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate $CertificateTemplate
        $Result2 = $Csr | Get-IssuedCertificate -ConfigString $ConfigString -CertificateTemplate "User_Online" # For comparison

        $SidExtension1 = [Convert]::ToBase64String(($Result1.Certificate.Extensions | Where-Object {$_.Oid.Value -eq $Oid.szOID_DS_CA_SECURITY_EXT }).RawData)
        $SidExtension2 = [Convert]::ToBase64String(($Result2.Certificate.Extensions | Where-Object {$_.Oid.Value -eq $Oid.szOID_DS_CA_SECURITY_EXT }).RawData)

        $Result1.Disposition | Should -Be $CertCli.CR_DISP_ISSUED
        $Result1.StatusCodeInt | Should -Be $WinError.ERROR_SUCCESS
        [bool]($Result1.Certificate.Extensions | Where-Object {$_.Oid.Value -eq $Oid.szOID_DS_CA_SECURITY_EXT }) | 
            Should -Be $True
        ($SidExtension1 -eq $SidExtension2) | Should -Be $True
            
    }

}