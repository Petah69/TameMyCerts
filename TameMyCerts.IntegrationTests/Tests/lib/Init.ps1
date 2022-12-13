Function Test-AdcsServiceAvailability {

    [cmdletbinding()]
    param()

    New-Variable -Option Constant -Name CC_LOCALCONFIG -Value 0x00000003
    New-Variable -Option Constant -Name CR_PROP_CANAME -Value 0x00000006
    New-Variable -Option Constant -Name PROPTYPE_STRING -Value 4

    $CertConfig = New-Object -ComObject CertificateAuthority.Config
    $ConfigString = $CertConfig.GetConfig($CC_LOCALCONFIG)
    $CertAdmin = New-Object -ComObject CertificateAuthority.Admin.1

    Try {
        [void]($CertAdmin.GetCAProperty($ConfigString, $CR_PROP_CANAME, 0, $PROPTYPE_STRING,0))
        Return $True
    }
    Catch {
        Return $False
    }

}

$TestStartTime = Get-Date

Import-Module -Name PSCertificateEnrollment -MinimumVersion "1.0.7" -ErrorAction Stop

$CaName = "TEST-CA"
$DomainName = "tamemycerts-tests.local"
$ConfigString = "$($env:ComputerName).$DomainName\$CaName"

New-Variable -Option Constant -Name WinError -Value @{
    ERROR_SUCCESS = 0x0
    ERROR_INVALID_TIME = 0x8007076d
    NTE_FAIL = 0x80090020
    CERTSRV_E_TEMPLATE_DENIED = 0x80094012
    CERTSRV_E_BAD_REQUESTSUBJECT = 0x80094001
    CERTSRV_E_UNSUPPORTED_CERT_TYPE = 0x80094800
    CERTSRV_E_KEY_LENGTH = 0x80094811
    CERT_E_INVALID_NAME = 0x800b0114
}

New-Variable -Option Constant -Name CertCli -Value @{
    CR_DISP_INCOMPLETE = 0
    CR_DISP_ERROR = 1
    CR_DISP_DENIED = 2
    CR_DISP_ISSUED = 3
    CR_DISP_ISSUED_OUT_OF_BAND = 4
    CR_DISP_UNDER_SUBMISSION = 5
    CR_DISP_REVOKED = 6
}

New-Variable -Option Constant -Name EditFlag -Value @{
    EDITF_ATTRIBUTEENDDATE = 0x20
    EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x40000
}