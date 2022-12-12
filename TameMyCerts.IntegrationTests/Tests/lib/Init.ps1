$TestStartTime = Get-Date

Import-Module -Name PSCertificateEnrollment -MinimumVersion "1.0.6"

$CaName = "TEST-CA"
$DomainName = "tamemycerts-tests.local"
$ConfigString = "$($env:ComputerName).$DomainName\$CaName"

New-Variable -Option Constant -Name WinError -Value @{
    ERROR_SUCCESS = "0x0"
    ERROR_INVALID_TIME = "0x00001901"
    NTE_FAIL = "0x80090020"
    CERTSRV_E_TEMPLATE_DENIED = "0x80094012"
    CERTSRV_E_BAD_REQUESTSUBJECT = "0x80094001"
    CERTSRV_E_UNSUPPORTED_CERT_TYPE = "0x80094800"
    CERTSRV_E_KEY_LENGTH = "0x80094811"
    CERT_E_INVALID_NAME = "0x800b0114"
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