BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    Restart-Service -Name CertSvc

    # TODO: Replace with a "wait for CertSrv.Request is up" test
    Start-Sleep -Seconds 5
}

Describe 'TameMyCerts.Tests' {

    It 'Given the module is installed, it is the active one' {

        $RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName\PolicyModules"
        $Active = (Get-ItemProperty -Path $RegistryRoot -Name Active).Active
        $Active | Should -Be "TameMyCerts.Policy"
    }

    It 'Given the module is installed, it is successfully loaded' {

        $Events = Get-WinEvent -FilterHashtable @{
            Logname='Application'; ProviderName='TameMyCerts'; Id=1; StartTime=$TestStartTime
        } -ErrorAction SilentlyContinue

        $Events.Count | Should -Be 1
    }
}

<#
Audit Mode logs when denied
Audit Mode does no log when approved
Certificate content doesnt get modified when Audit mode is enabled
Certificate content gets modified when Audit mode is not enabled
Certificate content gets modified for a resubmitted request
Invalid start/end dates are not relevant when a denied request is resubmitted by an administrator
StartDate is not applied (if flag is not set)
AD Attributes are correctly added to Subject DN
Request a certificate from an allowed process name gets permitted
Request a certificate from a disallowed process name gets denied
Request a certificate from an allowed CSP gets permitted
Request a certificate from a disallowed CSP gets denied
Request with "san" Attribute is denied if flag is set
Request with "san" Attribute is allowed if flag is not set
Request with RSA key gets denied when policy requires ECC key

Object is found when SearchRoot is specified
Object is found when SearchRoot is not specified (using GC)
Attributes are mapped when DS mapping is enabled

How is (subject modification) behavior with REBUILD_MODIFIED_SUBJECT_ONLY enabled?
What about the Events generated? (do we analyze and compare them as well)
#>