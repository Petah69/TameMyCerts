BeforeAll {

    . "C:\IntegrationTests\Tests\lib\Init.ps1"

    Restart-Service -Name CertSvc

    do {
        Start-Sleep -Seconds 1
    } while (-not (Test-AdcsServiceAvailability))
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
StartDate is not applied (if flag is not set)
AD Attributes are correctly added to Subject DN
Request a certificate from an allowed process name gets permitted
Request a certificate from a disallowed process name gets denied
Request a certificate from an allowed CSP gets permitted
Request a certificate from a disallowed CSP gets denied
SID Extension gets permitted
SID Extension gets denied
SID Extension gets removed
SID Extension gets added from AD
SAN gets built from Subject DN

How is (subject modification) behavior with REBUILD_MODIFIED_SUBJECT_ONLY enabled?
What about the Events generated? (do we analyze and compare them as well)
#>