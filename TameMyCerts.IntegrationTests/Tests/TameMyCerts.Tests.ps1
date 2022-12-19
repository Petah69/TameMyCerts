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
DS mapping will probably fail for an online template using the built-in administrator account, as the userPrincipalName is not mandatory. Write a test for this and think about changing to sAMAccountName perhaps.

Request a certificate from an allowed process name gets permitted
Request a certificate from a disallowed process name gets denied
Request a certificate from an allowed CSP gets permitted
Request a certificate from a disallowed CSP gets denied

How is (subject modification) behavior with REBUILD_MODIFIED_SUBJECT_ONLY enabled?
What about the Events generated? (do we analyze and compare them as well)

Audit Mode logs when denied
Audit Mode does no log when approved
#>