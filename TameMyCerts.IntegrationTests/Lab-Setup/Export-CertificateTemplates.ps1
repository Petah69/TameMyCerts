<#
    .SYNOPSIS
    Exports all certificate templates bound to our test certification authority to LDIF files.
#>

#Requires -Modules ADCSAdministration

[cmdletbinding()]
param (
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ConfigNC = "CN=Configuration,DC=tamemycerts-tests,DC=local"
)

Get-CATemplate | ForEach-Object -Process {

    $FilePath = "$($_.Name).ldf"

    Remove-Item -Path $FilePath -ErrorAction SilentlyContinue

    $Arguments = @(
        "-f"
        "$FilePath"
        "-d"
        "CN=$($_.Name),CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
        "-p"
        "Base"
        "-o"
        "dSCorePropagationData,whenChanged,whenCreated,uSNCreated,uSNChanged,objectGuid,msPKI-Cert-Template-OID"
    )
    [void](& ldifde $Arguments)
}