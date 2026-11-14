function Import-RacAllowList {
    <#
    .SYNOPSIS
        Loads and validates an allow-list (.json or .csv) without running a scan.

    .DESCRIPTION
        Use this to check an allow-list before deploying it. Problems (missing
        approver, unknown indicator names, bad expiry dates, an Agent '*' entry with
        no scope) are returned as warnings.

    .EXAMPLE
        Import-RacAllowList -Path .\allowlist.json | Select-Object -ExpandProperty Warnings
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $signatures = Import-RacSignatureFile -Path (Join-Path -Path $script:RacModuleRoot -ChildPath 'Data/signatures.json')
    $result = Read-RacAllowListFile -Path $Path -KnownIndicators @($signatures._IndicatorWeights.Keys)
    foreach ($w in $result.Warnings) { Write-Warning $w }
    return $result
}
