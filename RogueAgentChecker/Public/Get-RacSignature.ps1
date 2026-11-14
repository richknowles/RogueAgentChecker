function Get-RacSignature {
    <#
    .SYNOPSIS
        Lists the agents Rogue Agent Checker knows how to recognize.

    .DESCRIPTION
        Shows each agent's id (use it in the allow-list's Agent field), name,
        vendor and kind. Use -Path to inspect a custom signature file.

    .EXAMPLE
        Get-RacSignature | Format-Table Id, Name, Kind
    #>
    [CmdletBinding()]
    param([string]$Path)

    if (-not $Path) { $Path = Join-Path -Path $script:RacModuleRoot -ChildPath 'Data/signatures.json' }
    $sig = Import-RacSignatureFile -Path $Path
    foreach ($a in $sig.agents) {
        [pscustomobject]@{
            Id     = $a.id
            Name   = $a.name
            Vendor = $a.vendor
            Kind   = $a.kind
        }
    }
}
