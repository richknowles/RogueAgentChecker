function Export-RacReport {
    <#
    .SYNOPSIS
        Writes the HTML, CSV and JSON report files for a scan result.

    .DESCRIPTION
        Invoke-RogueAgentScan calls this automatically unless -NoReport is used.
        Call it yourself to (re)write a report from a result object, for example
        after a scan run with -NoReport -PassThru.

    .EXAMPLE
        $r = Invoke-RogueAgentScan -NoReport -PassThru
        Export-RacReport -ScanResult $r -OutputPath C:\RAC\Reports
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$ScanResult,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [string]$BaseName
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    if (-not $BaseName) {
        $BaseName = 'RogueAgentReport_{0}_{1}' -f ($ScanResult.ComputerName -replace '[^A-Za-z0-9_-]', '_'), $ScanResult.StartTime.ToString('yyyyMMdd-HHmmss')
    }

    $html = Join-Path -Path $OutputPath -ChildPath ($BaseName + '.html')
    $csv = Join-Path -Path $OutputPath -ChildPath ($BaseName + '_findings.csv')
    $json = Join-Path -Path $OutputPath -ChildPath ($BaseName + '.json')

    # Record the file names first so the report's "Files written" line is complete.
    $ScanResult.ReportFiles['Html'] = $html
    $ScanResult.ReportFiles['Csv'] = $csv
    $ScanResult.ReportFiles['Json'] = $json

    Export-RacFindingCsv -ScanResult $ScanResult -Path $csv
    Write-RacLog -Level OUTPUT -Message ('Wrote ' + $csv)
    Export-RacFindingJson -ScanResult $ScanResult -Path $json
    Write-RacLog -Level OUTPUT -Message ('Wrote ' + $json)
    Export-RacFindingHtml -ScanResult $ScanResult -Path $html
    Write-RacLog -Level OUTPUT -Message ('Wrote ' + $html)

    return [pscustomobject]@{ Html = $html; Csv = $csv; Json = $json }
}
