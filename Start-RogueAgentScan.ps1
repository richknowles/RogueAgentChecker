<#
.SYNOPSIS
    Runs a read-only Rogue Agent Checker scan of this machine and writes the report.

.DESCRIPTION
    A convenience wrapper around Invoke-RogueAgentScan for people who would rather
    run a script than import a module. If allowlist.json (or allowlist.csv) sits
    next to this script, it is used automatically.

    With -RmmMode the script prints one summary line and exits with a code an RMM
    script check can act on:
        0  nothing unapproved found
        1  Unknown items only (agents that need an owner decision)
        2  at least one Suspicious finding
        3  the scan itself failed

.EXAMPLE
    .\Start-RogueAgentScan.ps1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-RogueAgentScan.ps1 -OutputPath C:\ProgramData\RogueAgentChecker -RmmMode
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'Reports'),
    [string]$AllowListPath,
    [string[]]$SearchRoot,
    [string[]]$ProxyLogPath,
    [ValidateRange(1, 90)][int]$LookbackDays = 7,
    [switch]$IncludeBrowserAiSessions,
    [switch]$RmmMode
)

$ErrorActionPreference = 'Stop'

try {
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'RogueAgentChecker/RogueAgentChecker.psd1') -Force

    if (-not $AllowListPath) {
        foreach ($candidate in @('allowlist.json', 'allowlist.csv')) {
            $path = Join-Path -Path $PSScriptRoot -ChildPath $candidate
            if (Test-Path -LiteralPath $path) { $AllowListPath = $path; break }
        }
    }

    $scanParams = @{
        OutputPath   = $OutputPath
        LookbackDays = $LookbackDays
        PassThru     = $true
    }
    if ($AllowListPath) { $scanParams.AllowListPath = $AllowListPath }
    if ($SearchRoot) { $scanParams.SearchRoot = $SearchRoot }
    if ($ProxyLogPath) { $scanParams.ProxyLogPath = $ProxyLogPath }
    if ($IncludeBrowserAiSessions) { $scanParams.IncludeBrowserAiSessions = $true }

    $result = Invoke-RogueAgentScan @scanParams
}
catch {
    if ($RmmMode) {
        Write-Output ('RAC: scan failed: ' + $_.Exception.Message)
        exit 3
    }
    throw
}

if ($RmmMode) {
    Write-Output ('RAC: {0} suspicious, {1} unknown, {2} trusted on {3}. Report: {4}' -f $result.Summary.Suspicious, $result.Summary.Unknown, $result.Summary.Trusted, $result.ComputerName, $result.ReportFiles['Html'])
    if ($result.Summary.Suspicious -gt 0) { exit 2 }
    if ($result.Summary.Unknown -gt 0) { exit 1 }
    exit 0
}
