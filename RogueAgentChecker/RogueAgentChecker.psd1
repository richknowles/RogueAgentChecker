@{
    RootModule           = 'RogueAgentChecker.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '25cbcaf5-706a-4e00-859f-61401161992e'
    Author               = 'Rich Knowles'
    CompanyName          = 'WieldAI'
    Copyright            = '(c) 2026 Rich Knowles. All rights reserved.'
    Description          = 'Read-only scanner that finds unauthorized or unmanaged AI agents on a Windows machine, compares them with an allow-list, and writes an HTML/CSV audit report. Think RogueChecker, for agentic AI.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Invoke-RogueAgentScan',
        'Export-RacReport',
        'Import-RacAllowList',
        'ConvertTo-RacAllowListEntry',
        'Get-RacSignature'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'AI', 'Agents', 'MCP', 'Audit', 'Inventory', 'ShadowAI', 'ReadOnly', 'Windows')
            ReleaseNotes = '0.1.0 MVP: read-only local scan across seven breadcrumb categories, allow-list classification, HTML/CSV/JSON report.'
        }
    }
}
