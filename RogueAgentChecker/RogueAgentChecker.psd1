@{
    RootModule           = 'RogueAgentChecker.psm1'
    ModuleVersion        = '0.1.1'
    GUID                 = '25cbcaf5-706a-4e00-859f-61401161992e'
    Author               = 'Rich Knowles'
    CompanyName          = 'WieldAI'
    Copyright            = '(c) 2026 Rich Knowles. Licensed under the Apache License, Version 2.0.'
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
            LicenseUri   = 'https://github.com/richknowles/RogueAgentChecker/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/richknowles/RogueAgentChecker'
            ReleaseNotes = '0.1.1: fixes from the first real-Windows run (standard-user scans now read your own registry hive; honest coverage for the DNS cache and Security log; RAC ignores its own tests; extension labels, including Claude in Chrome as its own entry; hidden-task scoring; RAC recognizes its own code by content; event logs that overwrote themselves are no longer reported as fully covered; RAC now looks inside the script or encoded command a process or autostart runs, so a hidden script calling an AI API is caught even after the DNS cache has forgotten the hostname). See CHANGELOG.md.'
        }
    }
}
