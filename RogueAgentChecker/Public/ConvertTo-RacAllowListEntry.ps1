function ConvertTo-RacAllowListEntry {
    <#
    .SYNOPSIS
        Drafts allow-list entries from findings you have decided to approve.

    .DESCRIPTION
        Turns one or more findings into allow-list entries scoped to the agent and,
        by default, the user. Nothing is written to disk: review the output, then
        paste it into your allow-list file. Approval is a human decision; this only
        saves typing.

    .PARAMETER Finding
        Findings from Invoke-RogueAgentScan -PassThru (pipeline input).

    .PARAMETER ApprovedBy
        Who approved this agent. Required, because auditors will ask.

    .PARAMETER ExpiresInDays
        Approval lifetime. Default 90 days.

    .PARAMETER AllUsers
        Do not restrict the entry to the finding's user.

    .PARAMETER AsJson
        Emit JSON text instead of objects.

    .EXAMPLE
        $scan = Invoke-RogueAgentScan -PassThru
        $scan.Findings | Where-Object Agent -eq 'Claude Code' |
            ConvertTo-RacAllowListEntry -ApprovedBy 'IT Security (J. Admin)' -Ticket CHG-1042 -AsJson
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$ApprovedBy,
        [ValidateRange(1, 730)][int]$ExpiresInDays = 90,
        [string]$Ticket = '',
        [switch]$AllUsers,
        [switch]$AsJson
    )

    begin {
        $entries = [ordered]@{}
        $today = (Get-Date).Date
    }
    process {
        foreach ($f in @($Finding)) {
            if (-not $f) { continue }
            $agentKey = $f.AgentId
            if (-not $agentKey) { $agentKey = $f.Agent }
            $users = @()
            if (-not $AllUsers -and $f.User) { $users = @(([string]$f.User) -split ',\s*' | ForEach-Object { Get-RacUserLeaf $_ } | Where-Object { $_ }) }
            $key = '{0}|{1}' -f $agentKey, ($users -join ';')

            if (-not $entries.Contains($key)) {
                $name = $f.Agent
                if ($users.Count -gt 0) { $name += ' - ' + ($users -join ', ') }
                $entry = [ordered]@{
                    Name              = $name
                    Agent             = $agentKey
                    Users             = $users
                    Categories        = @()
                    McpServers        = @()
                    AllowedIndicators = @()
                    ApprovedBy        = $ApprovedBy
                    ApprovedOn        = $today.ToString('yyyy-MM-dd')
                    Expires           = $today.AddDays($ExpiresInDays).ToString('yyyy-MM-dd')
                    Ticket            = $Ticket
                    Notes             = 'Drafted from ' + $f.FindingId + '. Review scope before use.'
                }
                if (-not $f.AgentId) {
                    # Generic findings ('Unattributed ...') need a narrower scope than the agent name.
                    $entry.Agent = '*'
                    $entry.Categories = @($f.Category)
                    $entry['Breadcrumbs'] = @($f.Breadcrumb)
                    $entry['PathPattern'] = @($f.Location)
                }
                $entries[$key] = $entry
            }
            $e = $entries[$key]
            if ($f.Breadcrumb -eq 'McpServerConfig' -and $f.Evidence['Server name'] -and $e.McpServers -notcontains $f.Evidence['Server name']) {
                $e.McpServers += [string]$f.Evidence['Server name']
            }
            if ($e.Notes -notmatch [regex]::Escape($f.FindingId)) { $e.Notes = $e.Notes -replace '^Drafted from ', ('Drafted from ' + $f.FindingId + ', ') }
        }
    }
    end {
        $objects = foreach ($e in $entries.Values) { [pscustomobject]$e }
        if ($AsJson) { return (@($objects) | ConvertTo-Json -Depth 4) }
        return $objects
    }
}
