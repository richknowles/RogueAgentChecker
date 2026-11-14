<#
    Analyze-Processes.ps1 - Category 1: long-running agent processes, headless
    browsers, MCP servers.

    Input : $Context.Processes (from Get-RacRawProcess)
    Output: findings with Breadcrumb AgentProcess, McpServerProcess, HeadlessBrowser

    Every process is profiled once (Get-RacProcessProfile) and the result is
    cached, because the network analyzer asks the same questions about the
    processes that own LLM connections.
#>

function Get-RacProcessById {
    param($Context, [int]$ProcessId)
    if (-not $Context.ProcessById) {
        $map = @{}
        foreach ($p in @($Context.Processes)) { $map[[int]$p.ProcessId] = $p }
        $Context.ProcessById = $map
    }
    return $Context.ProcessById[$ProcessId]
}

function Get-RacProcessProfile {
    <#
        Answers, for one PID: which agent is it (if any), which agent launched it
        (walking up to 6 parents), is it a browser, is it browser automation or an
        MCP server. Cached in $Context.ProcessProfiles.
    #>
    param($Context, [int]$ProcessId)

    if ($Context.ProcessProfiles.ContainsKey($ProcessId)) { return $Context.ProcessProfiles[$ProcessId] }

    $sig = $Context.Signatures
    $proc = Get-RacProcessById -Context $Context -ProcessId $ProcessId
    $profileInfo = [pscustomobject]@{
        Process        = $proc
        AgentMatch     = $null
        AncestorAgent  = $null
        AncestorPid    = 0
        IsBrowser      = $false
        IsChildRenderer = $false
        McpPattern     = $null
        HeadlessPattern = $null
    }

    if ($proc) {
        $cmd = ConvertTo-RacNormalizedText $proc.CommandLine
        $profileInfo.AgentMatch = Find-RacAgentByProcess -Signatures $sig -Name $proc.Name -Path $proc.ExecutablePath -CommandLine $proc.CommandLine
        $profileInfo.IsBrowser = Test-RacNameInList -Signatures $sig -Group 'browserProcessNames' -Name $proc.Name
        $profileInfo.IsChildRenderer = ($profileInfo.IsBrowser -and $cmd -match '(^| )--type=')
        $profileInfo.McpPattern = Get-RacGenericMatch -Signatures $sig -Group 'mcpServer' -Text $cmd
        $pathText = ConvertTo-RacNormalizedText $proc.ExecutablePath
        if ($profileInfo.IsBrowser -or $pathText -match 'ms-playwright|puppeteer|headless') {
            $profileInfo.HeadlessPattern = Get-RacGenericMatch -Signatures $sig -Group 'headlessBrowser' -Text ($cmd + ' ' + $pathText)
        }

        # Walk the parent chain. A parent that started AFTER the child is a
        # recycled PID, not the real parent, so the walk stops there.
        $child = $proc
        for ($depth = 0; $depth -lt 6; $depth++) {
            $parent = Get-RacProcessById -Context $Context -ProcessId ([int]$child.ParentProcessId)
            if (-not $parent -or $parent.ProcessId -eq $child.ProcessId) { break }
            if ($parent.CreationDate -is [datetime] -and $child.CreationDate -is [datetime] -and $parent.CreationDate -gt $child.CreationDate) { break }
            $parentMatch = Find-RacAgentByProcess -Signatures $sig -Name $parent.Name -Path $parent.ExecutablePath -CommandLine $parent.CommandLine
            if ($parentMatch) {
                $profileInfo.AncestorAgent = $parentMatch.Agent
                $profileInfo.AncestorPid = [int]$parent.ProcessId
                break
            }
            $child = $parent
        }
    }

    $Context.ProcessProfiles[$ProcessId] = $profileInfo
    return $profileInfo
}

function Get-RacProcessOwnerCached {
    <# Owner from the fake/real process object if present, otherwise one WMI lookup, remembered. #>
    param($Process)
    if ($Process.Owner) { return [string]$Process.Owner }
    $owner = Get-RacProcessOwner -ProcessId ([int]$Process.ProcessId)
    $Process.Owner = $owner
    return $owner
}

function Find-RacProcessFinding {
    param([Parameter(Mandatory = $true)]$Context)

    $sig = $Context.Signatures
    $now = $Context.Now
    $count = 0

    foreach ($proc in @($Context.Processes)) {
        $pidValue = [int]$proc.ProcessId
        $info = Get-RacProcessProfile -Context $Context -ProcessId $pidValue
        if ($info.IsChildRenderer) { continue }   # Chromium renderer/GPU helpers repeat the parent's flags
        if (-not $info.AgentMatch -and -not $info.McpPattern -and -not $info.HeadlessPattern) { continue }

        $cmd = ConvertTo-RacNormalizedText $proc.CommandLine
        $pathText = ConvertTo-RacNormalizedText $proc.ExecutablePath

        # --- What is it, and whose is it? -----------------------------------
        $agentName = ''
        $agentId = ''
        if ($info.AgentMatch) {
            $agentName = [string]$info.AgentMatch.Agent.name
            $agentId = [string]$info.AgentMatch.Agent.id
        }
        elseif ($info.AncestorAgent) {
            $agentName = [string]$info.AncestorAgent.name
            $agentId = [string]$info.AncestorAgent.id
        }

        if ($info.McpPattern -and -not $info.AgentMatch) {
            $breadcrumb = 'McpServerProcess'
            if (-not $agentName) { $agentName = 'Unidentified MCP server' }
            $title = 'MCP server process {0} (PID {1})' -f $proc.Name, $pidValue
        }
        elseif ($info.HeadlessPattern -and -not $info.AgentMatch) {
            $breadcrumb = 'HeadlessBrowser'
            if (-not $agentName) { $agentName = 'Unattributed browser automation' }
            $title = 'Automated / headless browser {0} (PID {1})' -f $proc.Name, $pidValue
        }
        else {
            $breadcrumb = 'AgentProcess'
            $title = '{0} running ({1}, PID {2})' -f $agentName, $proc.Name, $pidValue
        }
        if ($info.AncestorAgent -and $breadcrumb -ne 'AgentProcess') {
            $title += ' launched by ' + $info.AncestorAgent.name
        }

        # --- Indicators ---------------------------------------------------------
        $indicators = @()
        $uptimeHours = $null
        if ($proc.CreationDate -is [datetime]) {
            $uptimeHours = [math]::Round(($now - $proc.CreationDate).TotalHours, 1)
            if ($uptimeHours -ge $Context.Options.LongRunningHours) { $indicators += 'LongRunning' }
        }
        if ($cmd -match '--remote-debugging-(port|pipe)') { $indicators += 'RemoteDebuggingPort' }
        if ($cmd -match '--remote-debugging-address[= ]+(0\.0\.0\.0|::|\[::\])') { $indicators += 'ListensOnAllInterfaces' }
        if (Get-RacFirstRegexMatch -Text $pathText -Pattern @($sig.genericPatterns.userWritablePaths)) { $indicators += 'UserWritableExecPath' }
        $stealth = Get-RacGenericMatch -Signatures $sig -Group 'stealthLaunch' -Text $cmd
        if ($stealth) { $indicators += 'StealthLaunch' }

        $owner = Get-RacProcessOwnerCached -Process $proc
        if (Test-RacSystemAccount -User $owner) { $indicators += 'SystemContext' }

        $categories = @()
        if ($info.McpPattern) {
            $categories = Get-RacMcpAppCategory -Signatures $sig -Text $cmd
            if ($categories -contains 'shell' -or $categories -contains 'files') { $indicators += 'ShellCapableMcp' }
        }

        # --- Evidence -----------------------------------------------------------
        $parent = Get-RacProcessById -Context $Context -ProcessId ([int]$proc.ParentProcessId)
        $parentText = 'PID {0} (not running)' -f $proc.ParentProcessId
        if ($parent) { $parentText = '{0} (PID {1})' -f $parent.Name, $parent.ProcessId }

        $evidence = [ordered]@{
            'Process'          = '{0} (PID {1})' -f $proc.Name, $pidValue
            'Executable'       = $proc.ExecutablePath
            'Command line'     = $proc.CommandLine
            'Parent'           = $parentText
            'Owner'            = $owner
            'Started'          = $proc.CreationDate
            'Uptime (hours)'   = $uptimeHours
        }
        if ($info.AgentMatch) { $evidence['Matched because'] = $info.AgentMatch.Reason }
        if ($info.AncestorAgent) { $evidence['Launched by'] = '{0} (PID {1})' -f $info.AncestorAgent.name, $info.AncestorPid }
        if ($info.McpPattern) { $evidence['MCP pattern'] = $info.McpPattern }
        if ($info.HeadlessPattern) { $evidence['Automation flag'] = $info.HeadlessPattern }
        if ($stealth) { $evidence['Stealth pattern'] = $stealth }
        if ($categories) { $evidence['Reaches'] = ($categories -join ', ') }

        if ($Context.Options.CheckSignatures -and $proc.ExecutablePath) {
            $signature = Get-RacFileSignature -Path $proc.ExecutablePath
            if ($signature) { $evidence['Authenticode'] = '{0}; signer: {1}' -f $signature.Status, $signature.Signer }
        }

        $location = $proc.ExecutablePath
        if (-not $location) { $location = 'PID ' + $pidValue }

        $count++
        New-RacFinding -Category 'Processes' -Breadcrumb $breadcrumb -Title $title `
            -Agent $agentName -AgentId $agentId -Location $location -User $owner `
            -EventTime $proc.CreationDate -Evidence $evidence -Indicators $indicators `
            -ActivityTimes @($proc.CreationDate) -AppCategories $categories `
            -Signals @{ ProcessId = $pidValue }
    }

    Add-RacCoverage -Source 'Process analysis' -Status 'Info' -ItemCount $count -Detail 'Agent, MCP server and browser-automation processes identified.'
}
