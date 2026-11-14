<#
    Analyze-Logs.ps1 - Category 6: agent logs, transcripts, tool-call histories,
    and event-log patterns (PowerShell 4104, Sysmon 1/3/11/22, Security 4688).

    Transcripts are summarized, never quoted: file counts, sizes, time ranges,
    and a COUNT of tool-call records. Event snippets are short and redacted.
#>

function Get-RacSnippet {
    <# Up to $Width characters around the first regex match, redacted. #>
    param([string]$Text, [string]$Pattern, [int]$Width = 160)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    # Redact the WHOLE text first. Cutting a window first could slice a key in
    # half, and half a key no longer matches any redaction pattern.
    $Text = Protect-RacText -Text $Text
    $m = [regex]::Match($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $start = 0
    if ($m.Success) { $start = [math]::Max(0, $m.Index - [int]($Width / 3)) }
    $length = [math]::Min($Width, $Text.Length - $start)
    $snippet = ($Text.Substring($start, $length) -replace '\s+', ' ').Trim()
    return (Protect-RacText -Text $snippet)   # second pass is cheap insurance
}

function Add-RacEventGroup {
    <# Accumulates events into a group keyed by $Key (count, first/last seen, a few samples). #>
    param([System.Collections.IDictionary]$Groups, [string]$Key, [hashtable]$Seed, [datetime]$Time, [string]$Sample)
    if (-not $Groups.Contains($Key)) {
        $g = [pscustomobject]@{ Count = 0; First = $Time; Last = $Time; Samples = @(); Times = @(); Seed = $Seed }
        $Groups[$Key] = $g
    }
    $g = $Groups[$Key]
    $g.Count++
    if ($Time -lt $g.First) { $g.First = $Time }
    if ($Time -gt $g.Last) { $g.Last = $Time }
    if ($g.Times.Count -lt 500) { $g.Times += $Time }
    if ($Sample -and $g.Samples.Count -lt 3 -and $g.Samples -notcontains $Sample) { $g.Samples += $Sample }
}

function Get-RacAgentFromImage {
    <# Agent for an event's process image path, or $null. #>
    param($Signatures, [string]$Image, [string]$CommandLine = '')
    if (-not $Image) { return $null }
    $leaf = Get-RacLeafName $Image
    return (Find-RacAgentByProcess -Signatures $Signatures -Name $leaf -Path $Image -CommandLine $CommandLine)
}

function Find-RacAgentLogFile {
    <# Agent log / transcript / history folders from the signature catalog. #>
    param($Context)

    $sig = $Context.Signatures
    $toolCallPattern = [string]$sig.genericPatterns.toolCallRecord

    foreach ($userProfile in @($Context.ProfileRoots)) {
        if (-not $userProfile.Readable) { continue }
        foreach ($agent in $sig.agents) {
            foreach ($lp in @($agent.logPaths)) {
                if (-not $lp -or -not $lp.path) { continue }
                $path = Expand-RacPathTemplate -Template ([string]$lp.path) -ProfileRoot $userProfile.Path
                foreach ($resolved in @(Resolve-RacPath -Path $path)) {
                    $key = 'log|' + $resolved.ToLowerInvariant()
                    if ($Context.SeenPaths.ContainsKey($key)) { continue }
                    $Context.SeenPaths[$key] = $true

                    $info = Get-RacItemInfo -Path $resolved
                    if (-not $info) { continue }
                    $files = @()
                    if ($info.IsDirectory) {
                        $filter = [string]$lp.filter
                        if (-not $filter) { $filter = '*' }
                        $files = @(Get-RacChildItem -Path $resolved -Filter $filter -Recurse -File -MaxItems 5000)
                    }
                    else {
                        $files = @($info)
                    }
                    if ($files.Count -eq 0) { continue }

                    $totalBytes = 0
                    $oldest = $null
                    $newest = $null
                    $recent = @()
                    foreach ($f in $files) {
                        $totalBytes += $f.Length
                        if ($f.LastWriteTime -is [datetime]) {
                            if ($null -eq $oldest -or $f.LastWriteTime -lt $oldest) { $oldest = $f.LastWriteTime }
                            if ($null -eq $newest -or $f.LastWriteTime -gt $newest) { $newest = $f.LastWriteTime }
                            if ($f.LastWriteTime -ge $Context.LookbackStart) { $recent += $f.LastWriteTime }
                        }
                    }

                    $kind = [string]$lp.kind
                    $toolCalls = $null
                    $toolNote = ''
                    if ($kind -eq 'Transcript' -or $kind -eq 'History') {
                        $toolCalls = 0
                        $counted = 0
                        $skipped = 0
                        $budget = 200MB
                        foreach ($f in ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 500)) {
                            if ($budget -le 0) { $skipped++; continue }
                            $n = Measure-RacPatternInFile -Path $f.FullName -Pattern $toolCallPattern -MaxBytes 5MB
                            if ($n -ge 0) { $toolCalls += $n; $counted++; $budget -= $f.Length } else { $skipped++ }
                        }
                        $toolNote = '{0} record(s) in {1} file(s)' -f $toolCalls, $counted
                        if ($skipped -gt 0) { $toolNote += ('; {0} file(s) too large or locked to count' -f $skipped) }
                    }

                    # Claude Desktop names its MCP logs mcp-server-<name>.log: a free inventory.
                    $mcpLogNames = @($files | ForEach-Object { if ($_.Name -match '^mcp-server-(.+)\.log$') { $Matches[1] } } | Select-Object -Unique)

                    $breadcrumb = 'AgentLog'
                    $label = 'logs'
                    if ($kind -eq 'Transcript') { $breadcrumb = 'AgentTranscript'; $label = 'transcripts' }
                    if ($kind -eq 'History') { $breadcrumb = 'AgentHistory'; $label = 'history' }

                    $evidence = [ordered]@{
                        'Location'            = $resolved
                        'Kind'                = $kind
                        'Files'               = $files.Count
                        'Total size (MB)'     = [math]::Round($totalBytes / 1MB, 2)
                        'Oldest'              = $oldest
                        'Newest'              = $newest
                        'Changed in lookback' = $recent.Count
                        'Tool-call records'   = $toolNote
                        'MCP servers in logs' = ($mcpLogNames -join ', ')
                        'Content'             = 'not quoted (summary only)'
                    }
                    New-RacFinding -Category 'LogsAndEvents' -Breadcrumb $breadcrumb `
                        -Title ('{0} {1}: {2} file(s), newest {3}' -f $agent.name, $label, $files.Count, (Format-RacTime $newest)) `
                        -Agent $agent.name -AgentId $agent.id -Location $resolved -User $userProfile.User `
                        -EventTime $newest -Evidence $evidence -ActivityTimes ($recent | Select-Object -First 500)
                }
            }
        }
    }
}

function Find-RacPowerShellEvent {
    <# Script Block Logging (4104) in both Windows PowerShell and PowerShell 7 logs. #>
    param($Context)

    $sig = $Context.Signatures
    $groups = [ordered]@{}
    $webVerb = 'invoke-restmethod|invoke-webrequest|\birm\b|\biwr\b|curl|wget|httpclient|webclient|net\.http'

    foreach ($logName in @('Microsoft-Windows-PowerShell/Operational', 'PowerShellCore/Operational')) {
        foreach ($e in @(Get-RacRawWinEvent -LogName $logName -Id 4104 -StartTime $Context.LookbackStart -MaxEvents $Context.Options.MaxEventsPerLog)) {
            if (-not $e) { continue }
            $text = [string]$e.Data['ScriptBlockText']
            if (-not $text) { continue }

            # Don't report ourselves: with Script Block Logging on, importing this
            # module logs its own code, which mentions agent names and key formats.
            $scriptPath = [string]$e.Data['Path']
            if ($scriptPath -and $script:RacModuleRoot -and $scriptPath.StartsWith($script:RacModuleRoot, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($text -match 'New-RacFinding|Invoke-RogueAgentScan|RacModuleRoot') { continue }

            $normalized = ConvertTo-RacNormalizedText $text

            $hostName = $null
            if ($normalized -match $sig._EndpointRegex) { $hostName = $Matches[1] }
            $agentMatch = Find-RacAgentByText -Signatures $sig -Text $text
            $secretRefs = @([regex]::Matches($text, '\$env:([A-Za-z0-9_]+)') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -match $sig.secretEnvNamePattern } | Select-Object -Unique)
            if (-not $hostName -and -not $agentMatch -and $secretRefs.Count -eq 0) { continue }

            $agentKey = 'unattributed'
            $agentName = 'Unattributed (PowerShell)'
            $agentId = ''
            if ($agentMatch) { $agentKey = $agentMatch.Agent.id; $agentName = $agentMatch.Agent.name; $agentId = $agentMatch.Agent.id }
            $calls = [bool]($hostName -and $normalized -match $webVerb)
            $key = '{0}|{1}|{2}' -f $agentKey, $hostName, $calls

            $pattern = '\$env:'
            if ($hostName) { $pattern = [regex]::Escape($hostName) }
            elseif ($agentMatch) { $pattern = '.' }
            $seed = @{ AgentName = $agentName; AgentId = $agentId; HostName = $hostName; Calls = $calls; SecretRefs = @() }
            Add-RacEventGroup -Groups $groups -Key $key -Seed $seed -Time $e.TimeCreated -Sample (Get-RacSnippet -Text $text -Pattern $pattern)
            foreach ($r in $secretRefs) { if ($groups[$key].Seed.SecretRefs -notcontains $r) { $groups[$key].Seed.SecretRefs += $r } }
            if ($scriptPath -and -not $groups[$key].Seed.ContainsKey('ScriptPath')) { $groups[$key].Seed.ScriptPath = $scriptPath }
        }
    }

    foreach ($g in $groups.Values) {
        $s = $g.Seed
        $indicators = @()
        if ($s.Calls) { $indicators += 'LlmCallFromScript' }
        $evidence = [ordered]@{
            'Event'               = 'PowerShell Script Block Logging (4104)'
            'Script blocks'       = $g.Count
            'First seen'          = $g.First
            'Last seen'           = $g.Last
            'LLM host referenced' = $s.HostName
            'Key variables used'  = ($s.SecretRefs -join ', ')
            'Script path'         = $s.ScriptPath
            'Samples (redacted)'  = ($g.Samples -join ' | ')
        }
        $what = 'references AI keys'
        if ($s.HostName) { $what = 'references ' + $s.HostName }
        if ($s.Calls) { $what = 'calls ' + $s.HostName }
        New-RacFinding -Category 'LogsAndEvents' -Breadcrumb 'PowerShellScriptBlock' `
            -Title ('PowerShell script {0} ({1} block(s))' -f $what, $g.Count) `
            -Agent $s.AgentName -AgentId $s.AgentId -Location 'Event log: PowerShell Operational (4104)' `
            -EventTime $g.Last -Evidence $evidence -Indicators $indicators -ActivityTimes $g.Times
    }
}

function Find-RacSysmonEvent {
    <# Sysmon: 22 DNS query, 3 network connect, 1 process create, 11 file create. #>
    param($Context)

    $sig = $Context.Signatures
    $trafficGroups = [ordered]@{}
    $processGroups = [ordered]@{}

    foreach ($e in @(Get-RacRawWinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(1, 3, 11, 22) -StartTime $Context.LookbackStart -MaxEvents $Context.Options.MaxEventsPerLog)) {
        if (-not $e) { continue }
        $d = $e.Data
        $image = [string]$d['Image']
        $user = [string]$d['User']

        if ($e.Id -eq 22 -or $e.Id -eq 3) {
            $hostName = [string]$d['QueryName']
            if ($e.Id -eq 3) { $hostName = [string]$d['DestinationHostname'] }
            $endpoint = Find-RacLlmEndpoint -Signatures $sig -HostName $hostName
            if (-not $endpoint) { continue }
            $leaf = (Get-RacLeafName $image).ToLowerInvariant()
            $agent = Get-RacAgentFromImage -Signatures $sig -Image $image
            $isBrowser = Test-RacNameInList -Signatures $sig -Group 'browserProcessNames' -Name $leaf
            if ($isBrowser -and -not $agent -and -not $Context.Options.IncludeBrowserAiSessions) { continue }
            $key = '{0}|{1}' -f $image.ToLowerInvariant(), $hostName.ToLowerInvariant()
            $seed = @{ Image = $image; HostName = $hostName.ToLowerInvariant(); Provider = [string]$endpoint.provider; Agent = $agent; User = $user; IsBrowser = $isBrowser; Leaf = $leaf; Ids = @() }
            Add-RacEventGroup -Groups $trafficGroups -Key $key -Seed $seed -Time $e.TimeCreated -Sample ''
            if ($trafficGroups[$key].Seed.Ids -notcontains $e.Id) { $trafficGroups[$key].Seed.Ids += $e.Id }
            continue
        }

        if ($e.Id -eq 1) {
            $cmd = [string]$d['CommandLine']
            $parentCmd = [string]$d['ParentCommandLine']
            $parentImage = [string]$d['ParentImage']
            $agent = Get-RacAgentFromImage -Signatures $sig -Image $image -CommandLine $cmd
            $parentAgent = Get-RacAgentFromImage -Signatures $sig -Image $parentImage -CommandLine $parentCmd
            $mcp = Get-RacGenericMatch -Signatures $sig -Group 'mcpServer' -Text $cmd
            $leaf = (Get-RacLeafName $image).ToLowerInvariant()
            $isShell = Test-RacNameInList -Signatures $sig -Group 'shellProcessNames' -Name $leaf
            $install = Get-RacGenericMatch -Signatures $sig -Group 'packageInstall' -Text $cmd

            if ($parentAgent -and $install) {
                $Context.BehaviorSignals.PackageInstalls.Add([pscustomobject]@{
                        AgentId = [string]$parentAgent.Agent.id; Agent = [string]$parentAgent.Agent.name; User = (Get-RacUserLeaf $user)
                        Time = $e.TimeCreated; What = (Protect-RacText -Text $cmd -MaxLength 200); Source = 'Sysmon 1'; ByAgent = $true
                    })
            }

            $owning = $agent
            if (-not $owning) { $owning = $parentAgent }
            if (-not $owning -and -not $mcp) { continue }
            $agentKey = 'mcp'
            if ($owning) { $agentKey = $owning.Agent.id }
            $seed = @{ Agent = $owning; Mcp = $mcp; User = $user; Shells = 0; Images = @() }
            Add-RacEventGroup -Groups $processGroups -Key $agentKey -Seed $seed -Time $e.TimeCreated -Sample (Protect-RacText -Text $cmd -MaxLength 200)
            $g = $processGroups[$agentKey]
            if ($parentAgent -and $isShell) { $g.Seed.Shells++ }
            if ($g.Seed.Images -notcontains $leaf -and $g.Seed.Images.Count -lt 10) { $g.Seed.Images += $leaf }
            continue
        }

        if ($e.Id -eq 11) {
            $target = [string]$d['TargetFilename']
            $agent = Find-RacAgentBySkillPath -Signatures $sig -Path $target
            if (-not $agent) { continue }
            $writer = Get-RacAgentFromImage -Signatures $sig -Image $image
            $leaf = (Get-RacLeafName $image).ToLowerInvariant()
            $byAgent = [bool]$writer -or (Test-RacNameInList -Signatures $sig -Group 'scriptHostNames' -Name $leaf)
            $Context.BehaviorSignals.SelfMod.Add([pscustomobject]@{
                    AgentId = [string]$agent.id; Agent = [string]$agent.name; User = (Get-RacUserFromPath -Path $target)
                    Path = $target; Time = $e.TimeCreated; Source = ('Sysmon 11 (written by {0})' -f $leaf); ByAgentProcess = $byAgent
                })
        }
    }

    foreach ($g in $trafficGroups.Values) {
        $s = $g.Seed
        $indicators = @()
        $agentName = 'Unidentified process'
        $agentId = ''
        if ($s.Agent) { $agentName = $s.Agent.Agent.name; $agentId = $s.Agent.Agent.id }
        elseif ($s.IsBrowser) { $agentName = 'Web browser' }
        elseif (Test-RacNameInList -Signatures $sig -Group 'scriptHostNames' -Name $s.Leaf) { $agentName = 'Script host (possible custom agent)' }
        else { $indicators += 'LlmFromNonAgentProcess' }
        $evidence = [ordered]@{
            'Process image' = $s.Image
            'Remote host'   = $s.HostName
            'Provider'      = $s.Provider
            'Events'        = ('{0} (Sysmon event ID {1})' -f $g.Count, ($s.Ids -join ', '))
            'First seen'    = $g.First
            'Last seen'     = $g.Last
            'User'          = $s.User
        }
        New-RacFinding -Category 'LogsAndEvents' -Breadcrumb 'SysmonLlmTraffic' `
            -Title ('{0} contacted {1} ({2} event(s))' -f (Get-RacLeafName $s.Image), $s.HostName, $g.Count) `
            -Agent $agentName -AgentId $agentId -Location ('Sysmon: ' + $s.Image) -User $s.User `
            -EventTime $g.Last -Evidence $evidence -Indicators $indicators -ActivityTimes $g.Times `
            -Signals @{ RemoteHost = $s.HostName }
    }

    foreach ($g in $processGroups.Values) {
        $s = $g.Seed
        $agentName = 'Unidentified MCP server'
        $agentId = ''
        if ($s.Agent) { $agentName = $s.Agent.Agent.name; $agentId = $s.Agent.Agent.id }
        $indicators = @()
        if ($s.Shells -gt 0) { $indicators += 'AgentSpawnedShell' }
        $evidence = [ordered]@{
            'Event'                = 'Sysmon process creation (1)'
            'Launches'             = $g.Count
            'First seen'           = $g.First
            'Last seen'            = $g.Last
            'Shells launched by agent' = $s.Shells
            'Images'               = ($s.Images -join ', ')
            'Sample command lines' = ($g.Samples -join ' | ')
            'User'                 = $s.User
        }
        New-RacFinding -Category 'LogsAndEvents' -Breadcrumb 'SysmonAgentProcess' `
            -Title ('{0}: {1} process launch(es) in the last {2} days' -f $agentName, $g.Count, $Context.Options.LookbackDays) `
            -Agent $agentName -AgentId $agentId -Location 'Event log: Sysmon Operational (1)' -User $s.User `
            -EventTime $g.Last -Evidence $evidence -Indicators $indicators -ActivityTimes $g.Times
    }
}

function Find-RacSecurityProcessEvent {
    <# Security 4688 (process creation with command line, if auditing is enabled). Elevated only. #>
    param($Context)

    $sig = $Context.Signatures
    $groups = [ordered]@{}
    foreach ($e in @(Get-RacRawWinEvent -LogName 'Security' -Id 4688 -StartTime $Context.LookbackStart -MaxEvents $Context.Options.MaxEventsPerLog)) {
        if (-not $e) { continue }
        $d = $e.Data
        $image = [string]$d['NewProcessName']
        $cmd = [string]$d['CommandLine']
        $parent = [string]$d['ParentProcessName']
        $agent = Get-RacAgentFromImage -Signatures $sig -Image $image -CommandLine $cmd
        $parentAgent = Get-RacAgentFromImage -Signatures $sig -Image $parent
        $install = Get-RacGenericMatch -Signatures $sig -Group 'packageInstall' -Text $cmd
        if ($parentAgent -and $install) {
            $Context.BehaviorSignals.PackageInstalls.Add([pscustomobject]@{
                    AgentId = [string]$parentAgent.Agent.id; Agent = [string]$parentAgent.Agent.name; User = [string]$d['SubjectUserName']
                    Time = $e.TimeCreated; What = (Protect-RacText -Text $cmd -MaxLength 200); Source = 'Security 4688'; ByAgent = $true
                })
        }
        if (-not $agent) { continue }
        $seed = @{ Agent = $agent; User = [string]$d['SubjectUserName'] }
        Add-RacEventGroup -Groups $groups -Key $agent.Agent.id -Seed $seed -Time $e.TimeCreated -Sample (Protect-RacText -Text $cmd -MaxLength 200)
    }
    foreach ($g in $groups.Values) {
        $evidence = [ordered]@{
            'Event'                = 'Security process creation (4688)'
            'Launches'             = $g.Count
            'First seen'           = $g.First
            'Last seen'            = $g.Last
            'Sample command lines' = ($g.Samples -join ' | ')
        }
        New-RacFinding -Category 'LogsAndEvents' -Breadcrumb 'SecurityProcessEvent' `
            -Title ('{0}: {1} process launch(es) recorded in the Security log' -f $g.Seed.Agent.Agent.name, $g.Count) `
            -Agent $g.Seed.Agent.Agent.name -AgentId $g.Seed.Agent.Agent.id -Location 'Event log: Security (4688)' -User $g.Seed.User `
            -EventTime $g.Last -Evidence $evidence -ActivityTimes $g.Times
    }
}

function Find-RacLogFinding {
    param([Parameter(Mandatory = $true)]$Context)
    Find-RacAgentLogFile -Context $Context
    Find-RacPowerShellEvent -Context $Context
    Find-RacSysmonEvent -Context $Context
    Find-RacSecurityProcessEvent -Context $Context
}
