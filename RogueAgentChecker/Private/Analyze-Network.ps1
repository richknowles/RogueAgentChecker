<#
    Analyze-Network.ps1 - Category 2: persistent outbound connections to LLM API
    endpoints, recent LLM lookups in the DNS cache, agent/model listeners, and
    (optionally) proxy logs.

    Hostnames come ONLY from the local DNS client cache. RAC never performs a DNS
    or reverse lookup, so it adds no traffic and leaks nothing.
#>

function ConvertTo-RacPlainIp {
    <# '::ffff:10.0.0.5' -> '10.0.0.5'; returns $null for anything that is not an IP. #>
    param([string]$Address)
    if ([string]::IsNullOrEmpty($Address)) { return $null }
    $a = $Address.Trim('[', ']')
    if ($a -match '^::ffff:(\d+\.\d+\.\d+\.\d+)$') { $a = $Matches[1] }
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($a, [ref]$ip)) { return $ip.ToString() }
    return $null
}

function Test-RacLoopbackOrUnspecified {
    param([string]$Address)
    return ($Address -match '^(127\.|0\.0\.0\.0$|::1?$)')
}

function Find-RacNetworkFinding {
    param([Parameter(Mandatory = $true)]$Context)

    $sig = $Context.Signatures
    $now = $Context.Now

    # ---- 1. IP -> hostname map, from the DNS cache only --------------------
    $ipToHost = @{}
    $llmHosts = [ordered]@{}
    foreach ($d in @($Context.DnsCache)) {
        $hostName = ([string]$d.Entry).ToLowerInvariant().TrimEnd('.')
        if (-not $hostName) { $hostName = ([string]$d.Name).ToLowerInvariant().TrimEnd('.') }
        if (-not $hostName) { continue }
        $ip = ConvertTo-RacPlainIp -Address ([string]$d.Data)
        if ($ip) {
            if (-not $ipToHost.ContainsKey($ip)) { $ipToHost[$ip] = @() }
            if ($ipToHost[$ip] -notcontains $hostName) { $ipToHost[$ip] += $hostName }
        }
        $endpoint = Find-RacLlmEndpoint -Signatures $sig -HostName $hostName
        if ($endpoint) {
            if (-not $llmHosts.Contains($hostName)) {
                $llmHosts[$hostName] = [pscustomobject]@{ Provider = [string]$endpoint.provider; Addresses = @() }
            }
            if ($ip -and $llmHosts[$hostName].Addresses -notcontains $ip) { $llmHosts[$hostName].Addresses += $ip }
        }
    }

    # ---- 2. Established connections to LLM endpoints, per (process, host) ---
    $localAddresses = @{}
    foreach ($c in @($Context.TcpConnections)) {
        $la = ConvertTo-RacPlainIp -Address $c.LocalAddress
        if ($la) { $localAddresses[$la] = $true }
    }

    # For multi-sample runs: which (pid|remote) pairs were present in every sample?
    $sampleCount = @($Context.TcpSamples).Count
    $seenInSamples = @{}
    foreach ($sample in @($Context.TcpSamples)) {
        $keysThisSample = @{}
        foreach ($c in @($sample)) {
            if ([string]$c.State -ne 'Established') { continue }
            $k = '{0}|{1}' -f $c.OwningProcess, (ConvertTo-RacPlainIp -Address $c.RemoteAddress)
            $keysThisSample[$k] = $true
        }
        foreach ($k in $keysThisSample.Keys) { $seenInSamples[$k] = 1 + [int]$seenInSamples[$k] }
    }

    $groups = [ordered]@{}
    $connectedHosts = @{}
    $browserSuppressed = 0
    foreach ($c in @($Context.TcpConnections)) {
        if ([string]$c.State -ne 'Established') { continue }
        $remote = ConvertTo-RacPlainIp -Address $c.RemoteAddress
        if (-not $remote -or -not $ipToHost.ContainsKey($remote)) { continue }

        $matchedHost = $null
        $endpoint = $null
        foreach ($h in $ipToHost[$remote]) {
            $endpoint = Find-RacLlmEndpoint -Signatures $sig -HostName $h
            if ($endpoint) { $matchedHost = $h; break }
        }
        if (-not $matchedHost) { continue }
        $connectedHosts[$matchedHost] = $true

        $info = Get-RacProcessProfile -Context $Context -ProcessId ([int]$c.OwningProcess)
        $isAutomation = [bool]($info.McpPattern -or $info.HeadlessPattern)
        if ($info.IsBrowser -and -not $isAutomation -and -not $info.AgentMatch -and -not $info.AncestorAgent -and -not $Context.Options.IncludeBrowserAiSessions) {
            $browserSuppressed++
            continue
        }

        $key = '{0}|{1}' -f $c.OwningProcess, $matchedHost
        if (-not $groups.Contains($key)) {
            $groups[$key] = [pscustomobject]@{
                ProcessId = [int]$c.OwningProcess; HostName = $matchedHost; Provider = [string]$endpoint.provider
                Info = $info; Remotes = @(); Count = 0; Oldest = $null; PersistentBySample = $false
            }
        }
        $g = $groups[$key]
        $g.Count++
        $remoteText = '{0}:{1}' -f $remote, $c.RemotePort
        if ($g.Remotes -notcontains $remoteText) { $g.Remotes += $remoteText }
        if ($c.CreationTime -is [datetime] -and ($null -eq $g.Oldest -or $c.CreationTime -lt $g.Oldest)) { $g.Oldest = $c.CreationTime }
        if ($sampleCount -gt 1 -and [int]$seenInSamples[('{0}|{1}' -f $c.OwningProcess, $remote)] -ge $sampleCount) { $g.PersistentBySample = $true }
    }

    foreach ($g in $groups.Values) {
        $proc = $g.Info.Process
        $procName = 'PID ' + $g.ProcessId
        $owner = ''
        $agentName = 'Unidentified process'
        $agentId = ''
        if ($proc) {
            $procName = '{0} (PID {1})' -f $proc.Name, $g.ProcessId
            $owner = Get-RacProcessOwnerCached -Process $proc
        }
        if ($g.Info.AgentMatch) { $agentName = $g.Info.AgentMatch.Agent.name; $agentId = $g.Info.AgentMatch.Agent.id }
        elseif ($g.Info.AncestorAgent) { $agentName = $g.Info.AncestorAgent.name; $agentId = $g.Info.AncestorAgent.id }
        elseif ($g.Info.IsBrowser) { $agentName = 'Web browser' }

        $indicators = @()
        $knownAi = [bool]($g.Info.AgentMatch -or $g.Info.AncestorAgent -or $g.Info.McpPattern -or $g.Info.HeadlessPattern -or $g.Info.IsBrowser)
        if (-not $knownAi) { $indicators += 'LlmFromNonAgentProcess' }

        $connectedMinutes = $null
        if ($g.Oldest -is [datetime]) {
            $connectedMinutes = [math]::Round(($now - $g.Oldest).TotalMinutes)
            if ($connectedMinutes -ge $Context.Options.PersistentMinutes) { $indicators += 'PersistentLlmConnection' }
        }
        if ($g.PersistentBySample) { $indicators += 'PersistentLlmConnection' }

        if ($proc) {
            if (Get-RacGenericMatch -Signatures $sig -Group 'stealthLaunch' -Text $proc.CommandLine) { $indicators += 'StealthLaunch' }
            if (Test-RacSystemAccount -User $owner) { $indicators += 'SystemContext' }
            if (Get-RacFirstRegexMatch -Text (ConvertTo-RacNormalizedText $proc.ExecutablePath) -Pattern @($sig.genericPatterns.userWritablePaths)) { $indicators += 'UserWritableExecPath' }
        }

        $evidence = [ordered]@{
            'Process'        = $procName
            'Remote host'    = $g.HostName
            'Provider'       = $g.Provider
            'Remote address' = ($g.Remotes -join ', ')
            'Open sockets'   = $g.Count
        }
        if ($proc) {
            $evidence['Executable'] = $proc.ExecutablePath
            $evidence['Command line'] = $proc.CommandLine
        }
        $evidence['Owner'] = $owner
        if ($g.Oldest) { $evidence['Connected since'] = $g.Oldest; $evidence['Open for (minutes)'] = $connectedMinutes }
        if ($sampleCount -gt 1) { $evidence['Samples'] = ('present in all {0} samples: {1}' -f $sampleCount, $g.PersistentBySample) }
        $evidence['Hostname source'] = 'local DNS client cache (no lookups performed)'

        $times = @()
        if ($g.Oldest) { $times += $g.Oldest }
        if ($proc -and $proc.CreationDate -is [datetime]) { $times += $proc.CreationDate }

        New-RacFinding -Category 'Network' -Breadcrumb 'LlmConnection' `
            -Title ('{0} connected to {1} ({2})' -f $procName, $g.HostName, $g.Provider) `
            -Agent $agentName -AgentId $agentId -Location ('{0} -> {1}' -f $procName, $g.HostName) -User $owner `
            -EventTime $g.Oldest -Evidence $evidence -Indicators $indicators -ActivityTimes $times `
            -Signals @{ RemoteHost = $g.HostName; ProcessId = $g.ProcessId }
    }

    if ($browserSuppressed -gt 0) {
        Add-RacCoverage -Source 'Browser AI sessions' -Status 'Info' -ItemCount $browserSuppressed -Detail 'Ordinary web-browser connections to AI services were counted but not itemized. Use -IncludeBrowserAiSessions to list them.'
    }

    # ---- 3. LLM hosts seen in the DNS cache with no attributable connection --
    foreach ($hostName in $llmHosts.Keys) {
        if ($connectedHosts.ContainsKey($hostName)) { continue }
        $entry = $llmHosts[$hostName]
        $evidence = [ordered]@{
            'Hostname'           = $hostName
            'Provider'           = $entry.Provider
            'Resolved addresses' = ($entry.Addresses -join ', ')
            'Note'               = 'Looked up recently (cache entries expire with their TTL). No open connection could be tied to a process at scan time. Sysmon Event 22 gives per-process DNS history.'
        }
        New-RacFinding -Category 'Network' -Breadcrumb 'DnsCacheLlm' `
            -Title ('Recent DNS lookup of {0} ({1})' -f $hostName, $entry.Provider) `
            -Agent 'Unattributed (DNS cache)' -Location ('DNS cache: ' + $hostName) `
            -EventTime $now -Evidence $evidence -Signals @{ RemoteHost = $hostName }
    }

    # ---- 4. Agent / model listeners and remote clients on their ports -------
    $ports = @{}
    foreach ($p in @($sig.localServicePorts)) { $ports[[int]$p.port] = $p }

    $listeners = [ordered]@{}
    foreach ($c in @($Context.TcpConnections)) {
        $port = [int]$c.LocalPort
        if (-not $ports.ContainsKey($port)) { continue }
        $svc = $ports[$port]
        $state = [string]$c.State
        $info = Get-RacProcessProfile -Context $Context -ProcessId ([int]$c.OwningProcess)
        if ($svc.requireAgentProcess) {
            $ownerAgentId = ''
            if ($info.AgentMatch) { $ownerAgentId = [string]$info.AgentMatch.Agent.id }
            if ($ownerAgentId -ne [string]$svc.agentId) { continue }
        }

        $key = '{0}|{1}' -f $port, $c.OwningProcess
        if (-not $listeners.Contains($key)) {
            $listeners[$key] = [pscustomobject]@{ Port = $port; Service = $svc; ProcessId = [int]$c.OwningProcess; Info = $info; Bound = @(); Clients = @() }
        }
        $l = $listeners[$key]
        if ($state -eq 'Listen') {
            $bound = ConvertTo-RacPlainIp -Address $c.LocalAddress
            if ($bound -and $l.Bound -notcontains $bound) { $l.Bound += $bound }
        }
        elseif ($state -eq 'Established') {
            $remote = ConvertTo-RacPlainIp -Address $c.RemoteAddress
            if ($remote -and -not (Test-RacLoopbackOrUnspecified -Address $remote) -and -not $localAddresses.ContainsKey($remote)) {
                $clientText = '{0}:{1}' -f $remote, $c.RemotePort
                if ($l.Clients -notcontains $clientText) { $l.Clients += $clientText }
            }
        }
    }

    foreach ($l in $listeners.Values) {
        if ($l.Bound.Count -eq 0 -and $l.Clients.Count -eq 0) { continue }
        $proc = $l.Info.Process
        $procName = 'PID ' + $l.ProcessId
        $owner = ''
        if ($proc) { $procName = '{0} (PID {1})' -f $proc.Name, $l.ProcessId; $owner = Get-RacProcessOwnerCached -Process $proc }

        $agentName = [string]$l.Service.product
        $agentId = [string]$l.Service.agentId
        if ($l.Info.AgentMatch) { $agentName = $l.Info.AgentMatch.Agent.name; $agentId = $l.Info.AgentMatch.Agent.id }
        elseif ($l.Info.AncestorAgent) { $agentName = $l.Info.AncestorAgent.name; $agentId = $l.Info.AncestorAgent.id }
        elseif ($agentId -and $sig._AgentById.ContainsKey($agentId)) { $agentName = $sig._AgentById[$agentId].name }

        $indicators = @()
        foreach ($b in $l.Bound) { if ($b -eq '0.0.0.0' -or $b -eq '::') { $indicators += 'ListensOnAllInterfaces' } }
        if ($l.Port -eq 9222) { $indicators += 'RemoteDebuggingPort' }
        if ($l.Clients.Count -gt 0) { $indicators += 'RemoteClientOnAgentPort' }

        $evidence = [ordered]@{
            'Port'           = $l.Port
            'Service'        = $l.Service.product
            'Bound to'       = ($l.Bound -join ', ')
            'Remote clients' = ($l.Clients -join ', ')
            'Process'        = $procName
            'Owner'          = $owner
        }
        if ($proc) { $evidence['Executable'] = $proc.ExecutablePath }

        $title = '{0} listening on port {1} ({2})' -f $agentName, $l.Port, $l.Service.product
        if ($agentName -eq [string]$l.Service.product) { $title = '{0} listening on port {1}' -f $agentName, $l.Port }
        if ($indicators -contains 'ListensOnAllInterfaces') { $title += ' on ALL network interfaces' }

        New-RacFinding -Category 'Network' -Breadcrumb 'AgentListener' -Title $title `
            -Agent $agentName -AgentId $agentId -Location ('TCP {0} ({1})' -f $l.Port, $procName) -User $owner `
            -EventTime $now -Evidence $evidence -Indicators $indicators
    }

    # ---- 5. Proxy logs (optional) -------------------------------------------
    $proxyHits = [ordered]@{}
    $linesTotal = 0
    $files = @()
    foreach ($p in @($Context.ProxyLogPaths)) {
        if (-not $p) { continue }
        $info = Get-RacItemInfo -Path $p
        if (-not $info) {
            Add-RacCoverage -Source "Proxy log: $p" -Status 'Skipped' -Detail 'Path not found.'
            continue
        }
        if ($info.IsDirectory) {
            $files += @(Get-RacChildItem -Path $p -File -MaxItems 50 | Where-Object { $_.Name -match '\.(log|txt|csv)$' -or $_.Name -match 'access' })
        }
        else {
            $files += $info
        }
    }
    foreach ($f in $files) {
        $result = Get-RacRegexCaptureCount -Path $f.FullName -Pattern $sig._EndpointRegex
        $linesTotal += $result.LinesRead
        $detail = ''
        if ($result.Truncated) { $detail = 'Stopped at the line cap; later lines not counted.' }
        Add-RacCoverage -Source ('Proxy log: ' + $f.FullName) -Status 'Checked' -ItemCount $result.LinesRead -Detail $detail
        foreach ($hostName in $result.Counts.Keys) {
            if (-not $proxyHits.Contains($hostName)) { $proxyHits[$hostName] = [pscustomobject]@{ Count = 0; Files = @() } }
            $proxyHits[$hostName].Count += [int]$result.Counts[$hostName]
            if ($proxyHits[$hostName].Files -notcontains $f.Name) { $proxyHits[$hostName].Files += $f.Name }
        }
    }
    foreach ($hostName in $proxyHits.Keys) {
        $endpoint = Find-RacLlmEndpoint -Signatures $sig -HostName $hostName
        $provider = 'LLM provider'
        if ($endpoint) { $provider = [string]$endpoint.provider }
        $evidence = [ordered]@{
            'Hostname'           = $hostName
            'Provider'           = $provider
            'Matching log lines' = $proxyHits[$hostName].Count
            'Log files'          = ($proxyHits[$hostName].Files -join ', ')
            'Lines scanned'      = $linesTotal
        }
        New-RacFinding -Category 'Network' -Breadcrumb 'ProxyLogLlm' `
            -Title ('{0} requests to {1} in proxy logs' -f $proxyHits[$hostName].Count, $hostName) `
            -Agent 'Unattributed (proxy log)' -Location ('Proxy logs: ' + $hostName) `
            -EventTime $now -Evidence $evidence -Signals @{ RemoteHost = $hostName }
    }
}
