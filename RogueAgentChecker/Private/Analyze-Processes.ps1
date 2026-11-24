<#
    Analyze-Processes.ps1 - Category 1: long-running agent processes, headless
    browsers, MCP servers.

    Input : $Context.Processes (from Get-RacRawProcess)
    Output: findings with Breadcrumb AgentProcess, McpServerProcess, HeadlessBrowser,
            LlmScriptProcess

    Every process is profiled once (Get-RacProcessProfile) and the result is
    cached, because the network analyzer asks the same questions about the
    processes that own LLM connections.
#>

# ---------------------------------------------------------------------------
# What a command runs: script files and encoded commands
# ---------------------------------------------------------------------------
# Added in 0.1.1 after the live test. A hidden PowerShell kept ONE connection to
# api.openai.com open for over an hour. Windows keeps that hostname in the DNS
# cache for only 60 seconds, so the network check could name the connection
# only in the first minute. What a process runs does not expire: RAC reads the
# script file a command line names (read-only, local files only, capped at 1 MB)
# and decodes -EncodedCommand payloads, then looks inside. Nothing is ever run.
# The same helper serves the process scan and every autostart type.

$script:RacScriptExtensions = 'ps1|psm1|vbs|js|mjs|cjs|wsf|py|pyw|cmd|bat'
$script:RacWebCallPattern = 'invoke-restmethod|invoke-webrequest|\birm\b|\biwr\b|curl|wget|httpclient|webclient|net\.http|requests\.(get|post)|httpx|urllib|aiohttp|\bfetch\(|xmlhttp|winhttp'

function Test-RacLocalFilePath {
    <#
        True for an absolute path on a local drive. Network paths (\\server\share,
        mapped network drives) are never opened: reading one would send traffic
        off the machine.
    #>
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $false }
    if ($Path -match '^(\\\\|//)') { return $false }
    if ($Path -match '^([A-Za-z]):[\\/]') {
        return (@('Fixed', 'Removable', 'Ram', 'CDRom') -contains (Get-RacDriveType -Letter $Matches[1]))
    }
    return $Path.StartsWith('/')   # absolute path on Linux or macOS (the test suite)
}

function Get-RacScriptPathFromCommand {
    <#
        Absolute paths of the script files a command line names, quoted or bare.
        Relative paths and paths with unexpanded %VARIABLES% are skipped: RAC does
        not guess whose working folder or profile they point into.
    #>
    param([AllowEmptyString()][string]$CommandLine)
    $found = @()
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $found }
    $ext = '\.(?:' + $script:RacScriptExtensions + ')'
    $pattern = '"([^"]+' + $ext + ')"|''([^'']+' + $ext + ')''|(?:^|[\s=])([^\s"''=]+' + $ext + ')(?=$|[\s"''])'
    foreach ($m in [regex]::Matches($CommandLine, $pattern, 'IgnoreCase')) {
        $p = $m.Groups[1].Value
        if (-not $p) { $p = $m.Groups[2].Value }
        if (-not $p) { $p = $m.Groups[3].Value }
        if (-not $p -or $p.Contains('%')) { continue }
        if ($p -notmatch '^([A-Za-z]:[\\/]|[\\/])') { continue }
        if ($found -notcontains $p) { $found += $p }
    }
    return $found
}

function ConvertFrom-RacEncodedCommand {
    <#
        The script inside 'powershell -EncodedCommand <base64>' (or -enc, -e, -ec),
        decoded the way PowerShell decodes it (UTF-16LE). Text only; nothing is run.
    #>
    param([AllowEmptyString()][string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    foreach ($m in [regex]::Matches($CommandLine, '(?:^|\s)[-/]([a-z]+)\s+([a-z0-9+/]{8,}={0,2})(?=\s|"|$)', 'IgnoreCase')) {
        $switch = $m.Groups[1].Value.ToLowerInvariant()
        if ($switch -ne 'ec' -and -not 'encodedcommand'.StartsWith($switch)) { continue }
        try { return [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($m.Groups[2].Value)) }
        catch { continue }
    }
    return $null
}

function Get-RacAiKeyName {
    <# AI key VARIABLE NAMES a text mentions (OPENAI_API_KEY, ...). Names only: values are never read out. #>
    param($Signatures, [AllowEmptyString()][string]$Text)
    $names = @()
    if ([string]::IsNullOrEmpty($Text) -or -not $Signatures.secretEnvNamePattern) { return $names }
    foreach ($m in [regex]::Matches($Text, '[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET)\b', 'IgnoreCase')) {
        $n = $m.Value.ToUpperInvariant()
        if ($n -match $Signatures.secretEnvNamePattern -and $names -notcontains $n) { $names += $n }
    }
    return $names
}

function Get-RacScriptFileText {
    <# Text of a script file, read at most once per scan. Local files only, 1 MB cap. #>
    param($Context, [string]$Path)
    $cache = $Context.ScriptTexts
    if ($null -ne $cache -and $cache.ContainsKey($Path)) { return $cache[$Path] }
    $text = $null
    if (Test-RacLocalFilePath -Path $Path) { $text = Read-RacTextFile -Path $Path -MaxBytes 1MB }
    if ($null -ne $cache) { $cache[$Path] = $text }
    return $text
}

function Get-RacScriptLlmUse {
    <#
        Does a command use an AI API through what it runs? Looks at, in order:
          - the command line itself (only with -IncludeCommandLine; LLM host names only)
          - a -EncodedCommand payload, decoded
          - each script file the command line names
        A decoded command or script counts when it names an LLM API host, imports
        an AI SDK, or uses an AI key variable. Returns $null or one object with
        Kind, ScriptPath, HostName, Sdk, KeyNames, Calls and a redacted Sample.
        Key values are never returned.
    #>
    param($Context, [AllowEmptyString()][string]$CommandLine, [switch]$IncludeCommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $sig = $Context.Signatures

    $sources = @()
    if ($IncludeCommandLine) { $sources += [pscustomobject]@{ Kind = 'CommandLine'; Text = $CommandLine; Path = '' } }
    $decoded = ConvertFrom-RacEncodedCommand -CommandLine $CommandLine
    if ($decoded) { $sources += [pscustomobject]@{ Kind = 'EncodedCommand'; Text = $decoded; Path = '' } }
    foreach ($path in @(Get-RacScriptPathFromCommand -CommandLine $CommandLine)) {
        $text = Get-RacScriptFileText -Context $Context -Path $path
        if ($text) { $sources += [pscustomobject]@{ Kind = 'ScriptFile'; Text = $text; Path = $path } }
    }

    foreach ($s in $sources) {
        $normalized = ConvertTo-RacNormalizedText $s.Text
        $hostName = $null
        if ($sig._EndpointRegex -and $normalized -match $sig._EndpointRegex) { $hostName = $Matches[1] }
        $sdk = $null
        $keyNames = @()
        if ($s.Kind -ne 'CommandLine') {
            $sdkPattern = Get-RacFirstRegexMatch -Text $normalized -Pattern @($sig.genericPatterns.llmSdkUse)
            if ($sdkPattern) { $sdk = ([regex]::Match($normalized, $sdkPattern).Value -replace '\s+', ' ').Trim() }
            $keyNames = @(Get-RacAiKeyName -Signatures $sig -Text $s.Text)
        }
        if (-not $hostName -and -not $sdk -and $keyNames.Count -eq 0) { continue }

        $samplePattern = '.'
        if ($hostName) { $samplePattern = [regex]::Escape($hostName) }
        elseif ($sdk) { $samplePattern = [regex]::Escape($sdk) }
        elseif ($keyNames.Count -gt 0) { $samplePattern = [regex]::Escape($keyNames[0]) }

        return [pscustomobject]@{
            Kind       = $s.Kind
            ScriptPath = $s.Path
            HostName   = $hostName
            Sdk        = $sdk
            KeyNames   = $keyNames
            Calls      = [bool]($sdk -or ($hostName -and $normalized -match $script:RacWebCallPattern))
            Sample     = (Get-RacSnippet -Text $s.Text -Pattern $samplePattern)
        }
    }
    return $null
}

function Format-RacScriptLlmUse {
    <# 'calls api.openai.com', 'uses an AI SDK (import openai)', 'uses AI keys (OPENAI_API_KEY)'. #>
    param($Use)
    if ($Use.HostName -and $Use.Calls) { return 'calls ' + $Use.HostName }
    if ($Use.HostName) { return 'references ' + $Use.HostName }
    if ($Use.Sdk) { return 'uses an AI SDK (' + $Use.Sdk + ')' }
    return 'uses AI keys (' + ($Use.KeyNames -join ', ') + ')'
}

function Format-RacScriptLlmReason {
    <# One sentence for 'Matched because': what runs, and what it does with AI. #>
    param($Use)
    $what = Format-RacScriptLlmUse -Use $Use
    $keys = ''
    if ($Use.KeyNames.Count -gt 0 -and $what -notlike 'uses AI keys*') { $keys = ' (key variables: ' + ($Use.KeyNames -join ', ') + ')' }
    switch ($Use.Kind) {
        'ScriptFile' { return ('runs the script {0}, which {1}{2}' -f $Use.ScriptPath, $what, $keys) }
        'EncodedCommand' { return ('runs an encoded PowerShell command that {0}{1}' -f $what, $keys) }
        default { return ('command line {0}' -f $what) }
    }
}

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

        # Not a known agent: is it running a script (or encoded command) that uses
        # an AI API? Processes started by a known agent are covered by that agent.
        $scriptUse = $null
        if (-not $info.AgentMatch -and -not $info.McpPattern -and -not $info.HeadlessPattern) {
            if ($info.AncestorAgent -or $info.IsBrowser) { continue }
            $scriptUse = Get-RacScriptLlmUse -Context $Context -CommandLine $proc.CommandLine -IncludeCommandLine
            if (-not $scriptUse) { continue }
        }

        $cmd = ConvertTo-RacNormalizedText $proc.CommandLine
        $pathText = ConvertTo-RacNormalizedText $proc.ExecutablePath

        # --- What is it, and whose is it? -----------------------------------
        $agentName = ''
        $agentId = ''
        if ($scriptUse) {
            $agentName = 'Unidentified script'
        }
        elseif ($info.AgentMatch) {
            $agentName = [string]$info.AgentMatch.Agent.name
            $agentId = [string]$info.AgentMatch.Agent.id
        }
        elseif ($info.AncestorAgent) {
            $agentName = [string]$info.AncestorAgent.name
            $agentId = [string]$info.AncestorAgent.id
        }

        if ($scriptUse) {
            $breadcrumb = 'LlmScriptProcess'
            $subject = 'runs a script that'
            if ($scriptUse.Kind -eq 'EncodedCommand') { $subject = 'runs an encoded command that' }
            elseif ($scriptUse.Kind -eq 'CommandLine') { $subject = 'command line' }
            $title = '{0} (PID {1}) {2} {3}' -f $proc.Name, $pidValue, $subject, (Format-RacScriptLlmUse -Use $scriptUse)
        }
        elseif ($info.McpPattern -and -not $info.AgentMatch) {
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
        $runsFrom = $pathText
        if ($scriptUse -and $scriptUse.ScriptPath) { $runsFrom += ' ' + (ConvertTo-RacNormalizedText $scriptUse.ScriptPath) }
        if (Get-RacFirstRegexMatch -Text $runsFrom -Pattern @($sig.genericPatterns.userWritablePaths)) { $indicators += 'UserWritableExecPath' }
        if ($scriptUse -and $scriptUse.Calls) { $indicators += 'LlmCallFromScript' }
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
        $signals = @{ ProcessId = $pidValue }
        if ($scriptUse) {
            $evidence['Found in'] = @{ ScriptFile = 'the script file it runs'; EncodedCommand = 'its encoded command (decoded, not run)'; CommandLine = 'its command line' }[$scriptUse.Kind]
            if ($scriptUse.ScriptPath) { $evidence['Script'] = $scriptUse.ScriptPath }
            if ($scriptUse.HostName) { $evidence['LLM host referenced'] = $scriptUse.HostName; $signals['RemoteHost'] = $scriptUse.HostName }
            if ($scriptUse.Sdk) { $evidence['AI SDK'] = $scriptUse.Sdk }
            if ($scriptUse.KeyNames.Count -gt 0) { $evidence['Key variables used'] = ($scriptUse.KeyNames -join ', ') }
            $evidence['Sample (redacted)'] = $scriptUse.Sample
        }

        if ($Context.Options.CheckSignatures -and $proc.ExecutablePath) {
            $signature = Get-RacFileSignature -Path $proc.ExecutablePath
            if ($signature) { $evidence['Authenticode'] = '{0}; signer: {1}' -f $signature.Status, $signature.Signer }
        }

        $location = $proc.ExecutablePath
        if ($scriptUse -and $scriptUse.ScriptPath) { $location = $scriptUse.ScriptPath }
        if (-not $location) { $location = 'PID ' + $pidValue }

        $count++
        New-RacFinding -Category 'Processes' -Breadcrumb $breadcrumb -Title $title `
            -Agent $agentName -AgentId $agentId -Location $location -User $owner `
            -EventTime $proc.CreationDate -Evidence $evidence -Indicators $indicators `
            -ActivityTimes @($proc.CreationDate) -AppCategories $categories `
            -Signals $signals
    }

    Add-RacCoverage -Source 'Process analysis' -Status 'Info' -ItemCount $count -Detail 'Agent, MCP server and browser-automation processes identified, plus processes running a script or encoded command that uses an AI API (script files are read, never run; network paths are never opened).'
}
