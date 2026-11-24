<#
    Analyze-Persistence.ps1 - Category 4: how agents survive a reboot without a
    person starting them. Scheduled tasks, services, Run/RunOnce keys, Startup
    folders, and WMI event subscriptions.

    Each autostart command is matched with the same signature logic used for
    processes. When the command itself looks ordinary, RAC also looks inside the
    script or encoded command it runs (Get-RacScriptLlmUse; read, never run).
    Every WMI command/script consumer is reported, attributed or not,
    because that mechanism is rarely legitimate and is a favourite hiding place.
#>

function Get-RacAutostartMatch {
    <#
        Decides whether an autostart entry belongs to an AI agent.
        Returns @{ AgentName; AgentId; Reason } or $null.
    #>
    param($Context, [AllowEmptyString()][string]$CommandText, [AllowEmptyString()][string]$NameText)

    $sig = $Context.Signatures
    $m = Find-RacAgentByText -Signatures $sig -Text $CommandText
    if (-not $m -and $NameText) { $m = Find-RacAgentByText -Signatures $sig -Text $NameText -KeywordsOnly }
    if ($m) { return [pscustomobject]@{ AgentName = [string]$m.Agent.name; AgentId = [string]$m.Agent.id; Reason = $m.Reason } }

    $mcp = Get-RacGenericMatch -Signatures $sig -Group 'mcpServer' -Text $CommandText
    if ($mcp) { return [pscustomobject]@{ AgentName = 'Unidentified MCP server'; AgentId = ''; Reason = "launches an MCP server (/$mcp/)" } }

    $headless = Get-RacGenericMatch -Signatures $sig -Group 'headlessBrowser' -Text $CommandText
    if ($headless) { return [pscustomobject]@{ AgentName = 'Unattributed browser automation'; AgentId = ''; Reason = "launches browser automation (/$headless/)" } }

    $normalized = ConvertTo-RacNormalizedText $CommandText
    if ($normalized -and $sig._EndpointRegex -and $normalized -match $sig._EndpointRegex) {
        return [pscustomobject]@{ AgentName = 'Unidentified agent'; AgentId = ''; Reason = 'command calls an LLM API (' + $Matches[1] + ')' }
    }

    # The command itself looks ordinary: look at the script or encoded command it
    # runs (see Get-RacScriptLlmUse; files are read, never run).
    $use = Get-RacScriptLlmUse -Context $Context -CommandLine $CommandText
    if ($use) {
        $extra = @()
        if ($use.Calls) { $extra += 'LlmCallFromScript' }
        return [pscustomobject]@{ AgentName = 'Unidentified agent'; AgentId = ''; Reason = (Format-RacScriptLlmReason -Use $use); Indicators = $extra; ScriptUse = $use }
    }
    return $null
}

function Add-RacScriptEvidence {
    <# Adds the script details of an autostart match to its evidence (names only, redacted sample). #>
    param($Evidence, $Match)
    $use = $Match.ScriptUse
    if (-not $use) { return }
    if ($use.ScriptPath) { $Evidence['Script'] = $use.ScriptPath }
    if ($use.HostName) { $Evidence['LLM host referenced'] = $use.HostName }
    if ($use.Sdk) { $Evidence['AI SDK'] = $use.Sdk }
    if ($use.KeyNames.Count -gt 0) { $Evidence['Key variables used'] = ($use.KeyNames -join ', ') }
    $Evidence['Sample (redacted)'] = $use.Sample
}

function Get-RacCommonAutostartIndicator {
    param($Context, [string]$CommandText, [string]$RunAs)
    $sig = $Context.Signatures
    $indicators = @('PersistenceAutostart')
    if (Get-RacGenericMatch -Signatures $sig -Group 'stealthLaunch' -Text $CommandText) { $indicators += 'StealthLaunch' }
    if (Get-RacFirstRegexMatch -Text (ConvertTo-RacNormalizedText $CommandText) -Pattern @($sig.genericPatterns.userWritablePaths)) { $indicators += 'UserWritableExecPath' }
    if (Test-RacSystemAccount -User $RunAs) { $indicators += 'SystemContext' }
    return $indicators
}

function Find-RacPersistenceFinding {
    param([Parameter(Mandatory = $true)]$Context)

    # ---- Scheduled tasks ------------------------------------------------------
    foreach ($t in @(Get-RacRawScheduledTask)) {
        if (-not $t) { continue }
        $taskName = '{0}{1}' -f $t.TaskPath, $t.TaskName
        foreach ($a in @($t.Actions)) {
            $commandText = ('{0} {1}' -f $a.Execute, $a.Arguments).Trim()
            $match = Get-RacAutostartMatch -Context $Context -CommandText $commandText -NameText $taskName
            if (-not $match) { continue }

            $indicators = @(Get-RacCommonAutostartIndicator -Context $Context -CommandText $commandText -RunAs $t.UserId)
            if ($t.Hidden) { $indicators += 'HiddenTask' }
            if ($match.Indicators) { $indicators += @($match.Indicators) }

            $run = Get-RacScheduledTaskRunInfo -TaskPath $t.TaskPath -TaskName $t.TaskName
            $evidence = [ordered]@{
                'Task'            = $taskName
                'State'           = $t.State
                'Runs as'         = $t.UserId
                'Run level'       = $t.RunLevel
                'Action'          = $commandText
                'Working folder'  = $a.WorkingDirectory
                'Triggers'        = ($t.Triggers -join ', ')
                'Hidden'          = $t.Hidden
                'Author'          = $t.Author
                'Registered'      = $t.RegistrationDate
                'Matched because' = $match.Reason
            }
            Add-RacScriptEvidence -Evidence $evidence -Match $match
            $times = @()
            if ($run) {
                $evidence['Last run'] = $run.LastRunTime
                $evidence['Next run'] = $run.NextRunTime
                if ($run.LastRunTime -is [datetime] -and $run.LastRunTime.Year -gt 2000) { $times += $run.LastRunTime }
            }
            $user = $t.UserId
            if (-not $user) { $user = $t.Author }
            New-RacFinding -Category 'Persistence' -Breadcrumb 'ScheduledTask' `
                -Title ("Scheduled task '{0}' starts {1}" -f $taskName, $match.AgentName) `
                -Agent $match.AgentName -AgentId $match.AgentId -Location ('Task Scheduler: ' + $taskName) -User $user `
                -EventTime ($times | Select-Object -First 1) -Evidence $evidence -Indicators $indicators -ActivityTimes $times
        }
    }

    # ---- Services ---------------------------------------------------------------
    foreach ($s in @(Get-RacRawService)) {
        if (-not $s) { continue }
        $match = Get-RacAutostartMatch -Context $Context -CommandText $s.PathName -NameText ('{0} {1}' -f $s.Name, $s.DisplayName)
        if (-not $match) { continue }
        $indicators = @(Get-RacCommonAutostartIndicator -Context $Context -CommandText $s.PathName -RunAs $s.StartName)
        if ($s.StartMode -notmatch '^Auto') { $indicators = @($indicators | Where-Object { $_ -ne 'PersistenceAutostart' }) }
        if ($match.Indicators) { $indicators += @($match.Indicators) }
        $evidence = [ordered]@{
            'Service'         = '{0} ({1})' -f $s.Name, $s.DisplayName
            'Binary path'     = $s.PathName
            'Start mode'      = $s.StartMode
            'State'           = $s.State
            'Runs as'         = $s.StartName
            'Process ID'      = $(if ($s.ProcessId -gt 0) { $s.ProcessId } else { $null })
            'Matched because' = $match.Reason
        }
        Add-RacScriptEvidence -Evidence $evidence -Match $match
        New-RacFinding -Category 'Persistence' -Breadcrumb 'Service' `
            -Title ("Service '{0}' runs {1}" -f $s.Name, $match.AgentName) `
            -Agent $match.AgentName -AgentId $match.AgentId -Location ('Service: ' + $s.Name) -User $s.StartName `
            -Evidence $evidence -Indicators $indicators
    }

    # ---- Run / RunOnce keys -----------------------------------------------------
    foreach ($r in @(Get-RacRawRunKey)) {
        if (-not $r) { continue }
        $match = Get-RacAutostartMatch -Context $Context -CommandText $r.Command -NameText $r.ValueName
        if (-not $match) { continue }
        $indicators = @(Get-RacCommonAutostartIndicator -Context $Context -CommandText $r.Command -RunAs '')
        if ($match.Indicators) { $indicators += @($match.Indicators) }
        $evidence = [ordered]@{
            'Registry key'    = $r.KeyPath
            'Value name'      = $r.ValueName
            'Command'         = $r.Command
            'Applies to'      = $(if ($r.User) { $r.User } else { 'all users (HKLM)' })
            'Matched because' = $match.Reason
        }
        Add-RacScriptEvidence -Evidence $evidence -Match $match
        New-RacFinding -Category 'Persistence' -Breadcrumb 'RunKey' `
            -Title ("Run key '{0}' starts {1} at logon" -f $r.ValueName, $match.AgentName) `
            -Agent $match.AgentName -AgentId $match.AgentId -Location ('{0}\{1}' -f $r.KeyPath, $r.ValueName) -User $r.User `
            -Evidence $evidence -Indicators $indicators
    }

    # ---- Startup folders --------------------------------------------------------
    foreach ($s in @(Get-RacRawStartupItem -ProfileRoot @($Context.ProfileRoots))) {
        if (-not $s) { continue }
        $commandText = ('"{0}" {1}' -f $s.TargetPath, $s.Arguments).Trim()
        $match = Get-RacAutostartMatch -Context $Context -CommandText $commandText -NameText (((Get-RacLeafName $s.Path) -replace '\.[^.]+$', ''))
        if (-not $match) { continue }
        $indicators = @(Get-RacCommonAutostartIndicator -Context $Context -CommandText $commandText -RunAs '')
        if ($match.Indicators) { $indicators += @($match.Indicators) }
        $evidence = [ordered]@{
            'Startup entry'   = $s.Path
            'Target'          = $s.TargetPath
            'Arguments'       = $s.Arguments
            'Created / changed' = $s.LastWriteTime
            'Matched because' = $match.Reason
        }
        Add-RacScriptEvidence -Evidence $evidence -Match $match
        New-RacFinding -Category 'Persistence' -Breadcrumb 'StartupItem' `
            -Title ("Startup folder entry '{0}' starts {1}" -f (Split-Path -Leaf $s.Path), $match.AgentName) `
            -Agent $match.AgentName -AgentId $match.AgentId -Location $s.Path -User $s.User `
            -EventTime $s.LastWriteTime -Evidence $evidence -Indicators $indicators -ActivityTimes @($s.LastWriteTime)
    }

    # ---- WMI event subscriptions -------------------------------------------------
    foreach ($w in @(Get-RacRawWmiSubscription)) {
        if (-not $w) { continue }
        if (@('CommandLineEventConsumer', 'ActiveScriptEventConsumer') -notcontains $w.ClassName) { continue }
        $text = ('{0} {1}' -f $w.CommandLine, $w.ScriptText).Trim()
        $match = Get-RacAutostartMatch -Context $Context -CommandText $text -NameText $w.Name
        $agentName = 'Unattributed WMI consumer'
        $agentId = ''
        $reason = 'Every command-line or script WMI consumer is reported.'
        if ($match) { $agentName = $match.AgentName; $agentId = $match.AgentId; $reason = $match.Reason }

        $indicators = @('PersistenceWmi')
        if (Get-RacGenericMatch -Signatures $Context.Signatures -Group 'stealthLaunch' -Text $text) { $indicators += 'StealthLaunch' }
        if ($match -and $match.Indicators) { $indicators += @($match.Indicators) }
        $evidence = [ordered]@{
            'Consumer'        = $w.Name
            'Consumer type'   = $w.ClassName
            'Command line'    = $w.CommandLine
            'Script'          = $w.ScriptText
            'Filter'          = $w.FilterName
            'Trigger query'   = $w.FilterQuery
            'Matched because' = $reason
        }
        if ($match) { Add-RacScriptEvidence -Evidence $evidence -Match $match }
        New-RacFinding -Category 'Persistence' -Breadcrumb 'WmiSubscription' `
            -Title ("WMI event subscription '{0}' runs {1}" -f $w.Name, $agentName) `
            -Agent $agentName -AgentId $agentId -Location ('root\subscription: ' + $w.Name) -User (Get-RacUserFromPath -Path $text) `
            -Evidence $evidence -Indicators $indicators
    }
}
