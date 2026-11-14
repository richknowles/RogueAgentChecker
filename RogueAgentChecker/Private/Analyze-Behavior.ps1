<#
    Analyze-Behavior.ps1 - Category 7: behavioral flags derived from the other
    six categories. Runs last.

      * Off-hours activity ...... agent activity timestamps outside business hours
      * Cross-app reach ......... one agent identity wired into many app categories,
                                  including the "lethal trifecta": private data +
                                  untrusted input + an outbound channel
      * Package installs ........ agents installing software, or agent software
                                  installed recently
      * Self-modification ....... recent writes to an agent's own skills, memory
                                  or instruction files
#>

function Find-RacBehaviorFinding {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [object[]]$Findings = @()
    )

    $sig = $Context.Signatures
    $opt = $Context.Options

    # ---- Off-hours activity, per agent -----------------------------------------
    $byAgent = [ordered]@{}
    foreach ($f in $Findings) {
        if (-not $f -or @($f.ActivityTimes).Count -eq 0) { continue }
        # Known agents get one timeline each. Unidentified things are kept apart by
        # location, so unrelated processes are never merged into one "agent".
        $key = 'id:' + $f.AgentId
        if (-not $f.AgentId) { $key = 'loc:' + $f.Location }
        if (-not $byAgent.Contains($key)) {
            $byAgent[$key] = [pscustomobject]@{ Agent = $f.Agent; AgentId = $f.AgentId; Location = $f.Location; Times = @(); Users = @(); Sources = @() }
        }
        $g = $byAgent[$key]
        foreach ($t in @($f.ActivityTimes)) {
            if ($t -is [datetime] -and $t -ge $Context.LookbackStart -and $t -le $Context.Now) { $g.Times += $t }
        }
        foreach ($u in @(([string]$f.User) -split ',\s*')) {
            $leaf = Get-RacUserLeaf $u
            if ($leaf -and $g.Users -notcontains $leaf) { $g.Users += $leaf }
        }
        if ($g.Sources -notcontains $f.Breadcrumb) { $g.Sources += $f.Breadcrumb }
    }
    foreach ($g in $byAgent.Values) {
        $times = @($g.Times | Sort-Object -Unique)
        if ($times.Count -eq 0) { continue }
        $off = @($times | Where-Object { Test-RacOffHours -Time $_ -StartHour $opt.BusinessHoursStart -EndHour $opt.BusinessHoursEnd -BusinessDays $opt.BusinessDays })
        if ($off.Count -lt $opt.OffHoursMinEvents) { continue }
        $examples = @($off | Sort-Object -Descending | Select-Object -First 5 | ForEach-Object { $_.ToString('ddd yyyy-MM-dd HH:mm') })
        $evidence = [ordered]@{
            'Off-hours timestamps' = ('{0} of {1} in the last {2} days' -f $off.Count, $times.Count, $opt.LookbackDays)
            'Business hours'       = ('{0:00}:00-{1:00}:00, {2}' -f $opt.BusinessHoursStart, $opt.BusinessHoursEnd, ($opt.BusinessDays -join ', '))
            'Most recent'          = ($examples -join '; ')
            'Evidence from'        = ($g.Sources -join ', ')
            'Users'                = ($g.Users -join ', ')
        }
        New-RacFinding -Category 'Behavior' -Breadcrumb 'OffHoursActivity' `
            -Title ('{0} active outside business hours ({1} times)' -f $g.Agent, $off.Count) `
            -Agent $g.Agent -AgentId $g.AgentId -Location ('Activity timeline: ' + $g.Location) -User (@($g.Users) -join ', ') `
            -EventTime ($off | Sort-Object -Descending | Select-Object -First 1) -Evidence $evidence -Indicators @('OffHoursActivity')
    }

    # ---- Cross-app reach (MCP), per agent + user --------------------------------
    $reach = [ordered]@{}
    foreach ($f in $Findings) {
        if (-not $f -or $f.Breadcrumb -ne 'McpServerConfig') { continue }
        if ($f.Signals -and $f.Signals.Disabled) { continue }
        $key = '{0}|{1}' -f $f.AgentId, $f.User
        if (-not $reach.Contains($key)) {
            $reach[$key] = [pscustomobject]@{ Agent = $f.Agent; AgentId = $f.AgentId; User = $f.User; Categories = @(); Servers = @(); Ids = @() }
        }
        $r = $reach[$key]
        foreach ($c in @($f.AppCategories)) { if ($r.Categories -notcontains $c) { $r.Categories += $c } }
        $serverName = ''
        if ($f.Signals) { $serverName = [string]$f.Signals.ServerName }
        if ($serverName -and $r.Servers -notcontains $serverName) { $r.Servers += $serverName }
        $r.Ids += $f.FindingId
    }
    $roles = $sig.mcpCategoryRoles
    foreach ($r in $reach.Values) {
        $cats = @($r.Categories | Sort-Object)
        $indicators = @()
        if ($cats.Count -ge $opt.CrossAppMinCategories) { $indicators += 'CrossAppReach' }

        $hasPrivate = @($cats | Where-Object { @($roles.privateData) -contains $_ }).Count -gt 0
        $hasUntrusted = @($cats | Where-Object { @($roles.untrustedInput) -contains $_ }).Count -gt 0
        $hasOutbound = @($cats | Where-Object { @($roles.externalComms) -contains $_ }).Count -gt 0
        if ($cats.Count -ge 2 -and $hasPrivate -and $hasUntrusted -and $hasOutbound) { $indicators += 'LethalTrifecta' }
        if ($indicators.Count -eq 0) { continue }

        $evidence = [ordered]@{
            'App categories'     = ($cats -join ', ')
            'MCP servers'        = ($r.Servers -join ', ')
            'Private data'       = $(if ($hasPrivate) { 'yes' } else { 'no' })
            'Untrusted input'    = $(if ($hasUntrusted) { 'yes' } else { 'no' })
            'Outbound channel'   = $(if ($hasOutbound) { 'yes' } else { 'no' })
            'Related findings'   = ($r.Ids -join ', ')
        }
        $title = '{0} for {1} can act across {2} app categories' -f $r.Agent, $r.User, $cats.Count
        if ($indicators -contains 'LethalTrifecta') { $title += ' (private data + untrusted input + outbound channel)' }
        New-RacFinding -Category 'Behavior' -Breadcrumb 'CrossAppReach' -Title $title `
            -Agent $r.Agent -AgentId $r.AgentId -Location ('MCP configuration of ' + $r.Agent) -User $r.User `
            -Evidence $evidence -Indicators $indicators -AppCategories $cats
    }

    # ---- Package installs, per agent ---------------------------------------------
    $installs = [ordered]@{}
    foreach ($p in $Context.BehaviorSignals.PackageInstalls.ToArray()) {
        $key = $p.AgentId
        if (-not $key) { $key = 'name:' + $p.Agent }
        if (-not $installs.Contains($key)) { $installs[$key] = [pscustomobject]@{ Agent = $p.Agent; AgentId = $p.AgentId; Items = @(); Users = @() } }
        $installs[$key].Items += $p
        $leaf = Get-RacUserLeaf $p.User
        if ($leaf -and $installs[$key].Users -notcontains $leaf) { $installs[$key].Users += $leaf }
    }
    foreach ($g in $installs.Values) {
        $indicators = @()
        if (@($g.Items | Where-Object { $_.ByAgent }).Count -gt 0) { $indicators += 'AgentInstallsPackages' }
        if (@($g.Items | Where-Object { -not $_.ByAgent }).Count -gt 0) { $indicators += 'RecentPackageInstall' }
        $sorted = @($g.Items | Sort-Object Time -Descending)
        $evidence = [ordered]@{
            'Installs'      = $g.Items.Count
            'Launched by the agent itself' = @($g.Items | Where-Object { $_.ByAgent }).Count
            'Most recent'   = (($sorted | Select-Object -First 5 | ForEach-Object { '{0} {1} [{2}]' -f (Format-RacTime $_.Time), $_.What, $_.Source }) -join ' | ')
            'Users'         = ($g.Users -join ', ')
        }
        New-RacFinding -Category 'Behavior' -Breadcrumb 'PackageInstallActivity' `
            -Title ('{0}: {1} package install(s) in the last {2} days' -f $g.Agent, $g.Items.Count, $opt.LookbackDays) `
            -Agent $g.Agent -AgentId $g.AgentId -Location ('Install activity: ' + $g.Agent) -User ($g.Users -join ', ') `
            -EventTime ($sorted | Select-Object -First 1).Time -Evidence $evidence -Indicators $indicators `
            -ActivityTimes @($g.Items | ForEach-Object { $_.Time })
    }

    # ---- Self-modification, per agent + user ------------------------------------
    $mods = [ordered]@{}
    foreach ($m in $Context.BehaviorSignals.SelfMod.ToArray()) {
        $userLeaf = Get-RacUserLeaf $m.User
        $key = '{0}|{1}' -f $m.AgentId, $userLeaf
        if (-not $mods.Contains($key)) { $mods[$key] = [pscustomobject]@{ Agent = $m.Agent; AgentId = $m.AgentId; User = $userLeaf; Items = @() } }
        $mods[$key].Items += $m
    }
    foreach ($g in $mods.Values) {
        $indicators = @('SelfModification')
        $byAgent = @($g.Items | Where-Object { $_.ByAgentProcess })
        if ($byAgent.Count -gt 0) { $indicators += 'SelfModificationByAgent' }
        $sorted = @($g.Items | Sort-Object Time -Descending)
        $uniquePaths = @($sorted | ForEach-Object { ConvertTo-RacNormalizedText $_.Path } | Select-Object -Unique)
        $short = @($uniquePaths | Select-Object -First 6 | ForEach-Object {
                $parts = @(([string]$_) -split '[\\/]' | Where-Object { $_ })
                ($parts | Select-Object -Last 3) -join '/'
            })
        $evidence = [ordered]@{
            'Files changed'          = $uniquePaths.Count
            'Newest change'          = $sorted[0].Time
            'Examples'               = ($short -join ', ')
            'Written by agent process' = $(if ($byAgent.Count -gt 0) { 'yes (' + (($byAgent | ForEach-Object { $_.Source } | Select-Object -Unique) -join ', ') + ')' } else { 'unknown (file timestamps only)' })
        }
        New-RacFinding -Category 'Behavior' -Breadcrumb 'SelfModification' `
            -Title ('{0} skills / memory changed for {1} ({2} file(s) in the last {3} days)' -f $g.Agent, $g.User, $uniquePaths.Count, $opt.LookbackDays) `
            -Agent $g.Agent -AgentId $g.AgentId -Location ('Skills and memory of ' + $g.Agent) -User $g.User `
            -EventTime $sorted[0].Time -Evidence $evidence -Indicators $indicators `
            -ActivityTimes @($sorted | Select-Object -First 200 | ForEach-Object { $_.Time })
    }
}
