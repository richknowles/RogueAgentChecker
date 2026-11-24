<#
    Classify.ps1 - turns findings into Trusted / Unknown / Suspicious.

        score = sum of the weights of the finding's indicators
        if an allow-list entry matches (and has not expired):
            residual = score - weights of indicators the entry explicitly accepts
            Suspicious if residual >= threshold, else Trusted
        else:
            Suspicious if score >= threshold, else Unknown

    Not on the allow-list means FLAGGED (Unknown at minimum), never blocked.
    Every decision is written out in the finding's Reasons so an auditor can
    check the arithmetic.
#>

# ---------------------------------------------------------------------------
# Allow-list loading and validation
# ---------------------------------------------------------------------------

function ConvertTo-RacList {
    <# Accepts a JSON array or a CSV cell like "alice; CORP\alice" and returns a clean string array. #>
    param($Value)
    if ($null -eq $Value) { return @() }
    $items = @()
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        foreach ($part in ([string]$v -split ';')) {
            $p = $part.Trim()
            if ($p) { $items += $p }
        }
    }
    return $items
}

function ConvertFrom-RacAllowListRecord {
    <# Normalizes one allow-list record (from JSON or CSV) and validates it. #>
    param($Record, [int]$Index, $KnownIndicators, [System.Collections.Generic.List[string]]$Warnings)

    $name = [string](Get-RacJsonProperty -Object $Record -Name 'Name')
    if (-not $name) { $name = "Entry #$Index" }
    $agent = ([string](Get-RacJsonProperty -Object $Record -Name 'Agent')).Trim()

    $entry = [pscustomobject]@{
        Name              = $name
        Agent             = $agent
        Users             = @(ConvertTo-RacList (Get-RacJsonProperty -Object $Record -Name 'Users'))
        Computers         = @(ConvertTo-RacList (Get-RacJsonProperty -Object $Record -Name 'Computers'))
        PathPattern       = @(ConvertTo-RacList (Get-RacJsonProperty -Object $Record -Name 'PathPattern'))
        Categories        = @(ConvertTo-RacList (Get-RacJsonProperty -Object $Record -Name 'Categories'))
        Breadcrumbs       = @(ConvertTo-RacList (Get-RacJsonProperty -Object $Record -Name 'Breadcrumbs'))
        McpServers        = @(ConvertTo-RacList (Get-RacJsonProperty -Object $Record -Name 'McpServers'))
        Endpoints         = @(ConvertTo-RacList (Get-RacJsonProperty -Object $Record -Name 'Endpoints'))
        AllowedIndicators = @(ConvertTo-RacList (Get-RacJsonProperty -Object $Record -Name 'AllowedIndicators'))
        ApprovedBy        = [string](Get-RacJsonProperty -Object $Record -Name 'ApprovedBy')
        ApprovedOn        = [string](Get-RacJsonProperty -Object $Record -Name 'ApprovedOn')
        Expires           = [string](Get-RacJsonProperty -Object $Record -Name 'Expires')
        ExpiresDate       = $null
        Ticket            = [string](Get-RacJsonProperty -Object $Record -Name 'Ticket')
        Notes             = [string](Get-RacJsonProperty -Object $Record -Name 'Notes')
    }

    if (-not $agent) {
        $Warnings.Add("Allow-list entry '$name' has no Agent and was ignored. Use an agent id (see Get-RacSignature) or '*'.")
        return $null
    }
    if ($agent -eq '*' -and $entry.Categories.Count -eq 0 -and $entry.Breadcrumbs.Count -eq 0) {
        $Warnings.Add("Allow-list entry '$name' uses Agent '*' without Categories or Breadcrumbs and was ignored (it would approve everything).")
        return $null
    }
    foreach ($c in $entry.Categories) {
        if ($script:RacCategories -notcontains $c) { $Warnings.Add("Allow-list entry '$name' lists unknown category '$c'. Valid: $($script:RacCategories -join ', ').") }
    }
    foreach ($i in $entry.AllowedIndicators) {
        if ($KnownIndicators -and $KnownIndicators -notcontains $i) { $Warnings.Add("Allow-list entry '$name' accepts unknown indicator '$i'.") }
    }
    if ($entry.Expires) {
        $parsed = [datetime]::MinValue
        if ([datetime]::TryParseExact($entry.Expires, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            $entry.ExpiresDate = $parsed
        }
        else {
            $Warnings.Add("Allow-list entry '$name' has an Expires value '$($entry.Expires)' that is not yyyy-MM-dd; the entry is treated as expired.")
            $entry.ExpiresDate = [datetime]::MinValue
        }
    }
    if (-not $entry.ApprovedBy) { $Warnings.Add("Allow-list entry '$name' has no ApprovedBy. Auditors will ask who approved it.") }
    return $entry
}

function Read-RacAllowListFile {
    <# Loads an allow-list from .json (array, or { "entries": [...] }) or .csv. #>
    param([Parameter(Mandatory = $true)][string]$Path, $KnownIndicators)

    $warnings = New-Object System.Collections.Generic.List[string]
    $text = Read-RacTextFile -Path $Path -MaxBytes 5MB
    if ($null -eq $text) { throw "Allow-list not found or unreadable: $Path" }

    $records = @()
    if ($Path -match '\.csv$') {
        $records = @($text | ConvertFrom-Csv)
    }
    else {
        $parsed = ConvertFrom-RacJsonText -Text $text
        if ($null -eq $parsed) { throw "Allow-list is not valid JSON: $Path" }
        $entriesProp = Get-RacJsonProperty -Object $parsed -Name 'entries'
        if ($null -ne $entriesProp) { $records = @($entriesProp) } else { $records = @($parsed) }
    }

    $entries = @()
    $i = 0
    foreach ($r in $records) {
        $i++
        if ($null -eq $r) { continue }
        $e = ConvertFrom-RacAllowListRecord -Record $r -Index $i -KnownIndicators $KnownIndicators -Warnings $warnings
        if ($e) { $entries += $e }
    }

    return [pscustomobject]@{
        Path     = $Path
        Sha256   = (Get-RacFileSha256 -Path $Path)
        Entries  = $entries
        Warnings = $warnings.ToArray()
    }
}

# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

function Test-RacAllowListMatch {
    <# True if every constraint the entry sets is satisfied by the finding. #>
    param($Entry, $Finding, [string]$ComputerName)

    if ($Entry.Agent -ne '*') {
        if (-not (Test-RacWildcard -Value $Finding.AgentId -Pattern @($Entry.Agent)) -and -not (Test-RacWildcard -Value $Finding.Agent -Pattern @($Entry.Agent))) { return $false }
    }
    if ($Entry.Users.Count -gt 0) {
        $userMatched = $false
        foreach ($u in @(([string]$Finding.User) -split ',\s*')) {
            if (-not $u) { continue }
            if ((Test-RacWildcard -Value $u -Pattern $Entry.Users) -or (Test-RacWildcard -Value (Get-RacUserLeaf $u) -Pattern $Entry.Users)) { $userMatched = $true }
            else { $userMatched = $false; break }
        }
        if (-not $userMatched) { return $false }
    }
    if ($Entry.Computers.Count -gt 0 -and -not (Test-RacWildcard -Value $ComputerName -Pattern $Entry.Computers)) { return $false }
    if ($Entry.Categories.Count -gt 0 -and $Entry.Categories -notcontains $Finding.Category) { return $false }
    if ($Entry.Breadcrumbs.Count -gt 0 -and $Entry.Breadcrumbs -notcontains $Finding.Breadcrumb) { return $false }

    if ($Entry.PathPattern.Count -gt 0) {
        $candidates = @($Finding.Location)
        foreach ($k in @('Executable', 'File', 'Config file', 'Path', 'Install path', 'Folder', 'Location', 'Locations')) {
            if ($Finding.Evidence.Contains($k)) { $candidates += $Finding.Evidence[$k] }
        }
        $pathMatched = $false
        foreach ($c in $candidates) { if (Test-RacWildcard -Value $c -Pattern $Entry.PathPattern) { $pathMatched = $true; break } }
        if (-not $pathMatched) { return $false }
    }

    if ($Entry.McpServers.Count -gt 0) {
        if ($Finding.Breadcrumb -eq 'McpServerConfig') {
            if (-not (Test-RacWildcard -Value $Finding.Evidence['Server name'] -Pattern $Entry.McpServers)) { return $false }
        }
        elseif ($Finding.Breadcrumb -eq 'McpServerProcess') {
            $cmd = [string]$Finding.Evidence['Command line']
            $hit = $false
            foreach ($s in $Entry.McpServers) { if ($cmd -like ('*' + $s + '*')) { $hit = $true; break } }
            if (-not $hit) { return $false }
        }
    }

    if ($Entry.Endpoints.Count -gt 0) {
        $remoteHost = ''
        if ($Finding.Signals -and $Finding.Signals.RemoteHost) { $remoteHost = [string]$Finding.Signals.RemoteHost }
        if ($remoteHost -and -not (Test-RacWildcard -Value $remoteHost -Pattern $Entry.Endpoints)) { return $false }
    }
    return $true
}

# ---------------------------------------------------------------------------
# Scoring + labels
# ---------------------------------------------------------------------------

function Invoke-RacClassification {
    param(
        [object[]]$Findings,
        $AllowList,
        $Signatures,
        [string]$ComputerName,
        [datetime]$Now
    )

    $weights = $Signatures._IndicatorWeights
    $descriptions = $Signatures._IndicatorDescriptions
    $threshold = [int]$Signatures.scoring.suspiciousThreshold
    $entries = @()
    if ($AllowList) { $entries = @($AllowList.Entries) }

    foreach ($f in $Findings) {
        if (-not $f) { continue }
        $reasons = New-Object System.Collections.Generic.List[string]

        $score = 0
        foreach ($ind in $f.Indicators) {
            if ($weights.ContainsKey($ind)) { $score += [int]$weights[$ind] }
            else { Write-RacLog -Level WARN -Message "Indicator '$ind' has no weight in signatures.json; counted as 0." }
        }

        $matched = $null
        foreach ($e in $entries) {
            if (-not (Test-RacAllowListMatch -Entry $e -Finding $f -ComputerName $ComputerName)) { continue }
            if ($null -ne $e.ExpiresDate -and $e.ExpiresDate -lt $Now.Date) {
                $reasons.Add(("Allow-list entry '{0}' would match, but it expired on {1}." -f $e.Name, $e.Expires))
                continue
            }
            $matched = $e
            break
        }

        $accepted = @()
        if ($matched) {
            $accepted = @($f.Indicators | Where-Object { $matched.AllowedIndicators -contains $_ })
            $approval = "Matches allow-list entry '{0}'" -f $matched.Name
            $details = @()
            if ($matched.ApprovedBy) { $details += 'approved by ' + $matched.ApprovedBy }
            if ($matched.ApprovedOn) { $details += 'on ' + $matched.ApprovedOn }
            if ($matched.Expires) { $details += 'expires ' + $matched.Expires }
            if ($matched.Ticket) { $details += 'ticket ' + $matched.Ticket }
            if ($details.Count -gt 0) { $approval += ' (' + ($details -join ', ') + ')' }
            $reasons.Add($approval + '.')
            $f.AllowListEntry = $matched.Name
        }
        else {
            $reasons.Add('Not on the allow-list.')
        }

        $residual = $score
        foreach ($ind in $f.Indicators) {
            $w = 0
            if ($weights.ContainsKey($ind)) { $w = [int]$weights[$ind] }
            if ($accepted -contains $ind) {
                $residual -= $w
                $reasons.Add(('Accepted by the approval: {0} ({1}).' -f $ind, $descriptions[$ind]))
            }
            else {
                $reasons.Add(('+{0} {1}: {2}' -f $w, $ind, $descriptions[$ind]))
            }
        }

        if ($matched) {
            if ($residual -ge $threshold) {
                $f.Classification = 'Suspicious'
                $reasons.Add(('Approved agent, but remaining risk score {0} is at or above the threshold of {1}.' -f $residual, $threshold))
            }
            else {
                $f.Classification = 'Trusted'
                $reasons.Add(('Remaining risk score {0} is below the threshold of {1}.' -f $residual, $threshold))
            }
        }
        else {
            if ($residual -ge $threshold) {
                $f.Classification = 'Suspicious'
                $reasons.Add(('Risk score {0} is at or above the threshold of {1}.' -f $residual, $threshold))
            }
            else {
                $f.Classification = 'Unknown'
                $reasons.Add(('Risk score {0} is below the threshold of {1}; flagged because it is not approved.' -f $residual, $threshold))
            }
        }

        $f.Score = $residual
        $f.Reasons = $reasons.ToArray()
        $f.Recommendation = Get-RacRecommendation -Finding $f -Entry $matched
    }
}

# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

function Get-RacRecommendation {
    <# Plain-language next step for the admin, by classification and breadcrumb. #>
    param($Finding, $Entry)

    $who = 'the owner'
    if ($Finding.User -and -not (Test-RacSystemAccount -User $Finding.User) -and $Finding.User -ne 'LocalSystem') { $who = $Finding.User }
    elseif ($Finding.User) { $who = 'the administrator who set this up (it runs as ' + $Finding.User + ')' }

    switch ($Finding.Classification) {
        'Trusted' {
            $base = "No action needed. Approved under '$($Finding.AllowListEntry)'."
            if ($Entry -and $Entry.Expires) { $base += " Re-validate before the approval expires on $($Entry.Expires)." }
        }
        'Suspicious' {
            $base = "Investigate now. Confirm with $who whether this is sanctioned. Preserve evidence first (keep this report; capture the process or files before anything is removed), then contain it through your incident process. Rotate any AI keys or tokens found on this machine."
        }
        default {
            $base = "Assign an owner and decide. Ask $who what this agent is for. If approved, add an allow-list entry (ConvertTo-RacAllowListEntry drafts one) with an approver and expiry. If not approved, schedule removal through change control."
        }
    }

    $tips = @{
        'SecretFile'             = 'Move the key into a secret store or Windows Credential Manager. If the file is readable by other users or has been synced or committed anywhere, rotate the key at the provider.'
        'EnvVarSecret'           = 'Machine-wide AI keys are inherited by every user and service. Scope the key to the one account or service that needs it, and rotate it if it was shared.'
        'TokenFile'              = 'Sign-in tokens act as the user. If the agent is not approved, sign it out and revoke the session at the provider.'
        'CredentialStore'        = 'If the application is not approved, remove the stored credential and revoke the session at the provider.'
        'AgentListener'          = 'Bind the service to 127.0.0.1 or block the port at the host firewall. An exposed agent or model port lets anyone on the network drive it.'
        'HeadlessBrowser'        = 'A browser with remote debugging can be fully controlled by any local process, including the user''s signed-in sessions. Identify the automation that owns it.'
        'WmiSubscription'        = 'WMI subscriptions are a stealth persistence technique. Capture the consumer and filter details, then remove them through change control (v1 never removes anything).'
        'ScheduledTask'          = 'Confirm who created the task. Disable it through change control if the agent is not approved.'
        'Service'                = 'Agents running as services act without a person present. Confirm ownership and the account it runs as.'
        'McpServerConfig'        = 'Review what this MCP server can reach, remove servers that are not needed, and pin package versions instead of npx -y / uvx latest.'
        'McpServerProcess'       = 'Check which agent started this MCP server and whether that server is on the approved list.'
        'CrossAppReach'          = 'One agent identity can act across several apps. Narrow its tokens and scopes, split duties between agents, and require human approval for send, delete and execute actions.'
        'OffHoursActivity'       = 'Confirm whether this was scheduled automation or an unattended agent. Check the Persistence findings for the same agent.'
        'SelfModification'       = 'Compare the changed skill and memory files with a known-good copy. An agent that rewrites its own instructions can carry a prompt injection forward.'
        'PackageInstallActivity' = 'Review what was installed (watch for typosquats) and remove the agent''s ability to install software if it is not required.'
        'LlmConnection'          = 'Confirm the process is meant to call this AI provider and that the data it sends is allowed to leave.'
        'DnsCacheLlm'            = 'Attribute the lookup: check the network and Sysmon findings, or rerun with -NetworkSamples to catch the connection. Approve the provider in the allow-list if it is sanctioned.'
        'ProxyLogLlm'            = 'Use the proxy''s client IP and user fields to find the machine and person behind this traffic.'
        'BrowserExtension'       = 'Extensions with debugger or native messaging permission can drive the browser with the user''s sessions. Manage them with browser policy (ExtensionInstallAllowlist).'
        'NativeMessagingHost'    = 'This bridge lets a browser extension run a local program. Confirm both the extension and the program are approved.'
        'LlmScriptProcess'       = 'Open the script (see Script) and find its owner. A script that calls an AI API on its own is an unmanaged agent; check the Persistence findings for what starts it.'
        'PowerShellScriptBlock'  = 'Find the script (see Script path) and its owner. Scripts calling LLM APIs directly are unmanaged agents.'
        'SysmonLlmTraffic'       = 'Identify the program in Process image and confirm it is allowed to call this AI provider.'
    }
    $tip = $tips[$Finding.Breadcrumb]
    if ($tip -and $Finding.Classification -ne 'Trusted') { return ($base + ' ' + $tip) }
    return $base
}
