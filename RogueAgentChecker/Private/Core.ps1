<#
    Core.ps1 - shared plumbing for Rogue Agent Checker.

    What lives here:
      * Scan state ............ log path, coverage list, finding counter
      * Write-RacLog .......... every scan action is logged (and redacted first)
      * Add-RacCoverage ....... what was checked / skipped and why, for the report
      * Protect-RacText ....... secret redaction, applied at every output boundary
      * New-RacFinding ........ the ONE place findings are created
      * Small helpers ......... text normalization, matching, path templates,
                                JSON-with-comments handling, off-hours test

    Nothing in this file queries the operating system. The only file it writes is
    the scan log, which lives in the report output folder.
#>

# ---------------------------------------------------------------------------
# Redaction rules
# ---------------------------------------------------------------------------

# Key FORMAT patterns. These ship built in so redaction works even before the
# signature file loads; Set-RacSecretPattern adds the catalog's patterns on top.
$script:RacSecretPatterns = New-Object System.Collections.Generic.List[object]

function Set-RacSecretPattern {
    <#
        Registers secret-format patterns used both for detection (does this file
        contain a key?) and for redaction (scrub the key from any text we output).
    #>
    param([object[]]$Pattern)

    $script:RacSecretPatterns = New-Object System.Collections.Generic.List[object]
    foreach ($p in $Pattern) {
        if (-not $p -or -not $p.regex) { continue }
        $regex = New-Object System.Text.RegularExpressions.Regex($p.regex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $script:RacSecretPatterns.Add([pscustomobject]@{ Id = [string]$p.id; Name = [string]$p.name; Regex = $regex })
    }
}

# Minimal built-in set (the catalog normally replaces this with a larger list).
Set-RacSecretPattern -Pattern @(
    [pscustomobject]@{ id = 'anthropic-key'; name = 'Anthropic API key'; regex = 'sk-ant-[A-Za-z0-9_\-]{20,}' },
    [pscustomobject]@{ id = 'openai-key'; name = 'OpenAI API key'; regex = 'sk-(proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}' },
    [pscustomobject]@{ id = 'openai-style-key'; name = 'OpenAI-style secret key'; regex = '\bsk-[A-Za-z0-9]{32,}' },
    [pscustomobject]@{ id = 'github-token'; name = 'GitHub token'; regex = '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}' }
)

# Generic rules catch secrets whose format we don't know, by context:
#   key=value, --api-key value, Bearer xyz, https://user:password@host
# The (?!\[REDACTED) guard stops these from re-redacting a value that a format
# rule already replaced, so the report keeps the more specific label.
$script:RacGenericRedactions = @(
    @{
        Pattern     = '(\b(?:[a-z0-9_]*api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|[a-z0-9_]*_token|token|[a-z0-9_]*secret|password|passwd|pwd)\b\s*["'']?\s*[:=]\s*["'']?)(?!\[REDACTED)([^\s"'',;&]{4,})'
        Replacement = '$1[REDACTED]'
    },
    @{
        Pattern     = '(--?(?:api[_-]?key|token|secret|password|key)(?:\s+|=)["'']?)(?!\[REDACTED)([^\s"'',;&]{4,})'
        Replacement = '$1[REDACTED]'
    },
    @{
        Pattern     = '(\bbearer\s+)(?!\[REDACTED)([A-Za-z0-9._~+/=\-]{8,})'
        Replacement = '$1[REDACTED]'
    },
    @{
        Pattern     = '(\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:)(?!\[REDACTED)([^@\s/]+)(@)'
        Replacement = '$1[REDACTED]$3'
    }
)

function Protect-RacText {
    <#
        Returns $Text with anything that looks like a secret replaced by a marker
        such as [REDACTED:anthropic-key]. Redaction happens BEFORE truncation, so a
        key can never be half-cut into something the patterns no longer recognize.
    #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [int]$MaxLength = 0
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $out = $Text
    foreach ($p in $script:RacSecretPatterns) {
        $out = $p.Regex.Replace($out, ('[REDACTED:' + $p.Id + ']'))
    }
    foreach ($rule in $script:RacGenericRedactions) {
        $out = [regex]::Replace($out, $rule.Pattern, $rule.Replacement, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    if ($MaxLength -gt 0 -and $out.Length -gt $MaxLength) {
        $out = $out.Substring(0, $MaxLength) + '...[truncated]'
    }
    return $out
}

function Get-RacSecretFormat {
    <#
        Returns the NAMES of key formats found in $Text (for example
        'Anthropic API key'). Never returns the matched value.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $names = @()
    foreach ($p in $script:RacSecretPatterns) {
        if ($p.Regex.IsMatch($Text)) { $names += $p.Name }
    }
    return @($names | Select-Object -Unique)
}

# ---------------------------------------------------------------------------
# Scan state, logging, coverage
# ---------------------------------------------------------------------------

function Initialize-RacScanState {
    param([string]$LogPath)

    $script:RacLogPath = $null
    $script:RacCoverage = New-Object System.Collections.Generic.List[object]
    $script:RacFindingCounter = 0

    if ($LogPath) {
        $folder = Split-Path -Parent $LogPath
        if ($folder -and -not (Test-Path -LiteralPath $folder)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
        }
        Set-Content -LiteralPath $LogPath -Value '# Rogue Agent Checker scan log (read-only scan; secrets are redacted)' -Encoding UTF8
        $script:RacLogPath = $LogPath
    }
}

function Stop-RacScanLog {
    <# Detaches the log file at the end of a scan so later commands never append to an old scan's log. #>
    if ($script:RacLogPath) { Write-RacLog -Level INFO -Message 'Scan log closed.' }
    $script:RacLogPath = $null
}

function Write-RacLog {
    <#
        Appends one timestamped line to the scan log and to the Verbose stream.
        Levels: INFO, ACTION (a step started), SOURCE (an OS source was read),
        SKIP, WARN, ERROR, FINDING, OUTPUT (a report file was written).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'ACTION', 'SOURCE', 'SKIP', 'WARN', 'ERROR', 'FINDING', 'OUTPUT')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'), $Level, (Protect-RacText -Text $Message)
    Write-Verbose $line
    if ($script:RacLogPath) {
        try {
            Add-Content -LiteralPath $script:RacLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            Write-Warning ('Could not write to the scan log: ' + $_.Exception.Message)
        }
    }
}

function Add-RacCoverage {
    <#
        Records what a source covered. The report's Coverage section is built from
        these rows so an auditor can tell "nothing found" from "couldn't look".
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][ValidateSet('Checked', 'Partial', 'Skipped', 'Error', 'Info')][string]$Status,
        [int]$ItemCount = -1,
        [string]$Detail = ''
    )

    if ($null -eq $script:RacCoverage) { $script:RacCoverage = New-Object System.Collections.Generic.List[object] }

    $row = [pscustomobject]@{
        Source    = $Source
        Status    = $Status
        ItemCount = $ItemCount
        Detail    = (Protect-RacText -Text $Detail)
    }
    $script:RacCoverage.Add($row)

    $level = 'SOURCE'
    if ($Status -eq 'Skipped') { $level = 'SKIP' }
    if ($Status -eq 'Error') { $level = 'ERROR' }
    if ($Status -eq 'Info') { $level = 'INFO' }
    $countText = ''
    if ($ItemCount -ge 0) { $countText = " ($ItemCount items)" }
    Write-RacLog -Level $level -Message ('{0}: {1}{2} {3}' -f $Source, $Status, $countText, $Detail)
}

function Get-RacCoverage {
    if ($null -eq $script:RacCoverage) { return @() }
    return $script:RacCoverage.ToArray()
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

$script:RacCategories = @('Processes', 'Network', 'ConfigAndSecrets', 'Persistence', 'TokensAndOAuth', 'LogsAndEvents', 'Behavior')

function New-RacFinding {
    <#
        Creates a finding. Every evidence value is converted to text and passed
        through Protect-RacText here, so analyzers cannot accidentally put a raw
        secret into the report even if they try.

        Classification, Score, Reasons and Recommendation are filled in later by
        the classifier (Classify.ps1).
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Processes', 'Network', 'ConfigAndSecrets', 'Persistence', 'TokensAndOAuth', 'LogsAndEvents', 'Behavior')]
        [string]$Category,
        [Parameter(Mandatory = $true)][string]$Breadcrumb,
        [Parameter(Mandatory = $true)][string]$Title,
        [string]$Agent = 'Unidentified agent',
        [string]$AgentId = '',
        [string]$Location = '',
        [string]$User = '',
        [object]$EventTime = $null,
        [System.Collections.IDictionary]$Evidence = @{},
        [string[]]$Indicators = @(),
        [object[]]$ActivityTimes = @(),
        [string[]]$AppCategories = @(),
        [hashtable]$Signals = @{}
    )

    $script:RacFindingCounter++

    $cleanEvidence = [ordered]@{}
    foreach ($key in $Evidence.Keys) {
        $value = $Evidence[$key]
        if ($null -eq $value) { continue }
        if ($value -is [datetime]) {
            $text = $value.ToString('yyyy-MM-dd HH:mm:ss')
        }
        elseif ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
            $text = (@($value) | ForEach-Object { [string]$_ }) -join '; '
        }
        else {
            $text = [string]$value
        }
        if ($text -eq '') { continue }
        $cleanEvidence[$key] = Protect-RacText -Text $text -MaxLength 600
    }

    $times = @()
    foreach ($t in $ActivityTimes) { if ($t -is [datetime]) { $times += $t } }

    $eventTimeValue = $null
    if ($EventTime -is [datetime]) { $eventTimeValue = $EventTime }

    [pscustomobject]@{
        FindingId      = 'RAC-{0:D4}' -f $script:RacFindingCounter
        Classification = 'Unknown'
        Score          = 0
        Category       = $Category
        Breadcrumb     = $Breadcrumb
        Agent          = $Agent
        AgentId        = $AgentId
        Title          = (Protect-RacText -Text $Title -MaxLength 200)
        User           = $User
        Location       = (Protect-RacText -Text $Location -MaxLength 400)
        EventTime      = $eventTimeValue
        Evidence       = $cleanEvidence
        Indicators     = @($Indicators | Where-Object { $_ } | Select-Object -Unique)
        Reasons        = @()
        AllowListEntry = ''
        Recommendation = ''
        # Internal fields used by the behavior analyzer; not written to the CSV.
        ActivityTimes  = $times
        AppCategories  = @($AppCategories | Where-Object { $_ } | Select-Object -Unique)
        Signals        = $Signals
    }
}

# ---------------------------------------------------------------------------
# Text and matching helpers
# ---------------------------------------------------------------------------

function ConvertTo-RacNormalizedText {
    <# Lowercase, backslashes to forward slashes. All signature regexes expect this. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.ToLowerInvariant().Replace('\', '/')
}

function Get-RacFirstRegexMatch {
    <# Returns the first pattern in $Pattern that matches $Text, or $null. #>
    param([AllowEmptyString()][string]$Text, [object[]]$Pattern)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    foreach ($p in $Pattern) {
        if ($p -and $Text -match $p) { return [string]$p }
    }
    return $null
}

function Test-RacWildcard {
    <# True if $Value matches any wildcard pattern (case-insensitive -like). #>
    param([AllowEmptyString()][AllowNull()][string]$Value, [object[]]$Pattern)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    foreach ($p in $Pattern) {
        if ($p -and $Value -like [string]$p) { return $true }
    }
    return $false
}

function Get-RacUserLeaf {
    <# 'CORP\alice' -> 'alice' #>
    param([AllowEmptyString()][AllowNull()][string]$User)
    if ([string]::IsNullOrEmpty($User)) { return '' }
    $parts = $User -split '[\\/]'
    return $parts[-1]
}

function Get-RacLeafName {
    <#
        'C:\Program Files\nodejs\node.exe' -> 'node.exe'. Splits on BOTH slash
        styles, because paths from event logs and the registry are Windows paths
        even when the code runs elsewhere (and [IO.Path]::GetFileName would not split them).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return '' }
    $parts = @($Path.Trim().Trim('"').TrimEnd('\', '/') -split '[\\/]')
    return $parts[-1]
}

function Get-RacUserFromPath {
    <# 'C:\Users\bob\.openclaw\x' -> 'bob' (local text parsing only, no lookups) #>
    param([AllowEmptyString()][AllowNull()][string]$Path)
    $n = ConvertTo-RacNormalizedText $Path
    if ($n -match '/users/([^/]+)/') { return $Matches[1] }
    if ($n -match '^/home/([^/]+)/') { return $Matches[1] }
    return ''
}

function Test-RacSystemAccount {
    <# True for SYSTEM / LocalService / NetworkService in their usual spellings. #>
    param([AllowEmptyString()][AllowNull()][string]$User)
    if ([string]::IsNullOrEmpty($User)) { return $false }
    $u = $User.ToLowerInvariant().Trim()
    $known = @(
        'system', 'nt authority\system', 'localsystem', '.\localsystem', 's-1-5-18',
        'local service', 'nt authority\local service', 'nt authority\localservice', 's-1-5-19',
        'network service', 'nt authority\network service', 'nt authority\networkservice', 's-1-5-20'
    )
    return ($known -contains $u)
}

function Format-RacTime {
    param([object]$Time)
    if ($Time -is [datetime]) { return $Time.ToString('yyyy-MM-dd HH:mm') }
    return ''
}

function Test-RacOffHours {
    <# True if $Time falls outside the configured business days/hours (local time). #>
    param(
        [datetime]$Time,
        [int]$StartHour,
        [int]$EndHour,
        [string[]]$BusinessDays
    )
    if ($BusinessDays -notcontains $Time.DayOfWeek.ToString()) { return $true }
    return ($Time.Hour -lt $StartHour -or $Time.Hour -ge $EndHour)
}

function Expand-RacPathTemplate {
    <#
        Turns a signature path template into a real path for ONE user profile.
          ~/.claude                  -> <profile>\.claude
          %APPDATA%/Claude           -> <profile>\AppData\Roaming\Claude
          %LOCALAPPDATA%/Ollama      -> <profile>\AppData\Local\Ollama
          %TEMP%/openclaw            -> <profile>\AppData\Local\Temp\openclaw
          %PROGRAMFILES%/nodejs      -> C:\Program Files\nodejs   (machine-wide)
        Profile tokens are expanded from the profile folder, NOT from the current
        user's environment, so one scan can cover every profile it can read.
        Returns $null if the template needs something we don't have.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Template,
        [AllowEmptyString()][AllowNull()][string]$ProfileRoot
    )

    $t = $Template.Trim()
    $base = $null
    $rest = $t

    $profileTokens = [ordered]@{
        '%APPDATA%'      = @('AppData', 'Roaming')
        '%LOCALAPPDATA%' = @('AppData', 'Local')
        '%TEMP%'         = @('AppData', 'Local', 'Temp')
    }
    $machineTokens = [ordered]@{
        '%PROGRAMDATA%'  = $env:ProgramData
        '%PROGRAMFILES%' = $env:ProgramFiles
    }

    if ($t.StartsWith('~')) {
        if ([string]::IsNullOrEmpty($ProfileRoot)) { return $null }
        $base = $ProfileRoot
        $rest = $t.Substring(1)
    }
    else {
        foreach ($token in $profileTokens.Keys) {
            if ($t.StartsWith($token, [System.StringComparison]::OrdinalIgnoreCase)) {
                if ([string]::IsNullOrEmpty($ProfileRoot)) { return $null }
                $base = $ProfileRoot
                foreach ($segment in $profileTokens[$token]) { $base = [System.IO.Path]::Combine($base, $segment) }
                $rest = $t.Substring($token.Length)
                break
            }
        }
        if ($null -eq $base) {
            foreach ($token in $machineTokens.Keys) {
                if ($t.StartsWith($token, [System.StringComparison]::OrdinalIgnoreCase)) {
                    if ([string]::IsNullOrEmpty($machineTokens[$token])) { return $null }
                    $base = $machineTokens[$token]
                    $rest = $t.Substring($token.Length)
                    break
                }
            }
        }
    }

    if ($null -eq $base) {
        # Already an absolute path (or a bare relative one): just normalize separators.
        $segments = @($t -split '[\\/]' | Where-Object { $_ -ne '' })
        if ($t -match '^[\\/]') { $base = [string][System.IO.Path]::DirectorySeparatorChar } else { $base = '' }
        $path = $base
        foreach ($s in $segments) {
            if ($path -eq '') { $path = $s } else { $path = [System.IO.Path]::Combine($path, $s) }
        }
        if ($path -match '^[A-Za-z]:$') { $path += [System.IO.Path]::DirectorySeparatorChar }
        return $path
    }

    $path = $base
    foreach ($s in @($rest -split '[\\/]' | Where-Object { $_ -ne '' })) {
        $path = [System.IO.Path]::Combine($path, $s)
    }
    return $path
}

function ConvertTo-RacPathFragmentRegex {
    <#
        Turns a template such as '~/.openclaw' or '%APPDATA%/Claude' into a regex
        that finds references to that location inside normalized text (for example
        a scheduled task's command line). Profile tokens become their relative
        AppData path so any user's copy matches.
    #>
    param([string]$Template)

    $t = ConvertTo-RacNormalizedText $Template
    $t = $t -replace '^~', ''
    $t = $t -replace '^%appdata%', '/appdata/roaming'
    $t = $t -replace '^%localappdata%', '/appdata/local'
    $t = $t -replace '^%temp%', '/appdata/local/temp'
    $t = $t -replace '^%programdata%', '/programdata'
    $t = $t -replace '^%programfiles%', '/program files'
    if ($t.Length -lt 4) { return $null }
    $escaped = [regex]::Escape($t) -replace '\\\*', '[^/]*'
    return $escaped + '(?=/|$|"|''|\s)'
}

# ---------------------------------------------------------------------------
# JSON helpers (config files are often JSON-with-comments, i.e. JSONC)
# ---------------------------------------------------------------------------

function Remove-RacJsonComment {
    <#
        Strips // and /* */ comments that sit outside of strings, and trailing
        commas, so ConvertFrom-Json (which is strict on Windows PowerShell 5.1)
        can read VS Code style JSONC files.
    #>
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $sb = New-Object System.Text.StringBuilder
    $inString = $false
    $escape = $false
    $i = 0
    $n = $Text.Length
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($inString) {
            [void]$sb.Append($c)
            if ($escape) { $escape = $false }
            elseif ($c -eq [char]'\') { $escape = $true }
            elseif ($c -eq [char]'"') { $inString = $false }
            $i++
            continue
        }
        if ($c -eq [char]'"') {
            $inString = $true
            [void]$sb.Append($c)
            $i++
            continue
        }
        if ($c -eq [char]'/' -and ($i + 1) -lt $n) {
            $next = $Text[$i + 1]
            if ($next -eq [char]'/') {
                while ($i -lt $n -and $Text[$i] -ne [char]"`n") { $i++ }
                continue
            }
            if ($next -eq [char]'*') {
                $i += 2
                while (($i + 1) -lt $n -and -not ($Text[$i] -eq [char]'*' -and $Text[$i + 1] -eq [char]'/')) { $i++ }
                $i += 2
                continue
            }
        }
        [void]$sb.Append($c)
        $i++
    }
    return [regex]::Replace($sb.ToString(), ',(\s*[}\]])', '$1')
}

function Get-RacJsonObjectAfterKey {
    <#
        Fallback for JSON files too large or too odd for ConvertFrom-Json: finds
        every "<Key>": { ... } object in the raw text by brace matching (string
        aware) and returns those slices so they can be parsed on their own.
    #>
    param([string]$Text, [string]$Key)

    $slices = @()
    if ([string]::IsNullOrEmpty($Text)) { return $slices }
    $pattern = '"' + [regex]::Escape($Key) + '"\s*:\s*\{'
    foreach ($m in [regex]::Matches($Text, $pattern)) {
        $start = $m.Index + $m.Length - 1
        $depth = 0
        $inString = $false
        $escape = $false
        for ($i = $start; $i -lt $Text.Length; $i++) {
            $c = $Text[$i]
            if ($inString) {
                if ($escape) { $escape = $false }
                elseif ($c -eq [char]'\') { $escape = $true }
                elseif ($c -eq [char]'"') { $inString = $false }
                continue
            }
            if ($c -eq [char]'"') { $inString = $true; continue }
            if ($c -eq [char]'{') { $depth++ }
            elseif ($c -eq [char]'}') {
                $depth--
                if ($depth -eq 0) {
                    $slices += $Text.Substring($start, $i - $start + 1)
                    break
                }
            }
        }
    }
    return $slices
}

function ConvertFrom-RacJsonText {
    <# ConvertFrom-Json that tolerates comments and returns $null instead of throwing. #>
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $null }
    try { return ($Text | ConvertFrom-Json -ErrorAction Stop) }
    catch { Write-Verbose ('Strict JSON parse failed, retrying without comments: ' + $_.Exception.Message) }
    try { return ((Remove-RacJsonComment -Text $Text) | ConvertFrom-Json -ErrorAction Stop) }
    catch { Write-Verbose ('JSON parse failed after removing comments: ' + $_.Exception.Message) }
    return $null
}

function Test-RacJsonObject {
    <# True if the value is a JSON object (PSCustomObject) as produced by ConvertFrom-Json. #>
    param([object]$Value)
    return ($Value -is [System.Management.Automation.PSCustomObject])
}

function Get-RacJsonProperty {
    <# Safe property read on a ConvertFrom-Json object; returns $null if missing. #>
    param([object]$Object, [string]$Name)
    if (-not (Test-RacJsonObject $Object)) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}
