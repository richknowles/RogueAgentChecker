<#
    Analyze-ConfigAndSecrets.ps1 - Category 3: agent config / memory / skills
    folders, MCP server inventory, API keys in .env and config files, AI keys in
    environment variables, installed agent packages and IDE extensions.

    SECRET HANDLING: files are parsed in memory for key NAMES (OPENAI_API_KEY)
    and key FORMATS ("looks like an Anthropic key"). Values are discarded as soon
    as the line has been tested and are never stored, logged, or reported.
#>

# ---------------------------------------------------------------------------
# Secret scanning (names and formats only)
# ---------------------------------------------------------------------------

function Test-RacRealSecretValue {
    <# Filters out empty values and obvious placeholders such as 'your-key-here'. #>
    param([AllowEmptyString()][string]$Value)
    if ($Value.Length -lt 8) { return $false }
    if ($Value -match '^(your|<|\$\{|\$\(|xxx|changeme|replace|example|placeholder|todo|none|null|\*+$)') { return $false }
    if ($Value -match '^\$[A-Za-z_]') { return $false }
    return $true
}

function Get-RacSecretScan {
    <#
        Scans text line by line. Returns key NAMES, key FORMAT names and line
        numbers. The text itself and any value are never returned.
    #>
    param($Signatures, [AllowEmptyString()][string]$Text, [switch]$EnvStyle)

    $names = @()
    $formats = @()
    $lineNumbers = @()
    if ([string]::IsNullOrEmpty($Text)) {
        return [pscustomobject]@{ KeyNames = @(); Formats = @(); LineNumbers = @(); HasSecret = $false }
    }

    $lineNo = 0
    foreach ($line in ($Text -split "`r?`n")) {
        $lineNo++
        $hit = $false
        if ($EnvStyle -and $line -match '^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $name = $Matches[1]
            $value = $Matches[2].Trim().Trim('"').Trim("'")
            if ($name -match $Signatures.secretEnvNamePattern -and (Test-RacRealSecretValue -Value $value)) {
                $names += $name
                $hit = $true
            }
            $value = $null
        }
        $lineFormats = @(Get-RacSecretFormat -Text $line)
        if ($lineFormats.Count -gt 0) { $formats += $lineFormats; $hit = $true }
        if ($hit) { $lineNumbers += $lineNo }
    }
    return [pscustomobject]@{
        KeyNames    = @($names | Select-Object -Unique)
        Formats     = @($formats | Select-Object -Unique)
        LineNumbers = $lineNumbers
        HasSecret   = (($names.Count + $formats.Count) -gt 0)
    }
}

function New-RacSecretFileFinding {
    param($Context, [string]$Path, $Scan, [string]$User, [string]$AgentName, [string]$AgentId)

    $key = 'secret|' + $Path.ToLowerInvariant()
    if ($Context.SeenPaths.ContainsKey($key)) { return }
    $Context.SeenPaths[$key] = $true

    $info = Get-RacItemInfo -Path $Path
    $acl = Get-RacFileAclSummary -Path $Path
    $indicators = @('SecretInPlaintext')
    if ($acl -and $acl.BroadRead) { $indicators += 'SecretWorldReadable' }

    $evidence = [ordered]@{
        'File'          = $Path
        'Key names'     = ($Scan.KeyNames -join ', ')
        'Key formats'   = ($Scan.Formats -join ', ')
        'Line numbers'  = ($Scan.LineNumbers -join ', ')
        'Last modified' = $(if ($info) { $info.LastWriteTime } else { $null })
        'Values'        = 'not recorded (RAC never stores or prints key values)'
    }
    if ($acl -and $acl.BroadRead) { $evidence['Readable by'] = ($acl.Identities -join ', ') }

    $what = @($Scan.KeyNames) + @($Scan.Formats) | Select-Object -First 3
    if (-not $AgentName) { $AgentName = 'Unattributed (secret file)' }
    $lastWrite = $null
    if ($info) { $lastWrite = $info.LastWriteTime }

    New-RacFinding -Category 'ConfigAndSecrets' -Breadcrumb 'SecretFile' `
        -Title ('Plaintext key or token in {0} ({1})' -f (Split-Path -Leaf $Path), ($what -join ', ')) `
        -Agent $AgentName -AgentId $AgentId -Location $Path -User $User -EventTime $lastWrite `
        -Evidence $evidence -Indicators $indicators -ActivityTimes @($lastWrite)
}

# ---------------------------------------------------------------------------
# MCP configuration parsing (JSON / JSONC, TOML, YAML)
# ---------------------------------------------------------------------------

function Find-RacMcpServerNode {
    <#
        Walks a parsed JSON document looking for MCP server maps:
          "mcpServers": { name: {...} }      (Claude, Cursor, Windsurf, Gemini, Cline, ...)
          "servers": { name: {...} }          (VS Code mcp.json, top level only)
          "mcp": { "servers": {...} }         (VS Code settings.json)
          "mcp": { name: {command|url} }      (OpenCode)
        Arrays are not walked (large histories live in arrays in some files).
    #>
    param($Node, [int]$Depth = 0, [string]$JsonPath = '')

    if ($Depth -gt 6 -or -not (Test-RacJsonObject $Node)) { return }

    foreach ($prop in $Node.PSObject.Properties) {
        $name = $prop.Name
        $value = $prop.Value
        if (-not (Test-RacJsonObject $value)) { continue }

        $isServerMap = $false
        if ($name -eq 'mcpServers') { $isServerMap = $true }
        elseif ($name -eq 'servers' -and ($Depth -eq 0 -or $JsonPath -match '\.mcp$')) { $isServerMap = $true }
        elseif ($name -eq 'mcp' -and -not $value.PSObject.Properties['servers']) {
            foreach ($child in $value.PSObject.Properties) {
                if ((Test-RacJsonObject $child.Value) -and ($child.Value.PSObject.Properties['command'] -or $child.Value.PSObject.Properties['url'])) { $isServerMap = $true; break }
            }
        }

        if ($isServerMap) {
            foreach ($server in $value.PSObject.Properties) {
                if (Test-RacJsonObject $server.Value) {
                    [pscustomobject]@{ Name = $server.Name; Definition = $server.Value; JsonPath = ($JsonPath + '.' + $name) }
                }
            }
        }
        else {
            Find-RacMcpServerNode -Node $value -Depth ($Depth + 1) -JsonPath ($JsonPath + '.' + $name)
        }
    }
}

function New-RacMcpServerRecord {
    param([string]$Name)
    [pscustomobject]@{
        Name = $Name; Command = ''; Args = @(); Url = ''; EnvNames = @(); SecretFormats = @(); Disabled = $false; Scope = ''
    }
}

function ConvertTo-RacMcpServerRecord {
    <# Normalizes one JSON server definition. Env/header VALUES are tested for key formats, then dropped. #>
    param([string]$Name, $Definition, [string]$JsonPath)

    $rec = New-RacMcpServerRecord -Name $Name
    $command = Get-RacJsonProperty -Object $Definition -Name 'command'
    if ($null -ne $command) {
        if ($command -is [array]) {
            $rec.Command = [string]$command[0]
            $rec.Args = @($command | Select-Object -Skip 1 | ForEach-Object { [string]$_ })
        }
        else {
            $rec.Command = [string]$command
        }
    }
    $argsValue = Get-RacJsonProperty -Object $Definition -Name 'args'
    if ($null -ne $argsValue) { $rec.Args += @($argsValue | ForEach-Object { [string]$_ }) }

    foreach ($urlKey in @('url', 'serverUrl', 'httpUrl', 'uri', 'endpoint')) {
        $u = Get-RacJsonProperty -Object $Definition -Name $urlKey
        if ($u) { $rec.Url = [string]$u; break }
    }
    foreach ($envKey in @('env', 'environment', 'headers')) {
        $envObj = Get-RacJsonProperty -Object $Definition -Name $envKey
        if (Test-RacJsonObject $envObj) {
            foreach ($p in $envObj.PSObject.Properties) {
                $rec.EnvNames += $p.Name
                foreach ($fmt in @(Get-RacSecretFormat -Text ([string]$p.Value))) { $rec.SecretFormats += ('{0} ({1})' -f $p.Name, $fmt) }
            }
        }
    }
    if ((Get-RacJsonProperty -Object $Definition -Name 'disabled') -eq $true -or (Get-RacJsonProperty -Object $Definition -Name 'enabled') -eq $false) {
        $rec.Disabled = $true
    }
    if ($JsonPath -match '^\.projects\.(.+)\.mcpServers$') { $rec.Scope = 'Project ' + $Matches[1] }
    return $rec
}

function Get-RacMcpServerFromJson {
    param([string]$Text)

    $root = ConvertFrom-RacJsonText -Text $Text
    $nodes = @()
    $parsed = $false
    if ($null -ne $root) {
        $parsed = $true
        $nodes = @(Find-RacMcpServerNode -Node $root)
    }
    else {
        # Too large or unusual for ConvertFrom-Json: parse only the server maps.
        foreach ($key in @('mcpServers', 'servers')) {
            foreach ($slice in @(Get-RacJsonObjectAfterKey -Text $Text -Key $key)) {
                $obj = ConvertFrom-RacJsonText -Text $slice
                if (Test-RacJsonObject $obj) {
                    $parsed = $true
                    foreach ($p in $obj.PSObject.Properties) {
                        if (Test-RacJsonObject $p.Value) { $nodes += [pscustomobject]@{ Name = $p.Name; Definition = $p.Value; JsonPath = '.' + $key } }
                    }
                }
            }
        }
    }
    $servers = foreach ($n in $nodes) { ConvertTo-RacMcpServerRecord -Name $n.Name -Definition $n.Definition -JsonPath $n.JsonPath }
    return [pscustomobject]@{ Parsed = $parsed; Servers = @($servers) }
}

function Get-RacQuotedList {
    <# '"a", "b"' -> @('a','b') #>
    param([string]$Text)
    return @([regex]::Matches($Text, '"((?:[^"\\]|\\.)*)"|''([^'']*)''') | ForEach-Object {
            if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value }
        })
}

function Get-RacMcpServerFromToml {
    <# Codex style: [mcp_servers.NAME] tables with command/args/url and an env sub-table. #>
    param([string]$Text)

    $servers = @()
    $current = $null
    $inEnv = $false
    $argsBuffer = $null

    foreach ($raw in ($Text -split "`r?`n")) {
        $line = $raw.Trim()
        if ($null -ne $argsBuffer) {
            $argsBuffer += ' ' + $line
            if ($line -match '\]') { $current.Args += Get-RacQuotedList -Text $argsBuffer; $argsBuffer = $null }
            continue
        }
        if ($line -eq '' -or $line.StartsWith('#')) { continue }

        if ($line -match '^\[mcp_servers\.(?:"([^"]+)"|([A-Za-z0-9_-]+))(\.env)?\]$') {
            $name = $Matches[1]
            if (-not $name) { $name = $Matches[2] }
            if ($Matches[3]) {
                $inEnv = $true
                if (-not $current -or $current.Name -ne $name) { if ($current) { $servers += $current }; $current = New-RacMcpServerRecord -Name $name }
                continue
            }
            if ($current) { $servers += $current }
            $current = New-RacMcpServerRecord -Name $name
            $inEnv = $false
            continue
        }
        if ($line.StartsWith('[')) {
            if ($current) { $servers += $current; $current = $null }
            $inEnv = $false
            continue
        }
        if (-not $current) { continue }

        if ($inEnv) {
            if ($line -match '^([A-Za-z0-9_]+)\s*=\s*(.+)$') {
                $current.EnvNames += $Matches[1]
                foreach ($fmt in @(Get-RacSecretFormat -Text $Matches[2])) { $current.SecretFormats += ('{0} ({1})' -f $Matches[1], $fmt) }
            }
            continue
        }
        if ($line -match '^command\s*=\s*["''](.*)["'']\s*$') { $current.Command = $Matches[1] }
        elseif ($line -match '^args\s*=\s*\[(.*)\]\s*$') { $current.Args += Get-RacQuotedList -Text $Matches[1] }
        elseif ($line -match '^args\s*=\s*\[') { $argsBuffer = $line }
        elseif ($line -match '^url\s*=\s*["''](.*)["'']') { $current.Url = $Matches[1] }
        elseif ($line -match '^enabled\s*=\s*false') { $current.Disabled = $true }
        elseif ($line -match '^env\s*=\s*\{(.*)\}') {
            foreach ($m in [regex]::Matches($Matches[1], '([A-Za-z0-9_]+)\s*=\s*"([^"]*)"')) {
                $current.EnvNames += $m.Groups[1].Value
                foreach ($fmt in @(Get-RacSecretFormat -Text $m.Groups[2].Value)) { $current.SecretFormats += ('{0} ({1})' -f $m.Groups[1].Value, $fmt) }
            }
        }
    }
    if ($current) { $servers += $current }
    return [pscustomobject]@{ Parsed = $true; Servers = $servers }
}

function Get-RacMcpServerFromYaml {
    <#
        Light YAML reader for the two common shapes:
          mcpServers:            extensions:
            - name: sqlite         github:
              command: npx           cmd: npx
              args: [...]            args: [...]
        Good enough to inventory names, commands and env var names.
    #>
    param([string]$Text)

    $servers = @()
    $current = $null
    $inBlock = $false
    $itemIndent = -1
    $collectingArgs = $false

    foreach ($raw in ($Text -split "`r?`n")) {
        if ($raw.Trim() -eq '' -or $raw.TrimStart().StartsWith('#')) { continue }
        $indent = $raw.Length - $raw.TrimStart().Length
        $line = $raw.Trim()

        if ($indent -eq 0) {
            if ($current) { $servers += $current; $current = $null }
            $inBlock = ($line -match '^(mcpServers|mcp_servers|extensions):\s*$')
            $itemIndent = -1
            $collectingArgs = $false
            continue
        }
        if (-not $inBlock) { continue }

        if ($line -match '^-\s+name:\s*(.+)$') {
            if ($current) { $servers += $current }
            $current = New-RacMcpServerRecord -Name ($Matches[1].Trim().Trim('"', "'"))
            $itemIndent = $indent
            $collectingArgs = $false
            continue
        }
        if ($line -match '^([A-Za-z0-9_.-]+):\s*$' -and ($itemIndent -lt 0 -or $indent -le $itemIndent)) {
            if ($current) { $servers += $current }
            $current = New-RacMcpServerRecord -Name $Matches[1]
            $itemIndent = $indent
            $collectingArgs = $false
            continue
        }
        if (-not $current) { continue }

        if ($collectingArgs -and $line -match '^-\s+(.+)$') { $current.Args += $Matches[1].Trim().Trim('"', "'"); continue }
        $collectingArgs = $false

        if ($line -match '^(command|cmd):\s*(.+)$') { $current.Command = $Matches[2].Trim().Trim('"', "'") }
        elseif ($line -match '^args:\s*\[(.*)\]\s*$') { $current.Args += Get-RacQuotedList -Text $Matches[1] }
        elseif ($line -match '^args:\s*$') { $collectingArgs = $true }
        elseif ($line -match '^(url|uri|endpoint):\s*(.+)$') { $current.Url = $Matches[2].Trim().Trim('"', "'") }
        elseif ($line -match '^enabled:\s*false') { $current.Disabled = $true }
        elseif ($line -match '^([A-Z][A-Z0-9_]+):\s*(.+)$') {
            $current.EnvNames += $Matches[1]
            foreach ($fmt in @(Get-RacSecretFormat -Text $Matches[2])) { $current.SecretFormats += ('{0} ({1})' -f $Matches[1], $fmt) }
        }
    }
    if ($current) { $servers += $current }
    return [pscustomobject]@{ Parsed = $true; Servers = $servers }
}

function Find-RacMcpServerConfig {
    <# One finding per MCP server defined in a config file. #>
    param($Context, [string]$Path, [string]$Format, $Agent, [string]$User, [string]$Scope = '')

    $key = 'mcp|' + $Path.ToLowerInvariant()
    if ($Context.SeenPaths.ContainsKey($key)) { return }
    $Context.SeenPaths[$key] = $true

    $sig = $Context.Signatures
    $text = Read-RacTextFile -Path $Path -MaxBytes 25MB
    if (-not $text) { return }

    switch ($Format) {
        'toml' { $result = Get-RacMcpServerFromToml -Text $text }
        'yaml' { $result = Get-RacMcpServerFromYaml -Text $text }
        default { $result = Get-RacMcpServerFromJson -Text $text }
    }
    $text = $null

    if (-not $result.Parsed) {
        Add-RacCoverage -Source ('MCP config: ' + $Path) -Status 'Partial' -Detail 'File exists but could not be parsed (for example JSON5). Review it manually.'
        return
    }

    $info = Get-RacItemInfo -Path $Path
    $lastWrite = $null
    if ($info) { $lastWrite = $info.LastWriteTime }
    $agentName = 'Unidentified agent'
    $agentId = ''
    if ($Agent) { $agentName = [string]$Agent.name; $agentId = [string]$Agent.id }

    foreach ($s in @($result.Servers)) {
        # Arguments that look like paths are left out of category matching so a
        # folder called C:\git does not make a filesystem server look like GitHub.
        $nonPathArgs = @($s.Args | Where-Object { $_ -and $_ -notmatch '^[A-Za-z]:[\\/]|^[\\/]|^\.{1,2}[\\/]|^~' })
        $urlHost = ''
        if ($s.Url -match '^[a-z][a-z0-9+.-]*://([^/:?#]+)') { $urlHost = $Matches[1].ToLowerInvariant() }

        $categoryText = ($s.Name, $s.Command, ($nonPathArgs -join ' '), $urlHost) -join ' '
        $categories = @(Get-RacMcpAppCategory -Signatures $sig -Text $categoryText)
        $commandText = (@($s.Command) + @($s.Args)) -join ' '

        $indicators = @()
        if ($categories -contains 'shell' -or $categories -contains 'files') { $indicators += 'ShellCapableMcp' }
        if ($urlHost -and $urlHost -notmatch '^(localhost|127\.|::1|\[::1\])') { $indicators += 'RemoteMcpServer' }
        $unpinned = Get-RacUnpinnedPackageSpec -Text $commandText
        if ($unpinned) { $indicators += 'UnpinnedPackage' }
        $inlineFormats = @(Get-RacSecretFormat -Text $commandText)
        if ($s.SecretFormats.Count -gt 0 -or $inlineFormats.Count -gt 0) { $indicators += 'SecretInPlaintext' }

        $transport = 'stdio (local process)'
        if ($s.Url) { $transport = 'remote (HTTP/SSE)' }
        $scopeText = $Scope
        if ($s.Scope) { $scopeText = $s.Scope }
        if (-not $scopeText) { $scopeText = 'User' }

        $plaintext = @($s.SecretFormats) + @($inlineFormats | ForEach-Object { 'in arguments (' + $_ + ')' })
        $evidence = [ordered]@{
            'Config file'        = $Path
            'Server name'        = $s.Name
            'Scope'              = $scopeText
            'Transport'          = $transport
            'Command'            = $s.Command
            'Arguments'          = ($s.Args -join ' ')
            'Remote host'        = $urlHost
            'Env var names'      = ($s.EnvNames -join ', ')
            'Plaintext secrets'  = ($plaintext -join '; ')
            'Unpinned package'   = $unpinned
            'Reaches'            = ($categories -join ', ')
            'Disabled in config' = $(if ($s.Disabled) { 'yes' } else { $null })
        }

        New-RacFinding -Category 'ConfigAndSecrets' -Breadcrumb 'McpServerConfig' `
            -Title ("MCP server '{0}' configured for {1}" -f $s.Name, $agentName) `
            -Agent $agentName -AgentId $agentId -Location ('{0} :: {1}' -f $Path, $s.Name) -User $User `
            -EventTime $lastWrite -Evidence $evidence -Indicators $indicators -AppCategories $categories `
            -Signals @{ ServerName = $s.Name; ConfigFile = $Path; Disabled = $s.Disabled }
    }
}

# ---------------------------------------------------------------------------
# Agent footprint per profile
# ---------------------------------------------------------------------------

function Find-RacAgentFootprint {
    <# Config/memory/skills folders for one agent in one profile, plus its MCP configs and key files. #>
    param($Context, $UserProfile, $Agent)

    $sig = $Context.Signatures
    $existing = @()
    foreach ($tpl in @($Agent.configPaths)) {
        if (-not $tpl) { continue }
        $path = Expand-RacPathTemplate -Template ([string]$tpl) -ProfileRoot $UserProfile.Path
        foreach ($resolved in @(Resolve-RacPath -Path $path)) { if ($existing -notcontains $resolved) { $existing += $resolved } }
    }

    if ($existing.Count -gt 0) {
        $newest = $null
        $activity = @()
        $topItems = 0
        foreach ($p in $existing) {
            $info = Get-RacItemInfo -Path $p
            if (-not $info) { continue }
            $children = @()
            if ($info.IsDirectory) { $children = @(Get-RacChildItem -Path $p -MaxItems 500) } else { $children = @($info) }
            $topItems += $children.Count
            foreach ($c in (@($info) + $children)) {
                if ($c.LastWriteTime -is [datetime]) {
                    if ($null -eq $newest -or $c.LastWriteTime -gt $newest) { $newest = $c.LastWriteTime }
                    if ($c.LastWriteTime -ge $Context.LookbackStart) { $activity += $c.LastWriteTime }
                }
            }
        }

        # Skills, memory and instruction files: list them, and remember recent
        # changes for the self-modification check in the behavior analyzer.
        $skillItems = @()
        foreach ($tpl in @($Agent.skillPaths)) {
            if (-not $tpl) { continue }
            $path = Expand-RacPathTemplate -Template ([string]$tpl) -ProfileRoot $UserProfile.Path
            foreach ($resolved in @(Resolve-RacPath -Path $path)) {
                $info = Get-RacItemInfo -Path $resolved
                if (-not $info) { continue }
                if ($info.IsDirectory) {
                    foreach ($d in @(Get-RacChildItem -Path $resolved -MaxItems 200)) { $skillItems += ((Split-Path -Leaf $resolved) + '/' + $d.Name) }
                    $files = @(Get-RacChildItem -Path $resolved -Recurse -Depth 3 -File -MaxItems 500)
                }
                else {
                    $skillItems += $info.Name
                    $files = @($info)
                }
                foreach ($f in $files) {
                    if ($f.LastWriteTime -is [datetime] -and $f.LastWriteTime -ge $Context.LookbackStart) {
                        $Context.BehaviorSignals.SelfMod.Add([pscustomobject]@{
                                AgentId = [string]$Agent.id; Agent = [string]$Agent.name; User = $UserProfile.User
                                Path = $f.FullName; Time = $f.LastWriteTime; Source = 'file timestamp'; ByAgentProcess = $false
                            })
                    }
                }
            }
        }

        $evidence = [ordered]@{
            'Kind'                = $Agent.kind
            'Vendor'              = $Agent.vendor
            'Locations'           = ($existing -join '; ')
            'Top-level items'     = $topItems
            'Last changed'        = $newest
            'Skills / memory'     = (($skillItems | Select-Object -First 15) -join ', ')
            'Changed in lookback' = $activity.Count
        }
        New-RacFinding -Category 'ConfigAndSecrets' -Breadcrumb 'AgentConfigDir' `
            -Title ('{0} installed or configured for user {1}' -f $Agent.name, $UserProfile.User) `
            -Agent $Agent.name -AgentId $Agent.id -Location $existing[0] -User $UserProfile.User `
            -EventTime $newest -Evidence $evidence -ActivityTimes ($activity | Select-Object -First 200)

        # Plaintext keys in the agent's own config files (top level of each folder).
        $tokenPaths = @()
        foreach ($tpl in @($Agent.tokenFiles)) {
            $tp = Expand-RacPathTemplate -Template ([string]$tpl) -ProfileRoot $UserProfile.Path
            foreach ($r in @(Resolve-RacPath -Path $tp)) { $tokenPaths += $r.ToLowerInvariant() }
        }
        foreach ($p in $existing) {
            $info = Get-RacItemInfo -Path $p
            $candidates = @()
            if ($info -and $info.IsDirectory) { $candidates = @(Get-RacChildItem -Path $p -File -MaxItems 200) } elseif ($info) { $candidates = @($info) }
            foreach ($c in $candidates) {
                if ($tokenPaths -contains $c.FullName.ToLowerInvariant()) { continue }      # reported as TokenFile, never opened
                if ($c.Name -notmatch '(^\.env(\..+)?$)|\.(json|jsonc|json5|toml|ya?ml|ini|conf|cfg|txt)$') { continue }
                if ($c.Length -gt 5MB) { continue }
                $content = Read-RacTextFile -Path $c.FullName -MaxBytes 5MB
                $isEnv = ($c.Name -like '.env*')
                $scan = Get-RacSecretScan -Signatures $sig -Text $content -EnvStyle:$isEnv
                $content = $null
                if ($scan.HasSecret) {
                    New-RacSecretFileFinding -Context $Context -Path $c.FullName -Scan $scan -User $UserProfile.User -AgentName $Agent.name -AgentId $Agent.id
                }
            }
        }
    }

    # MCP configs can exist even when the main config folder is elsewhere.
    foreach ($m in @($Agent.mcpConfigFiles)) {
        if (-not $m -or -not $m.path) { continue }
        $path = Expand-RacPathTemplate -Template ([string]$m.path) -ProfileRoot $UserProfile.Path
        foreach ($resolved in @(Resolve-RacPath -Path $path)) {
            Find-RacMcpServerConfig -Context $Context -Path $resolved -Format ([string]$m.format) -Agent $Agent -User $UserProfile.User
        }
    }
}

function Find-RacIdeExtension {
    <# AI agent extensions installed in VS Code, Cursor, Windsurf, Kiro. #>
    param($Context, $UserProfile)

    $sig = $Context.Signatures
    foreach ($tpl in @($sig.ideExtensionDirs)) {
        $base = Expand-RacPathTemplate -Template ([string]$tpl) -ProfileRoot $UserProfile.Path
        if (-not (Test-RacPath -Path $base)) { continue }
        $hostName = Split-Path -Leaf (Split-Path -Parent $base)
        $newestById = [ordered]@{}
        foreach ($dir in @(Get-RacChildItem -Path $base -Directory -MaxItems 2000)) {
            $folder = $dir.Name.ToLowerInvariant()
            $id = $folder -replace '-\d+(\.\d+)+.*$', ''
            $matched = $null
            foreach ($agent in $sig.agents) {
                foreach ($pattern in @($agent.ideExtensions)) {
                    if ($pattern -and $folder -match $pattern) { $matched = $agent; break }
                }
                if ($matched) { break }
            }
            if (-not $matched -and $id -notmatch $sig.aiKeywordPattern) { continue }
            if (-not $newestById.Contains($id) -or $dir.LastWriteTime -gt $newestById[$id].Dir.LastWriteTime) {
                $newestById[$id] = [pscustomobject]@{ Dir = $dir; Agent = $matched }
            }
        }
        foreach ($id in $newestById.Keys) {
            $entry = $newestById[$id]
            $agentName = 'Unidentified AI IDE extension'
            $agentId = ''
            if ($entry.Agent) { $agentName = $entry.Agent.name; $agentId = $entry.Agent.id }
            $version = ''
            if ($entry.Dir.Name -match '-(\d+(\.\d+)+.*)$') { $version = $Matches[1] }
            $indicators = @()
            if ($entry.Dir.CreationTime -is [datetime] -and $entry.Dir.CreationTime -ge $Context.LookbackStart) { $indicators += 'RecentPackageInstall' }
            $evidence = [ordered]@{
                'IDE'          = $hostName
                'Extension'    = $id
                'Version'      = $version
                'Folder'       = $entry.Dir.FullName
                'Installed on' = $entry.Dir.CreationTime
            }
            New-RacFinding -Category 'ConfigAndSecrets' -Breadcrumb 'IdeExtension' `
                -Title ('{0} extension in {1} ({2})' -f $agentName, $hostName, $id) `
                -Agent $agentName -AgentId $agentId -Location $entry.Dir.FullName -User $UserProfile.User `
                -EventTime $entry.Dir.CreationTime -Evidence $evidence -Indicators $indicators -ActivityTimes @($entry.Dir.CreationTime)
        }
    }
}

function Find-RacAgentPackage {
    <# Agent packages installed via npm (global), pipx, uv tools, or into Python site-packages. #>
    param($Context, $UserProfile)

    $sig = $Context.Signatures
    $locations = $sig.packageLocations
    $profilePath = ''
    $profileUser = ''
    if ($UserProfile) { $profilePath = $UserProfile.Path; $profileUser = $UserProfile.User }

    foreach ($agent in $sig.agents) {
        foreach ($pkg in @($agent.packages)) {
            if (-not $pkg -or -not $pkg.name) { continue }
            $hits = @()
            if ($pkg.ecosystem -eq 'npm') {
                foreach ($tpl in @($locations.npm)) {
                    $base = Expand-RacPathTemplate -Template ([string]$tpl) -ProfileRoot $profilePath
                    foreach ($b in @(Resolve-RacPath -Path $base)) {
                        $candidate = $b
                        foreach ($segment in ([string]$pkg.name -split '/')) { $candidate = [System.IO.Path]::Combine($candidate, $segment) }
                        if (Test-RacPath -Path $candidate) { $hits += [pscustomobject]@{ Path = $candidate; Via = 'npm global' } }
                    }
                }
            }
            elseif ($pkg.ecosystem -eq 'pypi') {
                foreach ($kind in @('pipx', 'uv')) {
                    foreach ($tpl in @($locations.$kind)) {
                        $base = Expand-RacPathTemplate -Template ([string]$tpl) -ProfileRoot $profilePath
                        foreach ($b in @(Resolve-RacPath -Path $base)) {
                            $candidate = [System.IO.Path]::Combine($b, [string]$pkg.name)
                            if (Test-RacPath -Path $candidate) { $hits += [pscustomobject]@{ Path = $candidate; Via = $kind } }
                        }
                    }
                }
                $distName = ([string]$pkg.name).ToLowerInvariant() -replace '[-.]', '_'
                foreach ($tpl in @($locations.sitePackages)) {
                    $base = Expand-RacPathTemplate -Template ([string]$tpl) -ProfileRoot $profilePath
                    foreach ($b in @(Resolve-RacPath -Path $base)) {
                        foreach ($dist in @(Resolve-RacPath -Path ([System.IO.Path]::Combine($b, $distName + '-*.dist-info')))) {
                            $hits += [pscustomobject]@{ Path = $dist; Via = 'site-packages' }
                        }
                    }
                }
            }

            foreach ($hit in $hits) {
                $key = 'pkg|' + $hit.Path.ToLowerInvariant()
                if ($Context.SeenPaths.ContainsKey($key)) { continue }
                $Context.SeenPaths[$key] = $true

                $info = Get-RacItemInfo -Path $hit.Path
                $version = ''
                if ($pkg.ecosystem -eq 'npm') {
                    $manifest = ConvertFrom-RacJsonText -Text (Read-RacTextFile -Path ([System.IO.Path]::Combine($hit.Path, 'package.json')) -MaxBytes 1MB)
                    $v = Get-RacJsonProperty -Object $manifest -Name 'version'
                    if ($v) { $version = [string]$v }
                }
                elseif ($hit.Path -match '-([^-\\/]+)\.dist-info$') { $version = $Matches[1] }

                $installed = $null
                if ($info) { $installed = $info.CreationTime }
                $indicators = @()
                $recent = ($installed -is [datetime] -and $installed -ge $Context.LookbackStart)
                if ($recent) {
                    $indicators += 'RecentPackageInstall'
                    $Context.BehaviorSignals.PackageInstalls.Add([pscustomobject]@{
                            AgentId = [string]$agent.id; Agent = [string]$agent.name; User = $profileUser; Time = $installed
                            What = ('{0} {1} ({2})' -f $pkg.name, $version, $hit.Via); Source = 'install folder date'; ByAgent = $false
                        })
                }
                $owner = $profileUser
                if (-not $owner) { $owner = Get-RacUserFromPath -Path $hit.Path }
                $evidence = [ordered]@{
                    'Package'      = $pkg.name
                    'Ecosystem'    = $pkg.ecosystem
                    'Installed via' = $hit.Via
                    'Version'      = $version
                    'Install path' = $hit.Path
                    'Installed on' = $installed
                }
                New-RacFinding -Category 'ConfigAndSecrets' -Breadcrumb 'AgentPackage' `
                    -Title ('{0} package installed: {1} {2}' -f $agent.name, $pkg.name, $version) `
                    -Agent $agent.name -AgentId $agent.id -Location $hit.Path -User $owner `
                    -EventTime $installed -Evidence $evidence -Indicators $indicators -ActivityTimes @($installed)
            }
        }
    }
}

function Find-RacProjectFile {
    <#
        Walks a folder tree for project-level agent files: .env files with AI
        keys, project MCP configs (.mcp.json, .vscode/mcp.json, ...) and project
        transcripts (.aider.chat.history.md).
    #>
    param($Context, [string]$Root, [string]$User)

    $sig = $Context.Signatures
    $pf = $sig.projectFiles
    $names = @($pf.envFileNames) + @('.mcp.json', 'mcp.json', 'settings.json') + @($pf.transcriptFiles | ForEach-Object { $_.name })
    $files = @(Find-RacFileByName -Root $Root -NamePattern $names -ExcludeDirectory @($pf.excludeDirs) -MaxDepth ([int]$pf.maxDepth) -MaxDirectories ([int]$pf.maxDirectories))

    foreach ($f in $files) {
        $leaf = $f.Name
        $parent = Split-Path -Leaf (Split-Path -Parent $f.FullName)
        $owner = $User
        if (-not $owner) { $owner = Get-RacUserFromPath -Path $f.FullName }

        # .env files
        $isEnv = $false
        foreach ($p in @($pf.envFileNames)) { if ($leaf -like $p) { $isEnv = $true } }
        if ($isEnv -and @($pf.envFileIgnore) -notcontains $leaf) {
            $content = Read-RacTextFile -Path $f.FullName -MaxBytes 1MB
            $scan = Get-RacSecretScan -Signatures $sig -Text $content -EnvStyle
            $content = $null
            if ($scan.HasSecret) {
                New-RacSecretFileFinding -Context $Context -Path $f.FullName -Scan $scan -User $owner -AgentName 'Unattributed (.env file)' -AgentId ''
            }
            continue
        }

        # Project MCP configs
        foreach ($m in @($pf.mcpConfigFiles)) {
            $rel = ([string]$m.relativePath) -split '/'
            $matches2 = $false
            if ($rel.Count -eq 1 -and $leaf -eq $rel[0]) { $matches2 = $true }
            if ($rel.Count -eq 2 -and $leaf -eq $rel[1] -and $parent -eq $rel[0]) { $matches2 = $true }
            if ($matches2) {
                $agent = $sig._AgentById[[string]$m.agentId]
                $projectDir = Split-Path -Parent $f.FullName
                if ($rel.Count -eq 2) { $projectDir = Split-Path -Parent $projectDir }
                Find-RacMcpServerConfig -Context $Context -Path $f.FullName -Format 'json' -Agent $agent -User $owner -Scope ('Project ' + $projectDir)
            }
        }

        # Project transcripts
        foreach ($t in @($pf.transcriptFiles)) {
            if ($leaf -ne $t.name) { continue }
            $agent = $sig._AgentById[[string]$t.agentId]
            $evidence = [ordered]@{
                'File'          = $f.FullName
                'Size (KB)'     = [math]::Round($f.Length / 1KB, 1)
                'Last modified' = $f.LastWriteTime
                'Project'       = (Split-Path -Parent $f.FullName)
            }
            New-RacFinding -Category 'LogsAndEvents' -Breadcrumb 'AgentTranscript' `
                -Title ('{0} chat history in project {1}' -f $agent.name, (Split-Path -Leaf (Split-Path -Parent $f.FullName))) `
                -Agent $agent.name -AgentId $agent.id -Location $f.FullName -User $owner `
                -EventTime $f.LastWriteTime -Evidence $evidence -ActivityTimes @($f.LastWriteTime)
        }
    }
}

function Find-RacEnvVarSecret {
    <# AI provider keys set as environment variables. Names only: values are never read. #>
    param($Context)
    $sig = $Context.Signatures
    foreach ($v in @(Get-RacRawEnvironmentVariable)) {
        if (-not $v -or -not $v.Name -or $v.Name -notmatch $sig.secretEnvNamePattern) { continue }
        $indicators = @('SecretInPlaintext')
        $where = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
        if ($v.Scope -eq 'Machine') { $indicators += 'MachineWideSecret' } else { $where = 'HKU\' + $v.User + '\Environment' }
        $provider = Get-RacProviderFromVariableName -Name $v.Name
        $evidence = [ordered]@{
            'Variable' = $v.Name
            'Scope'    = $v.Scope
            'User'     = $v.User
            'Provider' = $provider
            'Value'    = 'not read'
        }
        $title = '{0} key set as a {1} environment variable ({2})' -f $provider, $v.Scope.ToLowerInvariant(), $v.Name
        New-RacFinding -Category 'ConfigAndSecrets' -Breadcrumb 'EnvVarSecret' -Title $title `
            -Agent 'Unattributed (environment)' -Location $where -User $v.User `
            -Evidence $evidence -Indicators $indicators
    }
}

function Find-RacConfigFinding {
    param([Parameter(Mandatory = $true)]$Context)

    $sig = $Context.Signatures
    foreach ($userProfile in @($Context.ProfileRoots)) {
        if (-not $userProfile.Readable) { continue }
        Write-RacLog -Level ACTION -Message ('Scanning profile ' + $userProfile.Path)
        foreach ($agent in $sig.agents) {
            Find-RacAgentFootprint -Context $Context -UserProfile $userProfile -Agent $agent
        }
        Find-RacIdeExtension -Context $Context -UserProfile $userProfile
        Find-RacAgentPackage -Context $Context -UserProfile $userProfile

        foreach ($rootName in @($sig.projectFiles.searchRootNames)) {
            $root = [System.IO.Path]::Combine($userProfile.Path, [string]$rootName)
            if (Test-RacPath -Path $root) {
                Find-RacProjectFile -Context $Context -Root $root -User $userProfile.User
            }
        }
    }

    # Machine-wide package locations (for example %PROGRAMFILES%\nodejs).
    Find-RacAgentPackage -Context $Context -UserProfile $null

    foreach ($root in @($Context.SearchRoots)) {
        if (-not $root) { continue }
        if (Test-RacPath -Path $root) {
            Write-RacLog -Level ACTION -Message ('Scanning extra search root ' + $root)
            Find-RacProjectFile -Context $Context -Root $root -User ''
            Add-RacCoverage -Source ('Search root: ' + $root) -Status 'Checked'
        }
        else {
            Add-RacCoverage -Source ('Search root: ' + $root) -Status 'Skipped' -Detail 'Path not found.'
        }
    }

    Find-RacEnvVarSecret -Context $Context
    Add-RacCoverage -Source 'Agent folders, MCP configs, .env files, packages' -Status 'Info' -ItemCount @($Context.ProfileRoots | Where-Object { $_.Readable }).Count -Detail 'Profiles examined. Project folders are searched to depth 4 under Desktop, Documents, Downloads, source, src, dev, code, repos, projects, git, GitHub, workspace, work. OneDrive is skipped.'
}
