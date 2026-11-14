<#
    Signatures.ps1 - loads Data/signatures.json and answers "what is this?"

    The catalog is data, not code: to teach RAC about a new agent, add an entry
    to signatures.json. These functions only match text against that data.
#>

function Import-RacSignatureFile {
    <#
        Loads and validates the signature catalog, precompiles a few lookups, and
        registers the catalog's secret formats with the redaction engine.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $text = Read-RacTextFile -Path $Path -MaxBytes 10MB
    if (-not $text) { throw "Signature file not found or unreadable: $Path" }

    try {
        $sig = $text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw ("Signature file is not valid JSON: {0}. {1}" -f $Path, $_.Exception.Message)
    }
    if ($sig.schemaVersion -ne 1) { throw "Unsupported signature schemaVersion '$($sig.schemaVersion)' in $Path (expected 1)." }
    if (-not $sig.agents) { throw "Signature file has no 'agents' section: $Path" }

    Set-RacSecretPattern -Pattern @($sig.secretPatterns)

    # Precompute per-agent regexes used when matching free text (task commands,
    # event log text, file paths). Stored on the agent object with a leading
    # underscore to mark them as derived, not catalog content.
    $agentById = @{}
    foreach ($agent in $sig.agents) {
        $agentById[[string]$agent.id] = $agent

        $exeRules = @()
        foreach ($rule in @($agent.processes)) {
            if (-not $rule -or -not $rule.name) { continue }
            $exeRules += [pscustomobject]@{
                ExeRegex  = '(^|[/\\" ])' + [regex]::Escape(([string]$rule.name).ToLowerInvariant()) + '("|\s|$)'
                PathRegex = [string]$rule.path
            }
        }
        $pathFragments = @()
        foreach ($tpl in (@($agent.configPaths) + @($agent.skillPaths))) {
            if (-not $tpl) { continue }
            $fragment = ConvertTo-RacPathFragmentRegex -Template ([string]$tpl)
            if ($fragment) { $pathFragments += $fragment }
        }
        $skillFragments = @()
        foreach ($tpl in @($agent.skillPaths)) {
            if (-not $tpl) { continue }
            $fragment = ConvertTo-RacPathFragmentRegex -Template ([string]$tpl)
            if ($fragment) { $skillFragments += $fragment }
        }
        $agent | Add-Member -NotePropertyName '_ExeRules' -NotePropertyValue $exeRules -Force
        $agent | Add-Member -NotePropertyName '_PathFragments' -NotePropertyValue $pathFragments -Force
        $agent | Add-Member -NotePropertyName '_SkillFragments' -NotePropertyValue $skillFragments -Force
    }

    $weights = @{}
    $descriptions = @{}
    foreach ($prop in $sig.scoring.indicators.PSObject.Properties) {
        $weights[$prop.Name] = [int]$prop.Value.weight
        $descriptions[$prop.Name] = [string]$prop.Value.description
    }

    $sig | Add-Member -NotePropertyName '_AgentById' -NotePropertyValue $agentById -Force
    $sig | Add-Member -NotePropertyName '_EndpointRegex' -NotePropertyValue (ConvertTo-RacEndpointRegex -Endpoint @($sig.llmEndpoints)) -Force
    $sig | Add-Member -NotePropertyName '_IndicatorWeights' -NotePropertyValue $weights -Force
    $sig | Add-Member -NotePropertyName '_IndicatorDescriptions' -NotePropertyValue $descriptions -Force
    $sig | Add-Member -NotePropertyName '_SourcePath' -NotePropertyValue $Path -Force
    $sig | Add-Member -NotePropertyName '_Sha256' -NotePropertyValue (Get-RacFileSha256 -Path $Path) -Force

    Write-RacLog -Level ACTION -Message ("Loaded signature catalog {0}: {1} agents, {2} LLM endpoints, {3} secret formats (SHA-256 {4})" -f $sig.catalogVersion, @($sig.agents).Count, @($sig.llmEndpoints).Count, @($sig.secretPatterns).Count, $sig._Sha256)
    return $sig
}

function ConvertTo-RacEndpointRegex {
    <#
        Builds ONE regex that finds any LLM API hostname inside free text (proxy
        log lines, script blocks). Capture group 1 is the hostname.
        Wildcards: a leading '*.' means any subdomain; any other '*' means one
        label fragment (for example a region name).
    #>
    param([object[]]$Endpoint)

    $parts = @()
    foreach ($e in $Endpoint) {
        $p = ([string]$e.pattern).ToLowerInvariant()
        if (-not $p) { continue }
        if ($p.StartsWith('*.')) {
            $parts += '(?:[a-z0-9-]+\.)+' + ([regex]::Escape($p.Substring(2)) -replace '\\\*', '[a-z0-9-]*')
        }
        else {
            $parts += ([regex]::Escape($p) -replace '\\\*', '[a-z0-9-]*')
        }
    }
    if ($parts.Count -eq 0) { return '(?!x)x' }
    return '(?<![a-z0-9.-])(' + ($parts -join '|') + ')(?!\.?[a-z0-9-])'
}

function Find-RacLlmEndpoint {
    <# Returns the llmEndpoints entry matching a hostname, or $null. #>
    param($Signatures, [string]$HostName)
    if ([string]::IsNullOrEmpty($HostName)) { return $null }
    $h = $HostName.ToLowerInvariant().TrimEnd('.')
    foreach ($e in $Signatures.llmEndpoints) {
        if ($h -like ([string]$e.pattern).ToLowerInvariant()) { return $e }
    }
    return $null
}

function Find-RacAgentByProcess {
    <#
        Identifies a running process from its name, executable path and command
        line. Returns @{ Agent; Reason } or $null. First matching agent wins.
    #>
    param($Signatures, [string]$Name, [string]$Path, [string]$CommandLine)

    $n = ([string]$Name).ToLowerInvariant()
    $p = ConvertTo-RacNormalizedText $Path
    $c = ConvertTo-RacNormalizedText $CommandLine

    foreach ($agent in $Signatures.agents) {
        foreach ($rule in @($agent.processes)) {
            if (-not $rule -or -not $rule.name) { continue }
            if ($n -ne ([string]$rule.name).ToLowerInvariant()) { continue }
            if ($rule.path -and $p -notmatch $rule.path) { continue }
            $reason = "process name '$Name'"
            if ($rule.path) { $reason += " in a path matching /$($rule.path)/" }
            return [pscustomobject]@{ Agent = $agent; Reason = $reason }
        }
        foreach ($pattern in @($agent.commandLinePatterns)) {
            if ($pattern -and $c -match $pattern) {
                return [pscustomobject]@{ Agent = $agent; Reason = "command line matches /$pattern/" }
            }
        }
    }
    return $null
}

function Find-RacAgentByText {
    <#
        Identifies an agent from free text: an autostart command, an event's
        command line, a file path. Checks executable names, command-line
        patterns and references to the agent's config folders. With
        -IncludeKeywords it also matches product keywords (for names such as a
        scheduled task called "OpenClaw Gateway").
    #>
    param($Signatures, [AllowEmptyString()][string]$Text, [switch]$IncludeKeywords, [switch]$KeywordsOnly)

    $t = ConvertTo-RacNormalizedText $Text
    if (-not $t) { return $null }

    foreach ($agent in $Signatures.agents) {
        if (-not $KeywordsOnly) {
            foreach ($rule in @($agent._ExeRules)) {
                if ($t -match $rule.ExeRegex -and (-not $rule.PathRegex -or $t -match $rule.PathRegex)) {
                    return [pscustomobject]@{ Agent = $agent; Reason = 'references the executable of ' + $agent.name }
                }
            }
            foreach ($pattern in @($agent.commandLinePatterns)) {
                if ($pattern -and $t -match $pattern) {
                    return [pscustomobject]@{ Agent = $agent; Reason = "text matches /$pattern/" }
                }
            }
            foreach ($fragment in @($agent._PathFragments)) {
                if ($t -match $fragment) {
                    return [pscustomobject]@{ Agent = $agent; Reason = 'references a ' + $agent.name + ' folder' }
                }
            }
        }
        if ($IncludeKeywords -or $KeywordsOnly) {
            foreach ($k in @($agent.keywords)) {
                if ($k -and $t -match $k) {
                    return [pscustomobject]@{ Agent = $agent; Reason = "name matches /$k/" }
                }
            }
        }
    }
    return $null
}

function Find-RacAgentBySkillPath {
    <# True-ish (returns the agent) if a file path is inside an agent's skills/memory locations. #>
    param($Signatures, [string]$Path)
    $t = ConvertTo-RacNormalizedText $Path
    if (-not $t) { return $null }
    foreach ($agent in $Signatures.agents) {
        foreach ($fragment in @($agent._SkillFragments)) {
            if ($t -match $fragment) { return $agent }
        }
    }
    return $null
}

function Get-RacGenericMatch {
    <# First matching pattern from signatures.genericPatterns.<Group>, or $null. #>
    param($Signatures, [string]$Group, [AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $patterns = @($Signatures.genericPatterns.$Group)
    return (Get-RacFirstRegexMatch -Text (ConvertTo-RacNormalizedText $Text) -Pattern $patterns)
}

function Test-RacNameInList {
    param($Signatures, [string]$Group, [string]$Name)
    if (-not $Name) { return $false }
    return (@($Signatures.genericPatterns.$Group) -contains $Name.ToLowerInvariant())
}

function Get-RacMcpAppCategory {
    <#
        Which application categories (email, chat, files, shell, ...) does an MCP
        server reach? Keyword match with word boundaries on the server name,
        command and non-path arguments.
    #>
    param($Signatures, [AllowEmptyString()][string]$Text)

    $t = ConvertTo-RacNormalizedText $Text
    $cats = @()
    if (-not $t) { return $cats }
    foreach ($prop in $Signatures.mcpAppCategories.PSObject.Properties) {
        foreach ($kw in @($prop.Value)) {
            $rx = '(^|[^a-z0-9])' + [regex]::Escape([string]$kw) + '([^a-z0-9]|$)'
            if ($t -match $rx) { $cats += $prop.Name; break }
        }
    }
    return @($cats | Select-Object -Unique)
}

function Get-RacUnpinnedPackageSpec {
    <#
        If a command runs a package straight from a registry without a pinned
        version (npx -y pkg, npx pkg@latest, uvx pkg), returns the package spec.
        Unpinned packages can change code on every launch.
    #>
    param([AllowEmptyString()][string]$Text)

    $t = ConvertTo-RacNormalizedText $Text
    if (-not $t) { return $null }

    if ($t -match '(^|[ /"])npx(\.cmd)?"?\s+(?:(?:-y|--yes|-q|--quiet)\s+)*(@?[a-z0-9][a-z0-9._-]*(?:/[a-z0-9._-]+)?(?:@[^\s"]+)?)') {
        $spec = $Matches[3]
        if ($spec.StartsWith('@')) { $version = (($spec.Substring(1)) -split '@', 2)[1] }
        else { $version = ($spec -split '@', 2)[1] }
        if (-not $version -or $version -eq 'latest') { return $spec }
    }
    if ($t -match '(^|[ /"])uvx(\.exe)?"?\s+(?:-[^\s]+\s+)*([a-z0-9][a-z0-9._\[\]-]*(?:(?:==|@)[^\s"]+)?)') {
        $spec = $Matches[3]
        if ($spec -notmatch '==|@' -or $spec -match '@latest$') { return $spec }
    }
    return $null
}

function Get-RacProviderFromVariableName {
    <# OPENAI_API_KEY -> 'OpenAI'. Display only. #>
    param([string]$Name)
    $map = [ordered]@{
        'ANTHROPIC|CLAUDE' = 'Anthropic'; 'AZURE_OPENAI|AZURE_AI' = 'Azure OpenAI / AI Foundry'; 'OPENAI' = 'OpenAI'
        'GEMINI|GOOGLE|VERTEX' = 'Google'; 'MISTRAL' = 'Mistral'; 'GROQ' = 'Groq'; 'COHERE|^CO_API' = 'Cohere'
        'OPENROUTER' = 'OpenRouter'; 'DEEPSEEK' = 'DeepSeek'; 'XAI|GROK' = 'xAI'; 'PERPLEXITY|PPLX' = 'Perplexity'
        'HF_|HUGGING' = 'Hugging Face'; 'TOGETHER' = 'Together AI'; 'FIREWORKS' = 'Fireworks AI'; 'REPLICATE' = 'Replicate'
        'CEREBRAS' = 'Cerebras'; 'MOONSHOT' = 'Moonshot'; 'DASHSCOPE' = 'Alibaba DashScope'; 'OPENCLAW' = 'OpenClaw'
        'LANGCHAIN|LANGSMITH' = 'LangChain / LangSmith'; 'TAVILY' = 'Tavily'; 'EXA' = 'Exa'; 'FIRECRAWL' = 'Firecrawl'; 'BRAVE' = 'Brave Search'
    }
    foreach ($k in $map.Keys) { if ($Name -match $k) { return $map[$k] } }
    return 'AI provider'
}
