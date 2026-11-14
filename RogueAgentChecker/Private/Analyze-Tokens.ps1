<#
    Analyze-Tokens.ps1 - Category 5: OAuth grants and stored tokens for AI
    applications, where an endpoint can see them.

      * Windows Credential Manager target NAMES (cmdkey; secrets never shown)
      * Token / credential files by path, size and date (never opened)
      * Browser extensions for AI apps, with their control permissions
      * Native messaging hosts (local programs a browser extension can drive)

    Not visible from an endpoint: tenant-side consent grants (Entra ID enterprise
    apps, Google Workspace third-party access). The coverage section says so.
#>

function Find-RacTokenFinding {
    param([Parameter(Mandatory = $true)]$Context)

    $sig = $Context.Signatures

    # ---- Credential Manager ------------------------------------------------------
    $currentUser = Get-RacCurrentIdentity
    foreach ($c in @(Get-RacRawCredentialTarget)) {
        if (-not $c -or -not $c.Target) { continue }
        $target = [string]$c.Target
        $normalized = ConvertTo-RacNormalizedText $target
        $agent = $null
        foreach ($a in $sig.agents) {
            foreach ($rx in @($a.credentialTargets)) {
                if ($rx -and $normalized -match $rx) { $agent = $a; break }
            }
            if ($agent) { break }
        }
        if (-not $agent -and $normalized -notmatch $sig.aiKeywordPattern) { continue }
        $agentName = 'Unidentified AI application'
        $agentId = ''
        if ($agent) { $agentName = $agent.name; $agentId = $agent.id }
        $evidence = [ordered]@{
            'Credential target' = $target
            'Vault'             = 'Windows Credential Manager (current user)'
            'Secret'            = 'not read (cmdkey lists target names only)'
        }
        New-RacFinding -Category 'TokensAndOAuth' -Breadcrumb 'CredentialStore' `
            -Title ('Stored credential for {0} in Credential Manager' -f $agentName) `
            -Agent $agentName -AgentId $agentId -Location ('Credential Manager: ' + $target) -User $currentUser `
            -Evidence $evidence -Indicators @('StoredOAuthToken')
    }

    foreach ($userProfile in @($Context.ProfileRoots)) {
        if (-not $userProfile.Readable) { continue }

        # ---- Token files (presence only) ------------------------------------------
        foreach ($agent in $sig.agents) {
            foreach ($tpl in @($agent.tokenFiles)) {
                if (-not $tpl) { continue }
                $path = Expand-RacPathTemplate -Template ([string]$tpl) -ProfileRoot $userProfile.Path
                foreach ($resolved in @(Resolve-RacPath -Path $path)) {
                    $info = Get-RacItemInfo -Path $resolved
                    if (-not $info) { continue }
                    $acl = Get-RacFileAclSummary -Path $resolved
                    $indicators = @('StoredOAuthToken')
                    if ($acl -and $acl.BroadRead) { $indicators += 'SecretWorldReadable' }
                    $sizeText = '{0:N0} bytes' -f $info.Length
                    if ($info.IsDirectory) { $sizeText = '{0} item(s)' -f @(Get-RacChildItem -Path $resolved -MaxItems 500).Count }
                    $evidence = [ordered]@{
                        'Path'          = $resolved
                        'Size'          = $sizeText
                        'Last modified' = $info.LastWriteTime
                        'Contents'      = 'not opened (RAC reports token files by presence only)'
                    }
                    if ($acl -and $acl.BroadRead) { $evidence['Readable by'] = ($acl.Identities -join ', ') }
                    New-RacFinding -Category 'TokensAndOAuth' -Breadcrumb 'TokenFile' `
                        -Title ('{0} sign-in token stored for user {1}' -f $agent.name, $userProfile.User) `
                        -Agent $agent.name -AgentId $agent.id -Location $resolved -User $userProfile.User `
                        -EventTime $info.LastWriteTime -Evidence $evidence -Indicators $indicators -ActivityTimes @($info.LastWriteTime)
                }
            }
        }

        # ---- Browser extensions ------------------------------------------------------
        $knownIds = @{}
        foreach ($k in @($sig.knownBrowserExtensions)) { $knownIds[[string]$k.id] = $k }
        foreach ($bp in @($sig.browserProfiles)) {
            $userData = Expand-RacPathTemplate -Template ([string]$bp.path) -ProfileRoot $userProfile.Path
            if (-not (Test-RacPath -Path $userData)) { continue }
            foreach ($browserProfile in @(Get-RacChildItem -Path $userData -Directory -MaxItems 100)) {
                $extRoot = [System.IO.Path]::Combine($browserProfile.FullName, 'Extensions')
                if (-not (Test-RacPath -Path $extRoot)) { continue }
                foreach ($extDir in @(Get-RacChildItem -Path $extRoot -Directory -MaxItems 500)) {
                    if ($extDir.Name -eq 'Temp') { continue }
                    $versionDir = @(Get-RacChildItem -Path $extDir.FullName -Directory -MaxItems 20) | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if (-not $versionDir) { continue }
                    $manifest = ConvertFrom-RacJsonText -Text (Read-RacTextFile -Path ([System.IO.Path]::Combine($versionDir.FullName, 'manifest.json')) -MaxBytes 1MB)
                    if (-not $manifest) { continue }

                    $name = [string](Get-RacJsonProperty -Object $manifest -Name 'name')
                    $description = [string](Get-RacJsonProperty -Object $manifest -Name 'description')
                    if ($name -match '^__MSG_(.+)__$') {
                        $msgKey = $Matches[1]
                        foreach ($locale in @('en', 'en_US', 'en_GB')) {
                            $messages = ConvertFrom-RacJsonText -Text (Read-RacTextFile -Path ([System.IO.Path]::Combine($versionDir.FullName, '_locales', $locale, 'messages.json')) -MaxBytes 1MB)
                            if ($messages) {
                                foreach ($p in $messages.PSObject.Properties) {
                                    if ($p.Name -ieq $msgKey) { $name = [string](Get-RacJsonProperty -Object $p.Value -Name 'message') }
                                }
                                break
                            }
                        }
                    }

                    $known = $knownIds[$extDir.Name]
                    $isAi = [bool]$known -or ((ConvertTo-RacNormalizedText ($name + ' ' + $description)) -match $sig.aiKeywordPattern)
                    if (-not $isAi) { continue }

                    $permissions = @(Get-RacJsonProperty -Object $manifest -Name 'permissions') + @(Get-RacJsonProperty -Object $manifest -Name 'host_permissions') + @(Get-RacJsonProperty -Object $manifest -Name 'optional_permissions')
                    $notable = @($permissions | Where-Object { $_ -is [string] -and @('debugger', 'nativeMessaging', '<all_urls>', 'scripting', 'tabs', 'cookies', 'webRequest', 'clipboardRead', 'history', 'downloads', 'management', 'sidePanel') -contains $_ } | Select-Object -Unique)
                    $indicators = @()
                    if ($notable -contains 'debugger' -or $notable -contains 'nativeMessaging') { $indicators += 'BrowserControlPermission' }

                    $agentName = 'Unidentified AI browser extension'
                    $agentId = ''
                    if ($known -and $known.agentId -and $sig._AgentById.ContainsKey([string]$known.agentId)) {
                        $agentName = $sig._AgentById[[string]$known.agentId].name
                        $agentId = [string]$known.agentId
                    }
                    else {
                        $byText = Find-RacAgentByText -Signatures $sig -Text $name -KeywordsOnly
                        if ($byText) { $agentName = $byText.Agent.name; $agentId = $byText.Agent.id }
                    }

                    $evidence = [ordered]@{
                        'Browser'             = '{0} ({1})' -f $bp.browser, $browserProfile.Name
                        'Extension'           = $name
                        'Extension ID'        = $extDir.Name
                        'Version'             = $versionDir.Name
                        'Notable permissions' = ($notable -join ', ')
                        'Folder'              = $versionDir.FullName
                    }
                    New-RacFinding -Category 'TokensAndOAuth' -Breadcrumb 'BrowserExtension' `
                        -Title ("AI browser extension '{0}' in {1}" -f $name, $bp.browser) `
                        -Agent $agentName -AgentId $agentId -Location $versionDir.FullName -User $userProfile.User `
                        -EventTime $versionDir.LastWriteTime -Evidence $evidence -Indicators $indicators
                }
            }
        }
    }

    # ---- Native messaging hosts ------------------------------------------------------
    foreach ($h in @(Get-RacRawNativeMessagingHost)) {
        if (-not $h) { continue }
        $manifest = $null
        if ($h.ManifestPath) { $manifest = ConvertFrom-RacJsonText -Text (Read-RacTextFile -Path $h.ManifestPath -MaxBytes 1MB) }
        $hostExe = [string](Get-RacJsonProperty -Object $manifest -Name 'path')
        $description = [string](Get-RacJsonProperty -Object $manifest -Name 'description')
        $origins = @(Get-RacJsonProperty -Object $manifest -Name 'allowed_origins') + @(Get-RacJsonProperty -Object $manifest -Name 'allowed_extensions')
        $text = '{0} {1} {2} {3}' -f $h.HostName, $description, $hostExe, $h.ManifestPath

        $byText = Find-RacAgentByText -Signatures $sig -Text $text -IncludeKeywords
        if (-not $byText -and (ConvertTo-RacNormalizedText $text) -notmatch $sig.aiKeywordPattern) { continue }
        $agentName = 'Unidentified AI application'
        $agentId = ''
        if ($byText) { $agentName = $byText.Agent.name; $agentId = $byText.Agent.id }

        $evidence = [ordered]@{
            'Browser'          = $h.Browser
            'Registered for'   = $(if ($h.User) { '{0} ({1})' -f $h.Scope, $h.User } else { $h.Scope })
            'Host name'        = $h.HostName
            'Manifest'         = $h.ManifestPath
            'Host program'     = $hostExe
            'Allowed callers'  = (($origins | Where-Object { $_ }) -join ', ')
        }
        $user = $h.User
        if (-not $user) { $user = Get-RacUserFromPath -Path $h.ManifestPath }
        New-RacFinding -Category 'TokensAndOAuth' -Breadcrumb 'NativeMessagingHost' `
            -Title ("Browser bridge '{0}' lets {1} drive {2}" -f $h.HostName, $agentName, $h.Browser) `
            -Agent $agentName -AgentId $agentId -Location ('{0} native messaging: {1}' -f $h.Browser, $h.HostName) -User $user `
            -Evidence $evidence -Indicators @('BrowserControlBridge')
    }

    Add-RacCoverage -Source 'Tenant OAuth consent grants' -Status 'Skipped' -Detail 'Not visible from an endpoint. Review enterprise app consents in Entra ID / Google Workspace admin consoles.'
}
