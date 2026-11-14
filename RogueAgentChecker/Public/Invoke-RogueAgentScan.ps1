function Invoke-RogueAgentScan {
    <#
    .SYNOPSIS
        Finds AI agents on this machine and reports which are approved, unknown, or suspicious.

    .DESCRIPTION
        Rogue Agent Checker is RogueChecker for agentic AI. It looks for seven kinds
        of breadcrumbs (processes, network, config and secrets, persistence, tokens,
        logs and events, behavior), compares every agent it finds against your
        allow-list, and labels each finding Trusted, Unknown or Suspicious with the
        evidence and the reasoning.

        READ-ONLY: nothing is disabled, blocked, deleted or changed.
        LOCAL-ONLY: no network requests or DNS lookups; no data leaves the machine.
        Secrets are detected by name and format; values are never recorded.

        Runs as a standard user. Elevation widens coverage (other users' processes
        and profiles, the Security log, WMI subscriptions); the report's Coverage
        section lists anything that could not be examined.

    .PARAMETER OutputPath
        Folder for the HTML / CSV / JSON report and the scan log. Created if missing.

    .PARAMETER AllowListPath
        Allow-list of approved agents (.json or .csv). Without one, nothing can be Trusted.

    .PARAMETER SignaturePath
        Detection catalog. Defaults to Data\signatures.json inside the module.

    .PARAMETER ProfileRoot
        Scan only these user profile folders (default: every local profile that can be read).

    .PARAMETER SearchRoot
        Extra folders to search for .env files, project MCP configs and agent transcripts
        (for example D:\Source).

    .PARAMETER ProxyLogPath
        Proxy log files or folders to search for LLM API hostnames.

    .PARAMETER Category
        Limit the scan to some categories. Behavior is derived from the others.

    .PARAMETER NetworkSamples
        Take this many TCP snapshots, SampleIntervalSeconds apart, to spot persistent connections.

    .PARAMETER IncludeBrowserAiSessions
        Itemize ordinary browser connections to AI web apps (counted but hidden by default).

    .PARAMETER CheckSignatures
        Record the Authenticode signer of agent executables. Off by default because Windows
        may contact the certificate authority to check revocation.

    .PARAMETER NoReport
        Do not write HTML / CSV / JSON (the scan log is still written).

    .PARAMETER PassThru
        Return the scan result object.

    .EXAMPLE
        Invoke-RogueAgentScan -AllowListPath .\allowlist.json -OutputPath C:\RAC\Reports

    .EXAMPLE
        Invoke-RogueAgentScan -Category Processes, Network -NetworkSamples 3 -PassThru |
            Select-Object -ExpandProperty Findings | Format-Table FindingId, Classification, Agent, Title
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath 'RogueAgentReports'),
        [string]$AllowListPath,
        [string]$SignaturePath,
        [string[]]$ProfileRoot,
        [string[]]$SearchRoot,
        [string[]]$ProxyLogPath,
        [ValidateRange(1, 90)][int]$LookbackDays = 7,
        [ValidateRange(0, 23)][int]$BusinessHoursStart = 7,
        [ValidateRange(1, 24)][int]$BusinessHoursEnd = 19,
        [ValidateSet('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')]
        [string[]]$BusinessDays = @('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'),
        [ValidateRange(1, 720)][int]$LongRunningHours = 8,
        [ValidateRange(1, 10)][int]$NetworkSamples = 1,
        [ValidateRange(1, 300)][int]$SampleIntervalSeconds = 15,
        [ValidateRange(100, 100000)][int]$MaxEventsPerLog = 5000,
        [ValidateSet('Processes', 'Network', 'ConfigAndSecrets', 'Persistence', 'TokensAndOAuth', 'LogsAndEvents', 'Behavior')]
        [string[]]$Category = @('Processes', 'Network', 'ConfigAndSecrets', 'Persistence', 'TokensAndOAuth', 'LogsAndEvents', 'Behavior'),
        [switch]$IncludeBrowserAiSessions,
        [switch]$CheckSignatures,
        [switch]$NoReport,
        [switch]$PassThru
    )

    $startTime = Get-Date
    $computer = Get-RacComputerName
    $stamp = $startTime.ToString('yyyyMMdd-HHmmss')
    $baseName = 'RogueAgentReport_{0}_{1}' -f ($computer -replace '[^A-Za-z0-9_-]', '_'), $stamp
    if (-not $SignaturePath) { $SignaturePath = Join-Path -Path $script:RacModuleRoot -ChildPath 'Data/signatures.json' }

    # ---- Start the log first, so every later step is recorded ----------------
    $logPath = Join-Path -Path $OutputPath -ChildPath ($baseName + '_scan.log')
    Initialize-RacScanState -LogPath $logPath
    try {
        $runAs = Get-RacCurrentIdentity
        $elevated = Get-RacIsElevated
        Write-RacLog -Level ACTION -Message ("Scan started on {0} as {1} (elevated: {2}). Rogue Agent Checker {3}, PowerShell {4}." -f $computer, $runAs, $elevated, $script:RacVersion, $PSVersionTable.PSVersion)
        Write-RacLog -Level INFO -Message ("Parameters: categories={0}; lookbackDays={1}; businessHours={2}-{3} {4}; networkSamples={5}; checkSignatures={6}; includeBrowserAiSessions={7}" -f ($Category -join ','), $LookbackDays, $BusinessHoursStart, $BusinessHoursEnd, ($BusinessDays -join ','), $NetworkSamples, [bool]$CheckSignatures, [bool]$IncludeBrowserAiSessions)
        if (-not (Test-RacIsWindows)) {
            Write-RacLog -Level WARN -Message 'Not running on Windows: Windows-only sources will be skipped and recorded in Coverage.'
        }

        # ---- Policy: signatures and allow-list -------------------------------------
        $signatures = Import-RacSignatureFile -Path $SignaturePath
        $allowList = $null
        $knownIndicators = @($signatures._IndicatorWeights.Keys)
        if ($AllowListPath) {
            $allowList = Read-RacAllowListFile -Path $AllowListPath -KnownIndicators $knownIndicators
            Write-RacLog -Level ACTION -Message ("Loaded allow-list {0}: {1} entries (SHA-256 {2})" -f $AllowListPath, @($allowList.Entries).Count, $allowList.Sha256)
            foreach ($w in $allowList.Warnings) { Write-RacLog -Level WARN -Message $w; Write-Warning $w }
        }
        else {
            $msg = 'No allow-list supplied: every agent found will be Unknown or Suspicious.'
            Write-RacLog -Level WARN -Message $msg
            Add-RacCoverage -Source 'Allow-list' -Status 'Info' -Detail $msg
        }

        # ---- Profiles ------------------------------------------------------------------
        if ($ProfileRoot) {
            $profiles = foreach ($p in $ProfileRoot) {
                [pscustomobject]@{ User = (Split-Path -Leaf $p); Path = $p; Readable = (Test-RacPath -Path $p) }
            }
            Add-RacCoverage -Source 'User profiles (from -ProfileRoot)' -Status 'Checked' -ItemCount @($profiles).Count
        }
        else {
            $profiles = Get-RacProfileRoot
        }

        # ---- Scan context shared by all analyzers ---------------------------------------
        $context = [pscustomobject]@{
            ScanId          = [guid]::NewGuid().ToString()
            ComputerName    = $computer
            Now             = $startTime
            LookbackStart   = $startTime.AddDays(-$LookbackDays)
            Signatures      = $signatures
            ProfileRoots    = @($profiles)
            SearchRoots     = @($SearchRoot)
            ProxyLogPaths   = @($ProxyLogPath)
            Options         = [pscustomobject]@{
                LookbackDays             = $LookbackDays
                LongRunningHours         = $LongRunningHours
                BusinessHoursStart       = $BusinessHoursStart
                BusinessHoursEnd         = $BusinessHoursEnd
                BusinessDays             = $BusinessDays
                IncludeBrowserAiSessions = [bool]$IncludeBrowserAiSessions
                CheckSignatures          = [bool]$CheckSignatures
                MaxEventsPerLog          = $MaxEventsPerLog
                PersistentMinutes        = 10
                OffHoursMinEvents        = 3
                CrossAppMinCategories    = 3
            }
            Processes       = @()
            ProcessById     = $null
            ProcessProfiles = @{}
            TcpConnections  = @()
            TcpSamples      = @()
            DnsCache        = @()
            SeenPaths       = @{}
            BehaviorSignals = [pscustomobject]@{
                PackageInstalls = New-Object System.Collections.Generic.List[object]
                SelfMod         = New-Object System.Collections.Generic.List[object]
            }
        }

        # ---- Shared raw data ---------------------------------------------------------------
        if ($Category -contains 'Processes' -or $Category -contains 'Network') {
            Write-RacLog -Level ACTION -Message 'Reading the process table'
            $context.Processes = @(Get-RacRawProcess)
        }
        if ($Category -contains 'Network') {
            Write-RacLog -Level ACTION -Message 'Reading the DNS client cache'
            $context.DnsCache = @(Get-RacRawDnsCache)
            $samples = @()
            for ($i = 1; $i -le $NetworkSamples; $i++) {
                Write-RacLog -Level ACTION -Message ("Reading the TCP table (sample {0} of {1})" -f $i, $NetworkSamples)
                $samples += , @(Get-RacRawTcpConnection)
                if ($i -lt $NetworkSamples) { Start-Sleep -Seconds $SampleIntervalSeconds }
            }
            $context.TcpSamples = $samples
            $context.TcpConnections = $samples[-1]
        }

        # ---- Analyzers (one per category; a failure in one never stops the others) ----------
        $findings = New-Object System.Collections.Generic.List[object]
        $analyzers = [ordered]@{
            'Processes'        = 'Find-RacProcessFinding'
            'Network'          = 'Find-RacNetworkFinding'
            'ConfigAndSecrets' = 'Find-RacConfigFinding'
            'Persistence'      = 'Find-RacPersistenceFinding'
            'TokensAndOAuth'   = 'Find-RacTokenFinding'
            'LogsAndEvents'    = 'Find-RacLogFinding'
        }
        foreach ($name in $analyzers.Keys) {
            if ($Category -notcontains $name) {
                Add-RacCoverage -Source ('Category: ' + $name) -Status 'Skipped' -Detail 'Not selected with -Category.'
                continue
            }
            Write-RacLog -Level ACTION -Message ('Analyzing category ' + $name)
            try {
                foreach ($f in @(& $analyzers[$name] -Context $context)) {
                    if ($f) { $findings.Add($f) }
                }
            }
            catch {
                Write-RacLog -Level ERROR -Message ('Category {0} failed: {1} (line {2})' -f $name, $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber)
                Add-RacCoverage -Source ('Category: ' + $name) -Status 'Error' -Detail $_.Exception.Message
            }
        }
        if ($Category -contains 'Behavior') {
            Write-RacLog -Level ACTION -Message 'Analyzing category Behavior'
            try {
                foreach ($f in @(Find-RacBehaviorFinding -Context $context -Findings $findings.ToArray())) {
                    if ($f) { $findings.Add($f) }
                }
            }
            catch {
                Write-RacLog -Level ERROR -Message ('Category Behavior failed: ' + $_.Exception.Message)
                Add-RacCoverage -Source 'Category: Behavior' -Status 'Error' -Detail $_.Exception.Message
            }
        }

        # ---- Classify, sort (most severe first), and number the findings ---------------------
        Write-RacLog -Level ACTION -Message ('Classifying {0} finding(s)' -f $findings.Count)
        Invoke-RacClassification -Findings $findings.ToArray() -AllowList $allowList -Signatures $signatures -ComputerName $computer -Now $startTime
        $sorted = @($findings.ToArray() | Sort-Object @{ Expression = { Get-RacClassRank $_.Classification } }, @{ Expression = { $_.Score }; Descending = $true }, Category, Agent)
        $idMap = @{}
        $n = 0
        foreach ($f in $sorted) {
            $n++
            $newId = 'RAC-{0:D4}' -f $n
            $idMap[$f.FindingId] = $newId
            $f.FindingId = $newId
            Write-RacLog -Level FINDING -Message ('{0} {1} score={2} [{3}/{4}] {5}: {6}' -f $f.FindingId, $f.Classification, $f.Score, $f.Category, $f.Breadcrumb, $f.Agent, $f.Title)
        }
        # Behavior findings cross-reference other findings by ID; translate to the new numbers.
        foreach ($f in $sorted) {
            if ($f.Evidence.Contains('Related findings')) {
                $translated = @(([string]$f.Evidence['Related findings']) -split ',\s*' | ForEach-Object { if ($idMap.ContainsKey($_)) { $idMap[$_] } else { $_ } } | Sort-Object)
                $f.Evidence['Related findings'] = $translated -join ', '
            }
        }

        $summary = [pscustomobject]@{
            Total      = $sorted.Count
            Suspicious = @($sorted | Where-Object { $_.Classification -eq 'Suspicious' }).Count
            Unknown    = @($sorted | Where-Object { $_.Classification -eq 'Unknown' }).Count
            Trusted    = @($sorted | Where-Object { $_.Classification -eq 'Trusted' }).Count
            Agents     = @($sorted | ForEach-Object { $_.Agent } | Select-Object -Unique).Count
        }

        $result = [pscustomobject]@{
            ScanId              = $context.ScanId
            ToolVersion         = $script:RacVersion
            ComputerName        = $computer
            StartTime           = $startTime
            EndTime             = (Get-Date)
            RunAs               = $runAs
            Elevated            = $elevated
            PowerShellVersion   = [string]$PSVersionTable.PSVersion
            OperatingSystem     = (Get-RacOsDescription)
            Parameters          = [ordered]@{
                Category = ($Category -join ','); LookbackDays = $LookbackDays; BusinessHours = ('{0}-{1}' -f $BusinessHoursStart, $BusinessHoursEnd)
                BusinessDays = ($BusinessDays -join ','); NetworkSamples = $NetworkSamples; IncludeBrowserAiSessions = [bool]$IncludeBrowserAiSessions
                CheckSignatures = [bool]$CheckSignatures; ProfileRoot = (@($ProfileRoot) -join ';'); SearchRoot = (@($SearchRoot) -join ';'); ProxyLogPath = (@($ProxyLogPath) -join ';')
            }
            SignatureFile       = $SignaturePath
            SignatureVersion    = [string]$signatures.catalogVersion
            SignatureSha256     = [string]$signatures._Sha256
            AllowListFile       = $(if ($allowList) { $allowList.Path } else { '' })
            AllowListSha256     = $(if ($allowList) { $allowList.Sha256 } else { '' })
            AllowListEntryCount = $(if ($allowList) { @($allowList.Entries).Count } else { 0 })
            AllowListWarnings   = $(if ($allowList) { @($allowList.Warnings) } else { @() })
            Threshold           = [int]$signatures.scoring.suspiciousThreshold
            Summary             = $summary
            Coverage            = @()
            Findings            = $sorted
            ReportFiles         = [ordered]@{ Log = $logPath }
        }

        Write-RacLog -Level ACTION -Message ('Scan finished: {0} finding(s): {1} suspicious, {2} unknown, {3} trusted.' -f $summary.Total, $summary.Suspicious, $summary.Unknown, $summary.Trusted)

        if (-not $NoReport) {
            $result.Coverage = @(Get-RacCoverage)
            $null = Export-RacReport -ScanResult $result -OutputPath $OutputPath -BaseName $baseName
        }
        $result.Coverage = @(Get-RacCoverage)

        # ---- Console summary --------------------------------------------------------------
        Write-Host ''
        Write-Host ('Rogue Agent Checker - {0}' -f $computer)
        Write-Host ('  Suspicious : {0}' -f $summary.Suspicious) -ForegroundColor $(if ($summary.Suspicious -gt 0) { 'Red' } else { 'Gray' })
        Write-Host ('  Unknown    : {0}' -f $summary.Unknown) -ForegroundColor $(if ($summary.Unknown -gt 0) { 'Yellow' } else { 'Gray' })
        Write-Host ('  Trusted    : {0}' -f $summary.Trusted) -ForegroundColor 'Green'
        foreach ($k in $result.ReportFiles.Keys) { Write-Host ('  {0,-11}: {1}' -f $k, $result.ReportFiles[$k]) }
        Write-Host ''

        if ($PassThru) { return $result }
    }
    finally {
        Stop-RacScanLog
    }
}
