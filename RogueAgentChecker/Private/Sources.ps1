<#
    Sources.ps1 - EVERY operating-system read that Rogue Agent Checker performs.

    If you want to know what this tool touches on a machine, this is the only
    file you need to read. The rules for this file:

      * READ-ONLY.  Nothing here changes system state. Registry keys are opened
        for reading, files are opened with FileAccess.Read, WMI is queried, never
        written. The one WMI method used is Win32_Process.GetOwner (a read).
      * LOCAL-ONLY. Nothing here uses the network: no web requests, no DNS
        lookups, no reverse lookups, no SID-to-name translation.
      * STABLE SHAPES. Each function returns plain objects with fixed property
        names. Pester tests replace these functions with fakes (see
        Tests/Fixtures/FakeSystem.ps1) to replay a fake machine.
      * NEVER FATAL. A source that fails records a coverage row explaining why
        and returns nothing; the scan carries on.
#>

# ---------------------------------------------------------------------------
# Platform and identity
# ---------------------------------------------------------------------------

function Test-RacIsWindows {
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    $isWin = Get-Variable -Name 'IsWindows' -ValueOnly -ErrorAction SilentlyContinue
    return [bool]$isWin
}

function Get-RacIsElevated {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-RacCurrentIdentity {
    try { return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { Write-Verbose ('WindowsIdentity unavailable, using environment variables: ' + $_.Exception.Message) }
    if ($env:USERDOMAIN -and $env:USERNAME) { return ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME) }
    if ($env:USERNAME) { return $env:USERNAME }
    if ($env:USER) { return $env:USER }
    return 'unknown'
}

function Get-RacComputerName {
    if ($env:COMPUTERNAME) { return $env:COMPUTERNAME }
    return [System.Environment]::MachineName
}

function Get-RacOsDescription {
    try { return [System.Runtime.InteropServices.RuntimeInformation]::OSDescription } catch { Write-Verbose ('RuntimeInformation unavailable (older .NET): ' + $_.Exception.Message) }
    return [System.Environment]::OSVersion.VersionString
}

# ---------------------------------------------------------------------------
# User profiles
# ---------------------------------------------------------------------------

function Get-RacProfileRoot {
    <#
        Returns one object per local user profile: User (folder name), Path,
        Readable. The user name is taken from the folder name on purpose:
        translating SIDs to names can query a domain controller.
    #>
    $roots = @()
    try {
        $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            if (-not $p.Special -and $p.LocalPath) { $roots += [string]$p.LocalPath }
        }
    }
    catch {
        Write-RacLog -Level WARN -Message ('Win32_UserProfile unavailable, falling back to the Users folder: ' + $_.Exception.Message)
        if ($env:SystemDrive) {
            $usersDir = $env:SystemDrive + '\Users'
            foreach ($d in @(Get-ChildItem -LiteralPath $usersDir -Directory -Force -ErrorAction SilentlyContinue)) {
                if (@('Public', 'Default', 'Default User', 'All Users') -notcontains $d.Name) { $roots += $d.FullName }
            }
        }
    }

    $result = @()
    foreach ($r in ($roots | Sort-Object -Unique)) {
        $readable = $true
        try { $null = Get-ChildItem -LiteralPath $r -Force -ErrorAction Stop | Select-Object -First 1 }
        catch { $readable = $false }
        $result += [pscustomobject]@{ User = (Split-Path -Leaf $r); Path = $r; Readable = $readable }
    }

    $unreadable = @($result | Where-Object { -not $_.Readable })
    if ($unreadable.Count -gt 0) {
        Add-RacCoverage -Source 'User profiles' -Status 'Partial' -ItemCount $result.Count -Detail ('Not readable without elevation: ' + (($unreadable | ForEach-Object { $_.User }) -join ', '))
    }
    else {
        Add-RacCoverage -Source 'User profiles' -Status 'Checked' -ItemCount $result.Count
    }
    return $result
}

# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------

function Get-RacRawProcess {
    <# Win32_Process: name, path, command line, parent, start time. #>
    try {
        $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    }
    catch {
        Add-RacCoverage -Source 'Processes (Win32_Process)' -Status 'Error' -Detail $_.Exception.Message
        return
    }

    $out = foreach ($p in $procs) {
        [pscustomobject]@{
            ProcessId       = [int]$p.ProcessId
            ParentProcessId = [int]$p.ParentProcessId
            Name            = [string]$p.Name
            ExecutablePath  = [string]$p.ExecutablePath
            CommandLine     = [string]$p.CommandLine
            CreationDate    = $p.CreationDate
            Owner           = $null
        }
    }

    $hidden = @($out | Where-Object { -not $_.CommandLine -and $_.ProcessId -gt 4 }).Count
    if ($hidden -gt 0 -and -not (Get-RacIsElevated)) {
        Add-RacCoverage -Source 'Processes (Win32_Process)' -Status 'Partial' -ItemCount @($out).Count -Detail "$hidden processes had no visible command line (other users' or protected processes). Run elevated to see them."
    }
    else {
        Add-RacCoverage -Source 'Processes (Win32_Process)' -Status 'Checked' -ItemCount @($out).Count
    }
    return $out
}

function Get-RacProcessOwner {
    <# Owner of one process via Win32_Process.GetOwner (a read-only WMI method). #>
    param([int]$ProcessId)
    try {
        $proc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
        if (-not $proc) { return '' }
        $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction Stop
        if ($owner.ReturnValue -eq 0 -and $owner.User) {
            if ($owner.Domain) { return ('{0}\{1}' -f $owner.Domain, $owner.User) }
            return [string]$owner.User
        }
    }
    catch { Write-Verbose ('Owner lookup failed for PID ' + $ProcessId + ': ' + $_.Exception.Message) }
    return ''
}

function Get-RacFileSignature {
    <#
        Authenticode signer of a file. Only called with -CheckSignatures, because
        Windows may contact the certificate authority to check revocation.
    #>
    param([string]$Path)
    if (-not $Path) { return $null }
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) { return $null }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $signer = ''
        if ($sig.SignerCertificate) { $signer = [string]$sig.SignerCertificate.Subject }
        return [pscustomobject]@{ Status = [string]$sig.Status; Signer = $signer }
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

function Get-RacRawTcpConnection {
    <# TCP table with owning PID. Falls back to netstat (ships with Windows). #>
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try {
            $conns = @(Get-NetTCPConnection -ErrorAction Stop)
            $out = foreach ($c in $conns) {
                [pscustomobject]@{
                    LocalAddress  = [string]$c.LocalAddress
                    LocalPort     = [int]$c.LocalPort
                    RemoteAddress = [string]$c.RemoteAddress
                    RemotePort    = [int]$c.RemotePort
                    State         = [string]$c.State
                    OwningProcess = [int]$c.OwningProcess
                    CreationTime  = $c.CreationTime
                }
            }
            Add-RacCoverage -Source 'TCP connections (Get-NetTCPConnection)' -Status 'Checked' -ItemCount @($out).Count
            return $out
        }
        catch {
            Write-RacLog -Level WARN -Message ('Get-NetTCPConnection failed, trying netstat: ' + $_.Exception.Message)
        }
    }

    try {
        $lines = @(& netstat.exe -ano 2>$null)
    }
    catch {
        Add-RacCoverage -Source 'TCP connections' -Status 'Error' -Detail ('Neither Get-NetTCPConnection nor netstat is available: ' + $_.Exception.Message)
        return
    }
    $stateMap = @{ 'LISTENING' = 'Listen'; 'ESTABLISHED' = 'Established'; 'TIME_WAIT' = 'TimeWait'; 'CLOSE_WAIT' = 'CloseWait'; 'SYN_SENT' = 'SynSent' }
    $out = foreach ($line in $lines) {
        if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)\s*$') {
            $state = $Matches[5]
            if ($stateMap.ContainsKey($state)) { $state = $stateMap[$state] }
            [pscustomobject]@{
                LocalAddress  = $Matches[1].Trim('[', ']')
                LocalPort     = [int]$Matches[2]
                RemoteAddress = $Matches[3].Trim('[', ']')
                RemotePort    = [int]$Matches[4]
                State         = $state
                OwningProcess = [int]$Matches[6]
                CreationTime  = $null
            }
        }
    }
    Add-RacCoverage -Source 'TCP connections (netstat fallback)' -Status 'Partial' -ItemCount @($out).Count -Detail 'netstat does not report connection age, so long-lived connections cannot be measured.'
    return $out
}

function Get-RacRawDnsCache {
    <#
        Local DNS client cache. This is how remote IPs are mapped to hostnames:
        no lookups are made. Entries expire with their TTL.
    #>
    if (-not (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        Add-RacCoverage -Source 'DNS client cache' -Status 'Skipped' -Detail 'Get-DnsClientCache is not available on this system.'
        return
    }
    try {
        $entries = @(Get-DnsClientCache -ErrorAction Stop)
    }
    catch {
        Add-RacCoverage -Source 'DNS client cache' -Status 'Error' -Detail $_.Exception.Message
        return
    }
    $out = foreach ($e in $entries) {
        [pscustomobject]@{
            Entry      = [string]$e.Entry
            Name       = [string]$e.Name
            Type       = [string]$e.Type
            Data       = [string]$e.Data
            TimeToLive = [int]$e.TimeToLive
        }
    }
    Add-RacCoverage -Source 'DNS client cache' -Status 'Checked' -ItemCount @($out).Count -Detail 'Only recent lookups are present; entries expire with their TTL.'
    return $out
}

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

function Get-RacRawScheduledTask {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Add-RacCoverage -Source 'Scheduled tasks' -Status 'Skipped' -Detail 'ScheduledTasks module is not available.'
        return
    }
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    }
    catch {
        Add-RacCoverage -Source 'Scheduled tasks' -Status 'Error' -Detail $_.Exception.Message
        return
    }

    $out = foreach ($t in $tasks) {
        $actions = foreach ($a in @($t.Actions)) {
            if (-not $a) { continue }
            $execute = ''
            $arguments = ''
            $workingDir = ''
            if ($a.PSObject.Properties['Execute']) {
                $execute = [string]$a.Execute
                $arguments = [string]$a.Arguments
                $workingDir = [string]$a.WorkingDirectory
            }
            elseif ($a.PSObject.Properties['ClassId']) {
                $execute = 'COM handler ' + [string]$a.ClassId
                $arguments = [string]$a.Data
            }
            [pscustomobject]@{ Execute = $execute; Arguments = $arguments; WorkingDirectory = $workingDir }
        }
        $triggers = @()
        foreach ($tr in @($t.Triggers)) {
            if ($tr -and $tr.CimClass) { $triggers += ($tr.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Trigger$', '') }
        }
        $hidden = $false
        if ($t.Settings -and $t.Settings.PSObject.Properties['Hidden']) { $hidden = [bool]$t.Settings.Hidden }
        $userId = ''
        $runLevel = ''
        if ($t.Principal) { $userId = [string]$t.Principal.UserId; $runLevel = [string]$t.Principal.RunLevel }

        [pscustomobject]@{
            TaskPath         = [string]$t.TaskPath
            TaskName         = [string]$t.TaskName
            State            = [string]$t.State
            Author           = [string]$t.Author
            Description      = [string]$t.Description
            UserId           = $userId
            RunLevel         = $runLevel
            Hidden           = $hidden
            Actions          = @($actions)
            Triggers         = $triggers
            RegistrationDate = [string]$t.Date
        }
    }

    if (Get-RacIsElevated) {
        Add-RacCoverage -Source 'Scheduled tasks' -Status 'Checked' -ItemCount @($out).Count
    }
    else {
        Add-RacCoverage -Source 'Scheduled tasks' -Status 'Partial' -ItemCount @($out).Count -Detail 'Tasks registered by other users may be hidden from a non-elevated session.'
    }
    return $out
}

function Get-RacScheduledTaskRunInfo {
    <# Last/next run time for ONE task (only called for tasks that matched). #>
    param([string]$TaskPath, [string]$TaskName)
    if (-not (Get-Command Get-ScheduledTaskInfo -ErrorAction SilentlyContinue)) { return $null }
    try {
        $info = Get-ScheduledTaskInfo -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
        return [pscustomobject]@{ LastRunTime = $info.LastRunTime; NextRunTime = $info.NextRunTime; LastTaskResult = $info.LastTaskResult }
    }
    catch {
        return $null
    }
}

function Get-RacRawService {
    try {
        $svcs = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    }
    catch {
        Add-RacCoverage -Source 'Services (Win32_Service)' -Status 'Error' -Detail $_.Exception.Message
        return
    }
    $out = foreach ($s in $svcs) {
        [pscustomobject]@{
            Name        = [string]$s.Name
            DisplayName = [string]$s.DisplayName
            PathName    = [string]$s.PathName
            StartMode   = [string]$s.StartMode
            State       = [string]$s.State
            StartName   = [string]$s.StartName
            ProcessId   = [int]$s.ProcessId
        }
    }
    Add-RacCoverage -Source 'Services (Win32_Service)' -Status 'Checked' -ItemCount @($out).Count
    return $out
}

function Read-RacRegistryValue {
    <#
        Reads the values of ONE registry key. With -NamesOnly the values are never
        touched, which is how environment variables are inventoried.
    #>
    param([string]$Path, [switch]$NamesOnly)
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        return
    }
    foreach ($name in $key.GetValueNames()) {
        if ($NamesOnly) {
            [pscustomobject]@{ Name = $name; Value = $null }
        }
        else {
            [pscustomobject]@{ Name = $name; Value = [string]$key.GetValue($name) }
        }
    }
}

function Get-RacLoadedUserHive {
    <#
        Registry hives of users who are currently loaded (logged on or running
        something). RAC never loads offline hives: 'reg load' is a write.
        The user name comes from the hive's own Volatile Environment key.
    #>
    $result = @()
    try {
        $sids = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop | ForEach-Object { $_.PSChildName })
    }
    catch {
        return $result
    }
    foreach ($sid in $sids) {
        if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -and $sid -notmatch '^S-1-12-1-\d+-\d+-\d+-\d+$') { continue }
        $root = 'Registry::HKEY_USERS\' + $sid
        $user = $sid
        try {
            $ve = Get-Item -LiteralPath ($root + '\Volatile Environment') -ErrorAction Stop
            $name = [string]$ve.GetValue('USERNAME')
            $domain = [string]$ve.GetValue('USERDOMAIN')
            if ($name -and $domain) { $user = $domain + '\' + $name }
            elseif ($name) { $user = $name }
        }
        catch { Write-Verbose ('No Volatile Environment for ' + $sid + '; showing the SID instead.') }
        $result += [pscustomobject]@{ Sid = $sid; User = $user; Root = $root }
    }
    return $result
}

function Get-RacRawRunKey {
    <# Run / RunOnce / Policies Run values from HKLM and every loaded user hive. #>
    $machineKeys = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    $userKeys = @(
        'Software\Microsoft\Windows\CurrentVersion\Run',
        'Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )

    $targets = @()
    foreach ($k in $machineKeys) { $targets += [pscustomobject]@{ Hive = 'HKLM'; User = ''; Path = 'Registry::HKEY_LOCAL_MACHINE\' + $k } }
    $hives = @(Get-RacLoadedUserHive)
    foreach ($h in $hives) {
        foreach ($k in $userKeys) { $targets += [pscustomobject]@{ Hive = 'HKU\' + $h.Sid; User = $h.User; Path = $h.Root + '\' + $k } }
    }

    $out = foreach ($t in $targets) {
        foreach ($v in @(Read-RacRegistryValue -Path $t.Path)) {
            [pscustomobject]@{
                Hive      = $t.Hive
                User      = $t.User
                KeyPath   = ($t.Path -replace '^Registry::', '')
                ValueName = $v.Name
                Command   = $v.Value
            }
        }
    }
    Add-RacCoverage -Source 'Run / RunOnce registry keys' -Status 'Checked' -ItemCount @($out).Count -Detail ("HKLM plus {0} loaded user hive(s). Users who are not logged on are not covered (their hives are not loaded, and RAC never loads them)." -f $hives.Count)
    return $out
}

function Get-RacRawStartupItem {
    <#
        Startup-folder entries for each profile plus the all-users folder.
        Shortcuts are resolved with WScript.Shell. CreateShortcut() on an existing
        .lnk only READS it; nothing is written because .Save() is never called.
    #>
    param([object[]]$ProfileRoot)

    $folders = @()
    foreach ($p in $ProfileRoot) {
        $path = Expand-RacPathTemplate -Template '%APPDATA%/Microsoft/Windows/Start Menu/Programs/Startup' -ProfileRoot $p.Path
        if ($path) { $folders += [pscustomobject]@{ User = $p.User; Path = $path } }
    }
    if ($env:ProgramData) {
        $folders += [pscustomobject]@{ User = ''; Path = [System.IO.Path]::Combine($env:ProgramData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp') }
    }

    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop } catch { Write-RacLog -Level SKIP -Message ('WScript.Shell unavailable; startup shortcut targets will show the .lnk path only: ' + $_.Exception.Message) }

    $out = foreach ($f in $folders) {
        if (-not (Test-Path -LiteralPath $f.Path)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $f.Path -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.Name -eq 'desktop.ini') { continue }
            $target = $file.FullName
            $arguments = ''
            if ($file.Extension -eq '.lnk' -and $shell) {
                try {
                    $lnk = $shell.CreateShortcut($file.FullName)
                    $target = [string]$lnk.TargetPath
                    $arguments = [string]$lnk.Arguments
                }
                catch { Write-RacLog -Level WARN -Message ('Could not read shortcut ' + $file.FullName + ': ' + $_.Exception.Message) }
            }
            [pscustomobject]@{
                User          = $f.User
                Path          = $file.FullName
                TargetPath    = $target
                Arguments     = $arguments
                LastWriteTime = $file.LastWriteTime
            }
        }
    }
    Add-RacCoverage -Source 'Startup folders' -Status 'Checked' -ItemCount @($out).Count -Detail ('{0} folder(s) examined.' -f $folders.Count)
    return $out
}

function Get-RacRawWmiSubscription {
    <# Permanent WMI event subscriptions (root\subscription): consumers + their filters. #>
    try {
        $consumers = @(Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventConsumer' -ErrorAction Stop)
        $filters = @(Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventFilter' -ErrorAction Stop)
        $bindings = @(Get-CimInstance -Namespace 'root/subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop)
    }
    catch {
        $detail = $_.Exception.Message
        if ($detail -match 'denied') { $detail = 'Access denied. Run elevated to inspect WMI event subscriptions.' }
        Add-RacCoverage -Source 'WMI event subscriptions' -Status 'Skipped' -Detail $detail
        return
    }

    $out = foreach ($c in $consumers) {
        $className = [string]$c.CimClass.CimClassName
        $filterName = ''
        $query = ''
        $binding = $bindings | Where-Object { $_.Consumer -and $_.Consumer.Name -eq $c.Name } | Select-Object -First 1
        if ($binding -and $binding.Filter) {
            $filterName = [string]$binding.Filter.Name
            $f = $filters | Where-Object { $_.Name -eq $filterName } | Select-Object -First 1
            if ($f) { $query = [string]$f.Query }
        }
        $commandLine = ''
        if ($c.PSObject.Properties['CommandLineTemplate']) { $commandLine = [string]$c.CommandLineTemplate }
        if (-not $commandLine -and $c.PSObject.Properties['ExecutablePath']) { $commandLine = [string]$c.ExecutablePath }
        $scriptText = ''
        if ($c.PSObject.Properties['ScriptText']) { $scriptText = [string]$c.ScriptText }
        if (-not $scriptText -and $c.PSObject.Properties['ScriptFileName'] -and $c.ScriptFileName) { $scriptText = 'file: ' + [string]$c.ScriptFileName }

        [pscustomobject]@{
            Name        = [string]$c.Name
            ClassName   = $className
            CommandLine = $commandLine
            ScriptText  = $scriptText
            FilterName  = $filterName
            FilterQuery = $query
        }
    }
    Add-RacCoverage -Source 'WMI event subscriptions' -Status 'Checked' -ItemCount @($out).Count
    return $out
}

# ---------------------------------------------------------------------------
# Environment variables, Credential Manager, browser native messaging hosts
# ---------------------------------------------------------------------------

function Get-RacRawEnvironmentVariable {
    <#
        Environment variable NAMES at machine scope and for each loaded user hive.
        Values are never read (GetValueNames only).
    #>
    $out = @()
    foreach ($v in @(Read-RacRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -NamesOnly)) {
        $out += [pscustomobject]@{ Scope = 'Machine'; User = ''; Name = $v.Name }
    }
    foreach ($h in @(Get-RacLoadedUserHive)) {
        foreach ($v in @(Read-RacRegistryValue -Path ($h.Root + '\Environment') -NamesOnly)) {
            $out += [pscustomobject]@{ Scope = 'User'; User = $h.User; Name = $v.Name }
        }
    }
    Add-RacCoverage -Source 'Environment variables (names only)' -Status 'Checked' -ItemCount $out.Count -Detail 'Machine scope plus loaded user hives. Values are never read.'
    return $out
}

function Get-RacRawCredentialTarget {
    <#
        Windows Credential Manager target NAMES for the current user, via
        cmdkey /list. cmdkey cannot display stored secrets.
    #>
    if (-not (Get-Command cmdkey.exe -ErrorAction SilentlyContinue)) {
        Add-RacCoverage -Source 'Credential Manager (cmdkey)' -Status 'Skipped' -Detail 'cmdkey.exe is not available.'
        return
    }
    try {
        $lines = @(& cmdkey.exe /list 2>$null)
    }
    catch {
        Add-RacCoverage -Source 'Credential Manager (cmdkey)' -Status 'Error' -Detail $_.Exception.Message
        return
    }
    $out = foreach ($line in $lines) {
        if ($line -match 'target=(.+?)\s*$') { [pscustomobject]@{ Target = $Matches[1] } }
    }
    Add-RacCoverage -Source 'Credential Manager (cmdkey)' -Status 'Partial' -ItemCount @($out).Count -Detail 'Target names for the CURRENT user only; other users need their own scan session.'
    return $out
}

function Get-RacRawNativeMessagingHost {
    <# Browser native messaging hosts: local programs a browser extension can talk to. #>
    $browserKeys = [ordered]@{
        'Chrome'   = 'Google\Chrome\NativeMessagingHosts'
        'Edge'     = 'Microsoft\Edge\NativeMessagingHosts'
        'Brave'    = 'BraveSoftware\Brave-Browser\NativeMessagingHosts'
        'Chromium' = 'Chromium\NativeMessagingHosts'
        'Firefox'  = 'Mozilla\NativeMessagingHosts'
    }
    $roots = @(
        [pscustomobject]@{ Scope = 'Machine'; User = ''; Prefix = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\' },
        [pscustomobject]@{ Scope = 'Machine (32-bit)'; User = ''; Prefix = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\' }
    )
    foreach ($h in @(Get-RacLoadedUserHive)) {
        $roots += [pscustomobject]@{ Scope = 'User'; User = $h.User; Prefix = $h.Root + '\Software\' }
    }

    $out = foreach ($r in $roots) {
        foreach ($browser in $browserKeys.Keys) {
            $path = $r.Prefix + $browserKeys[$browser]
            $keys = @()
            try { $keys = @(Get-ChildItem -LiteralPath $path -ErrorAction Stop) } catch { continue }
            foreach ($k in $keys) {
                [pscustomobject]@{
                    Browser      = $browser
                    Scope        = $r.Scope
                    User         = $r.User
                    HostName     = [string]$k.PSChildName
                    ManifestPath = [string]$k.GetValue('')
                }
            }
        }
    }
    Add-RacCoverage -Source 'Browser native messaging hosts' -Status 'Checked' -ItemCount @($out).Count
    return $out
}

# ---------------------------------------------------------------------------
# Event logs
# ---------------------------------------------------------------------------

function Get-RacRawWinEvent {
    <#
        Events from one log, newest first, capped at MaxEvents. Each event's
        EventData is flattened into a Data hashtable (Name -> value).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [int[]]$Id,
        [datetime]$StartTime,
        [int]$MaxEvents = 5000
    )

    if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) {
        Add-RacCoverage -Source "Event log: $LogName" -Status 'Skipped' -Detail 'Get-WinEvent is not available on this system.'
        return
    }

    $filter = @{ LogName = $LogName }
    if ($Id) { $filter.Id = $Id }
    if ($StartTime) { $filter.StartTime = $StartTime }

    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch {
        $fqid = [string]$_.FullyQualifiedErrorId
        $message = $_.Exception.Message
        if ($fqid -match 'NoMatchingEventsFound') {
            Add-RacCoverage -Source "Event log: $LogName" -Status 'Checked' -ItemCount 0 -Detail ('Event IDs ' + ($Id -join ', '))
        }
        elseif ($fqid -match 'NoMatchingLogsFound' -or $message -match 'not an event log|could not be found') {
            Add-RacCoverage -Source "Event log: $LogName" -Status 'Skipped' -Detail 'Log not present on this machine (for Sysmon: Sysmon is not installed).'
        }
        elseif ($_.Exception -is [System.UnauthorizedAccessException] -or $message -match 'unauthorized|denied') {
            Add-RacCoverage -Source "Event log: $LogName" -Status 'Skipped' -Detail 'Access denied. Run elevated or add the account to Event Log Readers.'
        }
        else {
            Add-RacCoverage -Source "Event log: $LogName" -Status 'Error' -Detail $message
        }
        return
    }

    $out = foreach ($e in $events) {
        $data = @{}
        try {
            $xml = [xml]$e.ToXml()
            foreach ($d in @($xml.Event.EventData.Data)) {
                if ($d -and $d.Name) { $data[[string]$d.Name] = [string]$d.'#text' }
            }
        }
        catch { Write-Verbose ('Could not read EventData of record ' + $e.RecordId + ' in ' + $LogName + ': ' + $_.Exception.Message) }
        [pscustomobject]@{
            LogName     = $LogName
            Id          = [int]$e.Id
            TimeCreated = $e.TimeCreated
            RecordId    = $e.RecordId
            Data        = $data
        }
    }
    $detail = 'Event IDs ' + ($Id -join ', ')
    if (@($out).Count -ge $MaxEvents) { $detail += "; capped at $MaxEvents newest events (raise -MaxEventsPerLog to see more)" }
    Add-RacCoverage -Source "Event log: $LogName" -Status 'Checked' -ItemCount @($out).Count -Detail $detail
    return $out
}

# ---------------------------------------------------------------------------
# File system (all reads)
# ---------------------------------------------------------------------------

function ConvertTo-RacItemInfo {
    param($Item)
    if (-not $Item) { return $null }
    $isDir = [bool]$Item.PSIsContainer
    $length = 0
    if (-not $isDir) { $length = [long]$Item.Length }
    $attributes = [int]$Item.Attributes
    # 0x400000 = RECALL_ON_DATA_ACCESS (cloud placeholder), 0x1000 = OFFLINE
    $placeholder = (($attributes -band 0x400000) -ne 0) -or (($attributes -band 0x1000) -ne 0)
    [pscustomobject]@{
        FullName           = [string]$Item.FullName
        Name               = [string]$Item.Name
        IsDirectory        = $isDir
        Length             = $length
        LastWriteTime      = $Item.LastWriteTime
        CreationTime       = $Item.CreationTime
        IsReparsePoint     = (($attributes -band 0x400) -ne 0)
        IsCloudPlaceholder = $placeholder
    }
}

function Test-RacPath {
    <# Test-Path that accepts wildcards and never throws. #>
    param([AllowEmptyString()][AllowNull()][string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $false }
    try { return [bool](Test-Path -Path $Path -ErrorAction SilentlyContinue) } catch { return $false }
}

function Resolve-RacPath {
    <# Expands wildcards in a path and returns the full names of what exists. #>
    param([AllowEmptyString()][AllowNull()][string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return }
    foreach ($item in @(Get-Item -Path $Path -Force -ErrorAction SilentlyContinue)) {
        if ($item) { [string]$item.FullName }
    }
}

function Get-RacItemInfo {
    param([string]$Path)
    try { return (ConvertTo-RacItemInfo (Get-Item -LiteralPath $Path -Force -ErrorAction Stop)) } catch { return $null }
}

function Get-RacChildItem {
    <# Directory listing with caps. Returns item-info objects, never file contents. #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Filter,
        [switch]$Recurse,
        [int]$Depth = -1,
        [switch]$File,
        [switch]$Directory,
        [int]$MaxItems = 5000
    )
    $params = @{ LiteralPath = $Path; Force = $true; ErrorAction = 'SilentlyContinue' }
    if ($Filter) { $params.Filter = $Filter }
    if ($Recurse) {
        $params.Recurse = $true
        if ($Depth -ge 0) { $params.Depth = $Depth }
    }
    if ($File) { $params.File = $true }
    if ($Directory) { $params.Directory = $true }
    Get-ChildItem @params | Select-Object -First $MaxItems | ForEach-Object { ConvertTo-RacItemInfo $_ }
}

function Open-RacReadOnlyStream {
    <#
        Opens a file strictly for reading. FileShare ReadWrite+Delete lets us read
        logs that an agent is still writing without ever blocking it.
    #>
    param([string]$Path)
    return New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
}

function Read-RacTextFile {
    <#
        Reads a whole text file (capped). Cloud-only placeholders (OneDrive
        Files On-Demand) are skipped, because reading them triggers a download.
    #>
    param([string]$Path, [long]$MaxBytes = 2MB)

    $info = Get-RacItemInfo -Path $Path
    if (-not $info -or $info.IsDirectory) { return $null }
    if ($info.Length -gt $MaxBytes) {
        Write-RacLog -Level SKIP -Message ("Not read (larger than {0:N0} bytes): {1}" -f $MaxBytes, $Path)
        return $null
    }
    if ($info.IsCloudPlaceholder) {
        Write-RacLog -Level SKIP -Message "Not read (cloud-only placeholder; reading would trigger a download): $Path"
        return $null
    }

    $stream = $null
    $reader = $null
    try {
        $stream = Open-RacReadOnlyStream -Path $info.FullName
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true)
        return $reader.ReadToEnd()
    }
    catch {
        Write-RacLog -Level WARN -Message ("Could not read {0}: {1}" -f $Path, $_.Exception.Message)
        return $null
    }
    finally {
        if ($reader) { $reader.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }
}

function Measure-RacPatternInFile {
    <#
        Counts lines matching a regex. Returns ONLY the count (content is never
        kept). Returns -1 if the file is over the size cap, -2 if unreadable.
    #>
    param([string]$Path, [string]$Pattern, [long]$MaxBytes = 5MB)

    $info = Get-RacItemInfo -Path $Path
    if (-not $info -or $info.IsDirectory) { return -2 }
    if ($info.Length -gt $MaxBytes -or $info.IsCloudPlaceholder) { return -1 }

    $regex = New-Object System.Text.RegularExpressions.Regex($Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $count = 0
    $stream = $null
    $reader = $null
    try {
        $stream = Open-RacReadOnlyStream -Path $info.FullName
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true)
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($regex.IsMatch($line)) { $count++ }
        }
        return $count
    }
    catch {
        return -2
    }
    finally {
        if ($reader) { $reader.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }
}

function Get-RacRegexCaptureCount {
    <#
        Streams a (possibly huge) text file such as a proxy log and counts the
        values of capture group 1 of $Pattern. Returns counts only.
    #>
    param([string]$Path, [string]$Pattern, [int]$MaxLines = 2000000)

    $counts = @{}
    $linesRead = 0
    $regex = New-Object System.Text.RegularExpressions.Regex($Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $stream = $null
    $reader = $null
    try {
        $stream = Open-RacReadOnlyStream -Path $Path
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true)
        while ($linesRead -lt $MaxLines -and $null -ne ($line = $reader.ReadLine())) {
            $linesRead++
            foreach ($m in $regex.Matches($line)) {
                $key = $m.Groups[1].Value.ToLowerInvariant()
                $counts[$key] = 1 + [int]$counts[$key]
            }
        }
    }
    catch {
        Write-RacLog -Level WARN -Message ("Could not read {0}: {1}" -f $Path, $_.Exception.Message)
    }
    finally {
        if ($reader) { $reader.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }
    return [pscustomobject]@{ Counts = $counts; LinesRead = $linesRead; Truncated = ($linesRead -ge $MaxLines) }
}

function Find-RacFileByName {
    <#
        Breadth-first walk of a folder tree looking for files by name. Skips
        excluded folders (node_modules, .git, ...), never follows junctions or
        symlinks, and stops at MaxDepth / MaxDirectories.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string[]]$NamePattern,
        [string[]]$ExcludeDirectory = @(),
        [int]$MaxDepth = 4,
        [int]$MaxDirectories = 20000
    )

    $found = New-Object System.Collections.Generic.List[object]
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue([pscustomobject]@{ Path = $Root; Depth = 0 })
    $visited = 0

    while ($queue.Count -gt 0 -and $visited -lt $MaxDirectories) {
        $current = $queue.Dequeue()
        $visited++
        foreach ($child in @(Get-ChildItem -LiteralPath $current.Path -Force -ErrorAction SilentlyContinue)) {
            if ($child.PSIsContainer) {
                $isLink = (([int]$child.Attributes -band 0x400) -ne 0)
                if (-not $isLink -and $current.Depth -lt $MaxDepth -and ($ExcludeDirectory -notcontains $child.Name)) {
                    $queue.Enqueue([pscustomobject]@{ Path = $child.FullName; Depth = $current.Depth + 1 })
                }
            }
            else {
                foreach ($p in $NamePattern) {
                    if ($child.Name -like $p) { $found.Add((ConvertTo-RacItemInfo $child)); break }
                }
            }
        }
    }
    if ($visited -ge $MaxDirectories) {
        Write-RacLog -Level WARN -Message "Stopped walking $Root after $MaxDirectories folders (cap)."
    }
    return $found.ToArray()
}

function Get-RacFileAclSummary {
    <#
        Does a broad group (Everyone, Users, Authenticated Users, Guests) have read
        access to this file? Uses well-known SIDs, so it works on any language.
    #>
    param([string]$Path)
    if (-not (Get-Command Get-Acl -ErrorAction SilentlyContinue)) { return $null }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        $broad = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-32-545' = 'BUILTIN\Users'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-32-546' = 'BUILTIN\Guests' }
        $readData = [int][System.Security.AccessControl.FileSystemRights]::ReadData
        $hits = @()
        foreach ($r in $rules) {
            $sid = [string]$r.IdentityReference.Value
            if ($broad.ContainsKey($sid) -and [string]$r.AccessControlType -eq 'Allow' -and (([int]$r.FileSystemRights -band $readData) -ne 0)) {
                $hits += $broad[$sid]
            }
        }
        return [pscustomobject]@{ BroadRead = ($hits.Count -gt 0); Identities = @($hits | Select-Object -Unique) }
    }
    catch {
        return $null
    }
}

function Get-RacFileSha256 {
    <# SHA-256 of a policy file (signatures, allow-list), recorded in the report for audit. #>
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return '' }
}
