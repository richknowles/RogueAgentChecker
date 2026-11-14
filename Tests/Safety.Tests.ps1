#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.3.0' }
<#
    Safety tests: the promises in the README, checked mechanically.

      * Read-only ............ no command that changes system state appears in the module
      * Local-only ........... no network API appears in the module
      * Auditable ............ OS queries live in Sources.ps1 only; file writes only in
                               the logging and report code
      * Secrets stay secret .. fake keys planted in the fake machine never reach any output
      * Runs on 5.1 .......... ASCII-only source, and PSScriptAnalyzer's 5.1 checks pass

    These parse the code with PowerShell's own parser (AST), so comments and
    strings that merely MENTION a command do not count; only real calls do.
#>

BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
    $script:moduleDir = Split-Path -Parent $script:RacModuleManifest
    $script:codeFiles = @(Get-ChildItem -LiteralPath $script:moduleDir -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' })

    function Get-RacTestAst {
        param([string]$Path)
        $tokens = $null
        $errors = $null
        return [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    }

    function Get-RacTestCommandUse {
        <# Every command invoked in the module: @{ File; Name; Text } #>
        foreach ($file in $script:codeFiles) {
            $ast = Get-RacTestAst -Path $file.FullName
            foreach ($cmd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                [pscustomobject]@{ File = $file.Name; Name = [string]$cmd.GetCommandName(); Text = $cmd.Extent.Text }
            }
        }
    }
    $script:commandUse = @(Get-RacTestCommandUse)
}

Describe 'Read-only' {
    It 'contains no command that changes system state' {
        $forbidden = @(
            'Stop-Process', 'Remove-Item', 'Remove-ItemProperty', 'Set-ItemProperty', 'New-ItemProperty', 'Set-Item',
            'Rename-Item', 'Move-Item', 'Copy-Item', 'Clear-Content', 'Clear-Item', 'Clear-ItemProperty',
            'Stop-Service', 'Start-Service', 'Restart-Service', 'Set-Service', 'New-Service', 'Remove-Service', 'Suspend-Service',
            'Disable-ScheduledTask', 'Enable-ScheduledTask', 'Unregister-ScheduledTask', 'Register-ScheduledTask',
            'Set-ScheduledTask', 'Start-ScheduledTask', 'Stop-ScheduledTask',
            'Remove-CimInstance', 'Set-CimInstance', 'New-CimInstance', 'Remove-WmiObject', 'Set-WmiInstance', 'Invoke-WmiMethod',
            'Set-Acl', 'Start-Process', 'Invoke-Expression', 'iex', 'Add-Type', 'Set-ExecutionPolicy', 'Invoke-Item',
            'Restart-Computer', 'Stop-Computer', 'Clear-DnsClientCache', 'Clear-EventLog', 'Remove-EventLog', 'Limit-EventLog',
            'New-NetFirewallRule', 'Set-NetFirewallRule', 'Disable-NetAdapter', 'Set-DnsClientServerAddress', 'New-PSDrive',
            'reg', 'reg.exe', 'schtasks', 'schtasks.exe', 'sc', 'sc.exe', 'netsh', 'netsh.exe', 'wevtutil', 'wevtutil.exe',
            'taskkill', 'taskkill.exe', 'wmic', 'wmic.exe', 'icacls', 'icacls.exe', 'takeown', 'takeown.exe'
        )
        $hits = @($commandUse | Where-Object { $forbidden -contains $_.Name })
        $hits | ForEach-Object { "$($_.File): $($_.Text)" } | Should -BeNullOrEmpty
    }

    It 'uses Invoke-CimMethod only for the read-only Win32_Process.GetOwner method' {
        $calls = @($commandUse | Where-Object { $_.Name -eq 'Invoke-CimMethod' })
        $calls.Count | Should -BeGreaterThan 0
        foreach ($c in $calls) { $c.Text | Should -Match '-MethodName\s+GetOwner\b' }
    }

    It 'never calls a .NET method that saves, deletes or writes' {
        $denied = @('Save', 'Delete', 'DeleteValue', 'DeleteSubKey', 'DeleteSubKeyTree', 'SetValue', 'CreateSubKey', 'Kill', 'Put', 'Terminate', 'StopService', 'Create', 'WriteAllText', 'WriteAllBytes', 'AppendAllText')
        $hits = foreach ($file in $codeFiles) {
            $ast = Get-RacTestAst -Path $file.FullName
            foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
                $name = [string]$m.Member.Value
                if ($denied -contains $name) { "$($file.Name): $($m.Extent.Text)" }
            }
        }
        $hits | Should -BeNullOrEmpty
    }

    It 'opens files for reading only' {
        foreach ($file in $codeFiles) {
            $text = Get-Content -LiteralPath $file.FullName -Raw
            $text | Should -Not -Match 'FileAccess\]::(Write|ReadWrite)' -Because $file.Name
            $text | Should -Not -Match 'FileMode\]::(Create|CreateNew|Append|Truncate|OpenOrCreate)' -Because $file.Name
        }
    }

    It 'writes files only from the logging and report code' {
        $writers = @('Set-Content', 'Add-Content', 'New-Item', 'Out-File', 'Export-Csv', 'Export-Clixml', 'Tee-Object')
        $allowed = @('Core.ps1', 'Report.ps1', 'Export-RacReport.ps1')
        $hits = @($commandUse | Where-Object { $writers -contains $_.Name -and $allowed -notcontains $_.File })
        $hits | ForEach-Object { "$($_.File): $($_.Text)" } | Should -BeNullOrEmpty
    }
}

Describe 'Local-only' {
    It 'makes no network calls' {
        $netCommands = @(
            'Invoke-WebRequest', 'Invoke-RestMethod', 'iwr', 'irm', 'curl', 'curl.exe', 'wget', 'Resolve-DnsName',
            'Test-NetConnection', 'Test-Connection', 'Send-MailMessage', 'Start-BitsTransfer', 'nslookup', 'nslookup.exe',
            'ping', 'ping.exe', 'ssh', 'scp', 'ftp', 'certutil', 'certutil.exe', 'bitsadmin', 'bitsadmin.exe'
        )
        $hits = @($commandUse | Where-Object { $netCommands -contains $_.Name })
        $hits | ForEach-Object { "$($_.File): $($_.Text)" } | Should -BeNullOrEmpty
    }

    It 'references no .NET networking types' {
        $pattern = '^(System\.)?Net\.(WebClient|Http|Sockets|Dns|WebRequest|HttpWebRequest|FtpWebRequest|NetworkInformation|Mail)'
        $hits = foreach ($file in $codeFiles) {
            $ast = Get-RacTestAst -Path $file.FullName
            foreach ($t in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] -or $n -is [System.Management.Automation.Language.TypeConstraintAst] }, $true)) {
                if ($t.TypeName.FullName -match $pattern) { "$($file.Name): $($t.Extent.Text)" }
            }
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-Object' }, $true)) {
                if ($c.Extent.Text -match ('New-Object\s+(-TypeName\s+)?' + $pattern.TrimStart('^'))) { "$($file.Name): $($c.Extent.Text)" }
            }
        }
        $hits | Should -BeNullOrEmpty
    }
}

Describe 'Auditable' {
    It 'queries the operating system only from Sources.ps1' {
        $queries = @(
            'Get-CimInstance', 'Get-WmiObject', 'Get-NetTCPConnection', 'Get-DnsClientCache', 'Get-ScheduledTask', 'Get-ScheduledTaskInfo',
            'Get-WinEvent', 'Get-EventLog', 'Get-Acl', 'Get-ItemProperty', 'Get-AuthenticodeSignature', 'Get-Service', 'Get-Process',
            'Invoke-CimMethod', 'cmdkey', 'cmdkey.exe', 'netstat', 'netstat.exe', 'Get-FileHash', 'Get-Item', 'Get-ChildItem', 'Get-Content', 'Test-Path'
        )
        # Narrow, documented exceptions: the loader lists its own files; the log and
        # report writers check whether their OUTPUT folder exists.
        $exceptions = @{
            'Get-ChildItem' = @('RogueAgentChecker.psm1')
            'Test-Path'     = @('Core.ps1', 'Export-RacReport.ps1')
        }
        $hits = @($commandUse | Where-Object {
                $queries -contains $_.Name -and $_.File -ne 'Sources.ps1' -and -not ($exceptions.ContainsKey($_.Name) -and $exceptions[$_.Name] -contains $_.File)
            })
        $hits | ForEach-Object { "$($_.File): $($_.Text)" } | Should -BeNullOrEmpty
    }

    It 'exports only the documented commands' {
        Import-Module $script:RacModuleManifest -Force
        $exported = @((Get-Module RogueAgentChecker).ExportedFunctions.Keys | Sort-Object)
        $exported | Should -Be @('ConvertTo-RacAllowListEntry', 'Export-RacReport', 'Get-RacSignature', 'Import-RacAllowList', 'Invoke-RogueAgentScan')
    }

    It 'keeps the manifest version and the module version in step' {
        $manifest = Import-PowerShellDataFile -Path $script:RacModuleManifest
        $psm1 = Get-Content -LiteralPath (Join-Path -Path $moduleDir -ChildPath 'RogueAgentChecker.psm1') -Raw
        $psm1 | Should -Match ("RacVersion = '" + [regex]::Escape($manifest.ModuleVersion) + "'")
    }
}

Describe 'Windows PowerShell 5.1 compatibility' {
    It 'uses ASCII-only source and data (5.1 reads BOM-less UTF-8 files as ANSI)' {
        $repo = Split-Path -Parent $PSScriptRoot
        $files = @(Get-ChildItem -LiteralPath $repo -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1', '.json', '.csv' })
        foreach ($f in $files) {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            $nonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count
            $nonAscii | Should -Be 0 -Because "$($f.FullName) must be ASCII"
        }
    }

    It 'has no "a, b + c" precedence traps (the comma binds first and silently drops "+ c")' {
        $hits = foreach ($file in $codeFiles) {
            $ast = Get-RacTestAst -Path $file.FullName
            $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Operator -eq 'Plus' -and $n.Left -is [System.Management.Automation.Language.ArrayLiteralAst] }, $true) |
                ForEach-Object { '{0}:{1}: {2}' -f $file.Name, $_.Extent.StartLineNumber, $_.Extent.Text }
        }
        $hits | Should -BeNullOrEmpty
    }

    It 'parses with no errors' {
        foreach ($file in $codeFiles) {
            $tokens = $null
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            @($errors).Count | Should -Be 0 -Because $file.Name
        }
    }

    It 'passes PSScriptAnalyzer syntax and command checks for Windows PowerShell 5.1' {
        if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
            Set-ItResult -Skipped -Because 'PSScriptAnalyzer is not installed (Install-Module PSScriptAnalyzer -Scope CurrentUser)'
            return
        }
        $settings = @{
            Rules = @{
                PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1', '7.0') }
                PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework') }
            }
        }
        $results = @(Invoke-ScriptAnalyzer -Path $moduleDir -Recurse -Settings $settings -IncludeRule 'PSUseCompatibleSyntax', 'PSUseCompatibleCommands')
        $results | ForEach-Object { '{0}:{1} {2}' -f $_.ScriptName, $_.Line, $_.Message } | Should -BeNullOrEmpty
    }
}

Describe 'Secrets never reach any output' {
    BeforeAll {
        Import-Module $script:RacModuleManifest -Force
        $script:scan = Invoke-RacFixtureScan -TestRoot $TestDrive
        $script:outputs = [ordered]@{}
        foreach ($k in 'Html', 'Csv', 'Json', 'Log') { $script:outputs[$k] = Get-Content -LiteralPath $scan.Result.ReportFiles[$k] -Raw }
    }
    AfterAll {
        Remove-Variable -Name RacFake -Scope Global -ErrorAction SilentlyContinue
    }

    It 'never writes a planted fake key to the <_> output' -ForEach @('Html', 'Csv', 'Json', 'Log') {
        foreach ($name in $scan.Environment.Secrets.Keys) {
            $secret = $scan.Environment.Secrets[$name]
            $outputs[$_].Contains($secret) | Should -BeFalse -Because "the fake $name value must never appear in the $_ output"
        }
    }

    It 'never writes even a FRAGMENT of a fake key to the <_> output' -ForEach @('Html', 'Csv', 'Json', 'Log') {
        # Every planted fake key contains the marker RACTEST. A sliced key (for
        # example a snippet window that cuts through a token) would leave it behind.
        $outputs[$_] | Should -Not -Match 'RACTEST'
    }

    It 'never keeps a planted fake key in the returned objects' {
        $text = ($scan.Result.Findings | ForEach-Object {
                $_.Title; $_.Location; $_.Reasons; $_.Recommendation
                foreach ($k in $_.Evidence.Keys) { $_.Evidence[$k] }
            }) -join "`n"
        foreach ($name in $scan.Environment.Secrets.Keys) {
            $text.Contains($scan.Environment.Secrets[$name]) | Should -BeFalse -Because "fake $name"
        }
    }

    It 'actually redacted keys that appeared in command lines and configs (the test is not vacuous)' {
        $outputs['Html'] | Should -Match '\[REDACTED:anthropic-key\]'
        $outputs['Html'] | Should -Match '\[REDACTED:groq-key\]'
        $outputs['Html'] | Should -Match 'GROQ_API_KEY'
    }
}
