#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.3.0' }
<#
    Integration tests against the REAL Windows sources (Win32_Process, Task
    Scheduler, the real event logs). Opt-in, because they create two harmless
    fakes on your machine and then remove them:

      * a hidden PowerShell process that only runs Start-Sleep for 5 minutes, with
        a comment in its command line that makes it look like an MCP server
      * a DISABLED scheduled task in your own account, set to run once in five
        years, whose action looks like an OpenClaw gateway (it is never run)

    Run from a normal (non-elevated) PowerShell:
        $env:RAC_INTEGRATION = '1'
        Invoke-Pester -Path .\Tests\Integration.Windows.Tests.ps1 -Output Detailed

    The scan itself stays read-only; only this test file creates and removes the fakes.
#>

BeforeDiscovery {
    $script:runIntegration = ($env:RAC_INTEGRATION -eq '1') -and ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)
}

Describe 'Real Windows sources (opt-in: set RAC_INTEGRATION=1)' -Skip:(-not $runIntegration) {
    BeforeAll {
        $manifest = [System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'RogueAgentChecker', 'RogueAgentChecker.psd1')
        Import-Module $manifest -Force

        $marker = 'rac-fake-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $shellPath = (Get-Process -Id $PID).Path

        # Fake MCP server process: sleeps, nothing else. The text after '#' is a comment.
        $script:fakeProcess = Start-Process -FilePath $shellPath -WindowStyle Hidden -PassThru -ArgumentList @(
            '-NoProfile', '-Command', "Start-Sleep -Seconds 300 # $marker npx @modelcontextprotocol/server-filesystem"
        )
        Start-Sleep -Seconds 2

        # Fake OpenClaw autostart: disabled, far-future trigger, never runs.
        $script:taskName = 'RAC-FakeAgent-' + $marker
        $script:taskCreated = $false
        $script:taskError = ''
        try {
            $action = New-ScheduledTaskAction -Execute 'node.exe' -Argument 'C:\RacFake\node_modules\openclaw\dist\index.js gateway --port 18789'
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(5)
            $settings = New-ScheduledTaskSettingsSet -Disable
            Register-ScheduledTask -TaskName $script:taskName -Action $action -Trigger $trigger -Settings $settings -ErrorAction Stop | Out-Null
            $script:taskCreated = $true
        }
        catch {
            $script:taskError = $_.Exception.Message
        }

        $script:outDir = Join-Path -Path $TestDrive -ChildPath 'out'
        # 2>&1 keeps anything written to the error stream (red console text) so a test can assert there is none.
        $all = @(Invoke-RogueAgentScan -OutputPath $script:outDir -PassThru -WarningAction SilentlyContinue 2>&1 6>$null)
        $script:scanErrors = @($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $script:result = $all | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | Select-Object -Last 1
    }

    AfterAll {
        if ($script:fakeProcess -and -not $script:fakeProcess.HasExited) {
            Stop-Process -Id $script:fakeProcess.Id -Force -ErrorAction SilentlyContinue
        }
        if ($script:taskCreated) {
            Unregister-ScheduledTask -TaskName $script:taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Module RogueAgentChecker -ErrorAction SilentlyContinue
    }

    It 'finds the fake MCP server process through Win32_Process' {
        $f = @($result.Findings | Where-Object { $_.Breadcrumb -eq 'McpServerProcess' -and $_.Signals.ProcessId -eq $fakeProcess.Id })
        $f.Count | Should -Be 1
        $f[0].Classification | Should -Not -Be 'Trusted'
    }

    It 'finds the fake OpenClaw scheduled task through Task Scheduler' {
        if (-not $taskCreated) {
            Set-ItResult -Skipped -Because "this account could not register a task: $taskError"
            return
        }
        $f = @($result.Findings | Where-Object { $_.Breadcrumb -eq 'ScheduledTask' -and $_.Title -like "*$taskName*" })
        $f.Count | Should -Be 1
        $f[0].AgentId | Should -Be 'openclaw'
    }

    It 'completes every category without an error' {
        @($result.Coverage | Where-Object { $_.Source -like 'Category:*' -and $_.Status -eq 'Error' }) | Should -BeNullOrEmpty
    }

    It 'writes the report files on a real machine' {
        foreach ($k in 'Html', 'Csv', 'Json', 'Log') {
            Test-Path -LiteralPath $result.ReportFiles[$k] | Should -BeTrue
        }
    }

    It 'returns an RMM exit code from the wrapper script' {
        $wrapper = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'Start-RogueAgentScan.ps1'
        $shellPath = (Get-Process -Id $PID).Path
        $output = & $shellPath -NoProfile -ExecutionPolicy Bypass -File $wrapper -OutputPath (Join-Path -Path $TestDrive -ChildPath 'rmm') -RmmMode
        $LASTEXITCODE | Should -BeIn @(0, 1, 2)
        ($output | Select-Object -Last 1) | Should -Match '^RAC: \d+ suspicious, \d+ unknown, \d+ trusted'
    }

    It 'reads the current user''s own registry hive, elevated or not' {
        # v0.1.0: one unreadable service-account hive (S-1-5-19) made a standard-user scan skip ALL user hives.
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $hives = @(InModuleScope RogueAgentChecker { Get-RacLoadedUserHive })
        $mine = @($hives | Where-Object { $_.Sid -eq $me })
        $mine.Count | Should -Be 1
        $mine[0].Readable | Should -BeTrue
        $run = @($result.Coverage | Where-Object { $_.Source -eq 'Run / RunOnce registry keys' })
        $run[0].Detail | Should -Match '\b[1-9]\d* user hive\(s\) read'
    }

    It 'writes nothing to the error stream (no red text on the console)' {
        $scanErrors | ForEach-Object { $_.ToString() } | Should -BeNullOrEmpty
    }

    It 'says how far back the PowerShell log reaches, and flags a log that no longer covers the lookback' {
        # On the test VM this log held about an hour of a busy day while the report claimed 7 days.
        $row = @($result.Coverage | Where-Object { $_.Source -eq 'Event log: Microsoft-Windows-PowerShell/Operational' })
        $row.Count | Should -Be 1
        $row[0].Detail | Should -Match 'reaches back to'
        if ($row[0].Detail -match 'only reaches back to') { $row[0].Status | Should -Be 'Partial' }
    }

    It 'records why sources were limited when not elevated' {
        if ($result.Elevated) {
            Set-ItResult -Skipped -Because 'running elevated'
            return
        }
        @($result.Coverage | Where-Object { $_.Status -in 'Partial', 'Skipped' }).Count | Should -BeGreaterThan 0
        # v0.1.0 reported "Checked, 0 items" here when Windows silently returned nothing to a standard user.
        foreach ($source in 'DNS client cache', 'Event log: Security') {
            $row = @($result.Coverage | Where-Object { $_.Source -eq $source })
            if ($row.Count -gt 0) {
                ($row[0].Status -eq 'Checked' -and $row[0].ItemCount -eq 0) | Should -BeFalse -Because "$source must not claim a clean read it did not get"
            }
        }
    }
}
