#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.3.0' }
<#
    End-to-end detection tests against a FAKE machine.

    Fixtures/FakeSystem.ps1 supplies fake processes, connections, tasks, services,
    WMI subscriptions and events; Fixtures/New-RacFakeAgentEnvironment.ps1 writes
    fake agent folders, configs, transcripts and fake keys into TestDrive. One full
    scan runs in BeforeAll and every test inspects its result.

    Run:  Invoke-Pester -Path .\Tests -Output Detailed
#>

BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
    Import-Module $script:RacModuleManifest -Force
    $script:scan = Invoke-RacFixtureScan -TestRoot $TestDrive
    $script:findings = @($scan.Result.Findings)
}

AfterAll {
    Remove-Variable -Name RacFake -Scope Global -ErrorAction SilentlyContinue
    Remove-Module RogueAgentChecker -ErrorAction SilentlyContinue
}

Describe 'Category 1 - processes, headless browsers, MCP servers' {
    It 'flags the OpenClaw gateway as a long-running agent process' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'AgentProcess' -AgentId 'openclaw')
        $f.Count | Should -Be 1
        $f[0].Indicators | Should -Contain 'LongRunning'
        $f[0].Evidence['Process'] | Should -Be 'node.exe (PID 5100)'
    }

    It 'attributes an MCP server process to the agent that launched it' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'McpServerProcess')
        $f.Count | Should -Be 1
        $f[0].Agent | Should -Be 'Claude Desktop'
        $f[0].Evidence['Launched by'] | Should -Match 'Claude Desktop \(PID 4100\)'
    }

    It 'detects a headless browser with remote debugging and ties it to OpenClaw' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'HeadlessBrowser')
        $f.Count | Should -Be 1
        $f[0].Agent | Should -Be 'OpenClaw'
        $f[0].Indicators | Should -Contain 'RemoteDebuggingPort'
        $f[0].Classification | Should -Be 'Suspicious'
    }

    It 'ignores Chromium child processes and ordinary processes' {
        $pids = @($findings | Where-Object { $_.Category -eq 'Processes' } | ForEach-Object { $_.Signals.ProcessId })
        $pids | Should -Not -Contain 5201
        $pids | Should -Not -Contain 901
        $pids | Should -Not -Contain 900
        $pids | Should -Not -Contain 800
    }

    It 'flags a CrewAI agent running from Downloads as suspicious' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'AgentProcess' -AgentId 'agent-framework')
        $f.Count | Should -Be 1
        $f[0].Indicators | Should -Contain 'UserWritableExecPath'
        $f[0].Classification | Should -Be 'Suspicious'
    }

    It 'marks approved agents (Claude Code, Claude Desktop, Ollama) as Trusted' {
        foreach ($id in 'claude-code', 'claude-desktop', 'ollama') {
            $f = @(Get-RacTestFinding $scan -Breadcrumb 'AgentProcess' -AgentId $id)
            $f.Count | Should -Be 1 -Because "$id should be found"
            $f[0].Classification | Should -Be 'Trusted' -Because "$id is on the allow-list"
        }
    }
}

Describe 'Scripts that processes and autostarts run (added after the 0.1.1 live test)' {
    # In the live test, a hidden PowerShell kept one connection to api.openai.com
    # open for over an hour. The DNS cache forgot the hostname after 60 seconds, so
    # the network check missed it in three of four scans. These tests prove RAC
    # now finds it by what it runs, with no network evidence at all.

    It 'catches a hidden PowerShell by the script it runs, with no network evidence' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'LlmScriptProcess' -TitleLike '*PID 6600*')
        $f.Count | Should -Be 1
        $f[0].Title | Should -Be 'powershell.exe (PID 6600) runs a script that calls api.openai.com'
        $f[0].Classification | Should -Be 'Suspicious'
        $f[0].Agent | Should -Be 'Unidentified script'
        $f[0].User | Should -Be 'CORP\bob'
        $f[0].Indicators | Should -Contain 'StealthLaunch'
        $f[0].Indicators | Should -Contain 'LlmCallFromScript'
        $f[0].Location | Should -Be $scan.Environment.RogueScript
        $f[0].Evidence['Script'] | Should -Be $scan.Environment.RogueScript
        $f[0].Evidence['LLM host referenced'] | Should -Be 'api.openai.com'
        $f[0].Evidence['Key variables used'] | Should -Be 'OPENAI_API_KEY'
        @(Get-RacTestFinding $scan -Breadcrumb 'LlmConnection' -TitleLike '*PID 6600*').Count | Should -Be 0 -Because 'this process has no connection RAC can name, like the live test after the first minute'
    }

    It 'shows a redacted sample, never the key the script carries' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'LlmScriptProcess' -TitleLike '*PID 6600*')
        $f[0].Evidence['Sample (redacted)'] | Should -Match 'api\.openai\.com'
        (@($f[0].Evidence.Values) -join ' ') | Should -Not -Match 'RACTESTKEY'
    }

    It 'reports a visible script that uses an AI SDK, below the hidden one' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'LlmScriptProcess' -TitleLike '*PID 6700*')
        $f.Count | Should -Be 1
        $f[0].Title | Should -Be 'python.exe (PID 6700) runs a script that uses an AI SDK (from openai)'
        $f[0].Indicators | Should -Contain 'LlmCallFromScript'
        $f[0].Indicators | Should -Not -Contain 'StealthLaunch'
        $rogue = @(Get-RacTestFinding $scan -Breadcrumb 'LlmScriptProcess' -TitleLike '*PID 6600*')[0]
        $f[0].Score | Should -BeLessThan $rogue.Score
    }

    It 'ignores scripts with nothing to do with AI, and an encoded command that only names a cmdlet' {
        @($findings | Where-Object { $_.Title -like '*PID 6800*' -or $_.Location -eq $scan.Environment.PlainScript }).Count | Should -Be 0
        @(Get-RacTestFinding $scan -TitleLike '*Nightly Backup*').Count | Should -Be 0
        @(Get-RacTestFinding $scan -Breadcrumb 'LlmScriptProcess' -TitleLike '*PID 802*').Count | Should -Be 0
        @(Get-RacTestFinding $scan -Breadcrumb 'LlmScriptProcess').Count | Should -Be 2
    }

    It 'catches the hidden task that starts the rogue script' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'ScheduledTask' -TitleLike '*OneDrive Sync Helper*')
        $f.Count | Should -Be 1
        $f[0].Classification | Should -Be 'Suspicious'
        $f[0].Indicators | Should -Contain 'HiddenTask'
        $f[0].Indicators | Should -Contain 'StealthLaunch'
        $f[0].Indicators | Should -Contain 'LlmCallFromScript'
        $f[0].Evidence['Matched because'] | Should -Be ('runs the script {0}, which calls api.openai.com (key variables: OPENAI_API_KEY)' -f $scan.Environment.RogueScript)
        $f[0].Evidence['Script'] | Should -Be $scan.Environment.RogueScript
    }

    It 'decodes an encoded PowerShell command in a task and reads it, without running it' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'ScheduledTask' -TitleLike '*Telemetry Refresh*')
        $f.Count | Should -Be 1
        $f[0].Evidence['Matched because'] | Should -Be 'runs an encoded PowerShell command that calls api.groq.com (key variables: GROQ_API_KEY)'
        $f[0].Indicators | Should -Contain 'LlmCallFromScript'
        $f[0].Indicators | Should -Contain 'StealthLaunch' -Because 'an encoded command hides what runs, by design'
        $f[0].Classification | Should -Be 'Suspicious'
    }
}

Describe 'False positives reported by users' {
    It 'does not file Intel''s Local Management Service (LMS.exe) under LM Studio (issue #2)' {
        # LM Studio's CLI is also called lms.exe, but it lives in ~/.lmstudio/bin. Intel's
        # Management Engine service of the same name runs as SYSTEM from Program Files,
        # which made it look like a Suspicious LM Studio.
        $intel = @($findings | Where-Object {
                ((@($_.Title, $_.Location) + @($_.Evidence.Values)) -join ' ') -match 'Management Engine|DriverStore|PID 690[01]|Local Management Service'
            })
        $intel.Count | Should -Be 0
    }

    It 'still identifies the real LM Studio CLI in ~/.lmstudio/bin' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'AgentProcess' -AgentId 'lm-studio')
        $f.Count | Should -Be 1
        $f[0].Evidence['Process'] | Should -Be 'lms.exe (PID 6910)'
    }
}

Describe 'Category 2 - network' {
    It 'flags a hidden SYSTEM PowerShell talking to the OpenAI API' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'LlmConnection' -TitleLike 'powershell.exe*')
        $f.Count | Should -Be 1
        $f[0].Classification | Should -Be 'Suspicious'
        $f[0].Indicators | Should -Contain 'LlmFromNonAgentProcess'
        $f[0].Indicators | Should -Contain 'StealthLaunch'
        $f[0].Indicators | Should -Contain 'SystemContext'
        $f[0].Evidence['Remote host'] | Should -Be 'api.openai.com'
    }

    It 'resolves hostnames through CNAME entries in the DNS cache' {
        @(Get-RacTestFinding $scan -Breadcrumb 'LlmConnection' -TitleLike '*api.openai.com*').Count | Should -Be 1
    }

    It 'trusts the approved agent''s connection to an approved endpoint' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'LlmConnection' -AgentId 'claude-code')
        $f.Count | Should -Be 1
        $f[0].Classification | Should -Be 'Trusted'
        $f[0].Indicators | Should -Contain 'PersistentLlmConnection'
    }

    It 'does not itemize ordinary browser sessions, but counts them in coverage' {
        @(Get-RacTestFinding $scan -Breadcrumb 'LlmConnection' -TitleLike '*chatgpt.com*').Count | Should -Be 0
        $row = $scan.Result.Coverage | Where-Object { $_.Source -eq 'Browser AI sessions' }
        $row.ItemCount | Should -Be 1
    }

    It 'reports LLM lookups that have no attributable connection' {
        $gemini = @(Get-RacTestFinding $scan -Breadcrumb 'DnsCacheLlm' -TitleLike '*generativelanguage.googleapis.com*')
        $gemini.Count | Should -Be 1
        $gemini[0].Classification | Should -Be 'Unknown'
        $claude = @(Get-RacTestFinding $scan -Breadcrumb 'DnsCacheLlm' -TitleLike '*claude.ai*')
        $claude[0].Classification | Should -Be 'Trusted' -Because 'claude.ai is a sanctioned provider endpoint'
    }

    It 'flags an approved Ollama that listens on all interfaces with a LAN client' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'AgentListener' -AgentId 'ollama')
        $f.Count | Should -Be 1
        $f[0].Indicators | Should -Contain 'ListensOnAllInterfaces'
        $f[0].Indicators | Should -Contain 'RemoteClientOnAgentPort'
        $f[0].AllowListEntry | Should -Be 'Ollama - local models (alice only)'
        $f[0].Classification | Should -Be 'Suspicious' -Because 'the approval does not accept network exposure'
        $f[0].Evidence['Remote clients'] | Should -Match '10\.0\.0\.77'
    }

    It 'reports the Chrome DevTools port and the loopback OpenClaw gateway' {
        @(Get-RacTestFinding $scan -Breadcrumb 'AgentListener' -TitleLike '*port 9222*').Count | Should -Be 1
        $gw = @(Get-RacTestFinding $scan -Breadcrumb 'AgentListener' -TitleLike '*port 18789*')
        $gw.Count | Should -Be 1
        $gw[0].Indicators | Should -Not -Contain 'ListensOnAllInterfaces'
    }

    It 'counts LLM hosts in proxy logs and ignores look-alike domains' {
        $openai = @(Get-RacTestFinding $scan -Breadcrumb 'ProxyLogLlm' -TitleLike '*api.openai.com*')
        $openai.Count | Should -Be 1
        $openai[0].Evidence['Matching log lines'] | Should -Be '2'
        @(Get-RacTestFinding $scan -Breadcrumb 'ProxyLogLlm' -TitleLike '*evil*').Count | Should -Be 0
        @(Get-RacTestFinding $scan -Breadcrumb 'ProxyLogLlm' -TitleLike '*api.groq.com*').Count | Should -Be 1
    }
}

Describe 'Category 3 - config, memory, skills and secrets' {
    It 'finds each agent''s config folder in the right profile' {
        @(Get-RacTestFinding $scan -Breadcrumb 'AgentConfigDir' -AgentId 'claude-code' -User 'alice').Count | Should -Be 1
        @(Get-RacTestFinding $scan -Breadcrumb 'AgentConfigDir' -AgentId 'openclaw' -User 'bob').Count | Should -Be 1
        @(Get-RacTestFinding $scan -Breadcrumb 'AgentConfigDir' -AgentId 'openai-codex' -User 'carol').Count | Should -Be 1
    }

    It 'inventories MCP servers from JSON, JSONC, TOML and YAML configs' {
        $names = @(Get-RacTestFinding $scan -Breadcrumb 'McpServerConfig' | ForEach-Object { $_.Evidence['Server name'] })
        foreach ($n in 'filesystem', 'gmail', 'slack', 'desktop-commander', 'github', 'playwright', 'shell', 'sqlite', 'linear', 'sentry') {
            $names | Should -Contain $n
        }
    }

    It 'flags unpinned packages but not pinned ones' {
        $gmail = @(Get-RacTestFinding $scan -Breadcrumb 'McpServerConfig' -TitleLike "*'gmail'*")
        $gmail[0].Indicators | Should -Contain 'UnpinnedPackage'
        $playwright = @(Get-RacTestFinding $scan -Breadcrumb 'McpServerConfig' -TitleLike "*'playwright'*")
        $playwright[0].Indicators | Should -Not -Contain 'UnpinnedPackage'
        $github = @(Get-RacTestFinding $scan -Breadcrumb 'McpServerConfig' -TitleLike "*'github'*")
        $github[0].Indicators | Should -Not -Contain 'UnpinnedPackage'
    }

    It 'flags a remote MCP server and reports only its host' {
        $sentry = @(Get-RacTestFinding $scan -Breadcrumb 'McpServerConfig' -TitleLike "*'sentry'*")
        $sentry[0].Indicators | Should -Contain 'RemoteMcpServer'
        $sentry[0].Evidence['Remote host'] | Should -Be 'mcp.sentry.dev'
        $sentry[0].Evidence['Scope'] | Should -Match '^Project '
    }

    It 'lists env var names for MCP servers but never their values' {
        $slack = @(Get-RacTestFinding $scan -Breadcrumb 'McpServerConfig' -TitleLike "*'slack'*")
        $slack[0].Evidence['Env var names'] | Should -Match 'SLACK_BOT_TOKEN'
        $slack[0].Evidence['Plaintext secrets'] | Should -Match 'SLACK_BOT_TOKEN \(Slack token\)'
        $slack[0].Indicators | Should -Contain 'SecretInPlaintext'
    }

    It 'gives an approved agent no pass for unapproved MCP servers' {
        $fs = @(Get-RacTestFinding $scan -Breadcrumb 'McpServerConfig' -TitleLike "*'filesystem'*")
        $fs[0].Classification | Should -Be 'Trusted'
        $dc = @(Get-RacTestFinding $scan -Breadcrumb 'McpServerConfig' -TitleLike "*'desktop-commander'*")
        $dc[0].Classification | Should -Not -Be 'Trusted'
        $dc[0].Indicators | Should -Contain 'ShellCapableMcp'
    }

    It 'marks a Codex shell server with a key in its config as suspicious' {
        $shell = @(Get-RacTestFinding $scan -Breadcrumb 'McpServerConfig' -AgentId 'openai-codex')
        $shell[0].Classification | Should -Be 'Suspicious'
        $shell[0].Indicators | Should -Contain 'ShellCapableMcp'
        $shell[0].Indicators | Should -Contain 'UnpinnedPackage'
        $shell[0].Indicators | Should -Contain 'SecretInPlaintext'
    }

    It 'reports a world-readable .env file as suspicious, by key name and format only' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'SecretFile' -User 'carol' | Where-Object { $_.Location -like '*Downloads*' })
        $f.Count | Should -Be 1
        $f[0].Classification | Should -Be 'Suspicious'
        $f[0].Indicators | Should -Contain 'SecretWorldReadable'
        $f[0].Evidence['Key names'] | Should -Be 'GROQ_API_KEY'
        $f[0].Evidence['Key formats'] | Should -Be 'Groq API key'
        $f[0].Evidence['Line numbers'] | Should -Be '1'
    }

    It 'ignores .env.example templates and anything inside node_modules' {
        @(Get-RacTestFinding $scan -Breadcrumb 'SecretFile' | Where-Object { $_.Location -like '*.env.example' }).Count | Should -Be 0
        @(Get-RacTestFinding $scan -Breadcrumb 'SecretFile' | Where-Object { $_.Location -like '*node_modules*' }).Count | Should -Be 0
    }

    It 'flags a machine-wide AI key environment variable without reading its value' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'EnvVarSecret' -TitleLike '*machine*')
        $f.Count | Should -Be 1
        $f[0].Classification | Should -Be 'Suspicious'
        $f[0].Evidence['Value'] | Should -Be 'not read'
        @(Get-RacTestFinding $scan -Breadcrumb 'EnvVarSecret' | Where-Object { $_.Evidence['Variable'] -eq 'PATH' }).Count | Should -Be 0
    }

    It 'finds agent packages installed via npm, pipx and site-packages' {
        @(Get-RacTestFinding $scan -Breadcrumb 'AgentPackage' -AgentId 'openclaw').Evidence['Installed via'] | Should -Be 'npm global'
        @(Get-RacTestFinding $scan -Breadcrumb 'AgentPackage' -AgentId 'aider').Evidence['Installed via'] | Should -Be 'pipx'
        @(Get-RacTestFinding $scan -Breadcrumb 'AgentPackage' -AgentId 'agent-framework').Evidence['Version'] | Should -Be '0.86.0'
    }

    It 'finds AI IDE extensions, newest version only, and skips unrelated ones' {
        $ext = @(Get-RacTestFinding $scan -Breadcrumb 'IdeExtension')
        $ext.Count | Should -Be 2
        @($ext | Where-Object { $_.Evidence['Extension'] -like 'ms-python*' }).Count | Should -Be 0
    }

    It 'survives a JSON5 config (comments, unquoted keys) without failing the category' {
        # Once comments are stripped, BOTH Windows PowerShell 5.1 and PowerShell 7
        # accept this file's unquoted keys, so it parses on both. (v0.1.1's first
        # version of this test assumed 5.1 would reject it; the real Windows run
        # showed otherwise.) Whatever the parser does, the category must not fail
        # and no MCP config row may be an Error.
        @($scan.Result.Coverage | Where-Object { $_.Source -eq 'Category: ConfigAndSecrets' -and $_.Status -eq 'Error' }).Count | Should -Be 0
        @($scan.Result.Coverage | Where-Object { $_.Source -like 'MCP config:*openclaw.json' -and $_.Status -eq 'Error' }).Count | Should -Be 0
        @(Get-RacTestFinding $scan -Breadcrumb 'AgentConfigDir' -AgentId 'openclaw').Count | Should -Be 1
    }
}

Describe 'Category 4 - persistence' {
    It 'finds the OpenClaw logon task' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'ScheduledTask' -AgentId 'openclaw')
        $f.Count | Should -Be 1
        $f[0].Indicators | Should -Contain 'PersistenceAutostart'
    }

    It 'flags a hidden SYSTEM task that launches an MCP server' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'ScheduledTask' -TitleLike '*SystemHealthUpdater*')
        $f[0].Classification | Should -Be 'Suspicious'
        $f[0].Indicators | Should -Contain 'HiddenTask'
        $f[0].Indicators | Should -Contain 'SystemContext'
        $f[0].Indicators | Should -Contain 'StealthLaunch'
    }

    It 'flags an agent platform running as a LocalSystem service' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'Service' -AgentId 'n8n')
        $f[0].Classification | Should -Be 'Suspicious'
        $f[0].Indicators | Should -Contain 'SystemContext'
    }

    It 'trusts approved autostarts the allow-list explicitly accepts' {
        @(Get-RacTestFinding $scan -Breadcrumb 'RunKey' -AgentId 'claude-desktop')[0].Classification | Should -Be 'Trusted'
        @(Get-RacTestFinding $scan -Breadcrumb 'StartupItem' -AgentId 'ollama')[0].Classification | Should -Be 'Trusted'
    }

    It 'flags a WMI subscription that starts OpenClaw, and ignores the Windows default consumer' {
        $wmi = @(Get-RacTestFinding $scan -Breadcrumb 'WmiSubscription')
        $wmi.Count | Should -Be 1
        $wmi[0].Agent | Should -Be 'OpenClaw'
        $wmi[0].Classification | Should -Be 'Suspicious'
        $wmi[0].Indicators | Should -Contain 'PersistenceWmi'
    }

    It 'keeps HiddenTask as its own indicator when it is the only extra risk' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'ScheduledTask' -TitleLike '*Codex Sync*')
        $f.Count | Should -Be 1
        $f[0].Indicators | Should -Contain 'HiddenTask'
        $f[0].Indicators | Should -Contain 'PersistenceAutostart'
        $f[0].Indicators | Should -Not -Contain 'PersistenceAutostartHiddenTask'
        $f[0].Score | Should -Be 30
    }

    It 'leaves ordinary Windows autostarts alone' {
        @(Get-RacTestFinding $scan -TitleLike '*Defrag*').Count | Should -Be 0
        @(Get-RacTestFinding $scan -TitleLike '*SecurityHealth*').Count | Should -Be 0
        @(Get-RacTestFinding $scan -TitleLike '*Spooler*').Count | Should -Be 0
    }
}

Describe 'Category 5 - tokens and OAuth' {
    It 'finds AI credentials in Credential Manager by name only' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'CredentialStore')
        $f.Count | Should -Be 1
        $f[0].AgentId | Should -Be 'claude-code'
    }

    It 'reports the Codex token file without opening it' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'TokenFile' -AgentId 'openai-codex')
        $f.Count | Should -Be 1
        $f[0].Evidence['Contents'] | Should -Match 'not opened'
        @(Get-RacTestFinding $scan -Breadcrumb 'SecretFile' | Where-Object { $_.Location -like '*auth.json' }).Count | Should -Be 0
    }

    It 'resolves a localized extension name and flags browser-control permissions' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'BrowserExtension' -AgentId 'claude-in-chrome')
        $f.Count | Should -Be 1
        $f[0].Agent | Should -Be 'Claude in Chrome'
        $f[0].Evidence['Extension'] | Should -Be 'Claude'
        $f[0].Indicators | Should -Contain 'BrowserControlPermission'
    }

    It 'does not let an approval for the Claude Desktop app cover the Claude browser extension' {
        # v0.1.1's first build filed Claude in Chrome under Claude Desktop, so the
        # real Windows report named an app that was not installed, and approving the
        # app would also have approved an extension that can drive the browser.
        @(Get-RacTestFinding $scan -Breadcrumb 'BrowserExtension' -AgentId 'claude-desktop').Count | Should -Be 0
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'BrowserExtension' -AgentId 'claude-in-chrome')
        $f[0].Classification | Should -Not -Be 'Trusted' -Because 'the fixture allow-list approves Claude Desktop, not Claude in Chrome'
    }

    It 'names other AI extensions after themselves, not after a catalog app with a similar name' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'BrowserExtension' | Where-Object { $_.Evidence['Extension'] -eq 'ChatGPT Sidebar Helper' })
        $f.Count | Should -Be 1
        $f[0].Agent | Should -Be 'ChatGPT Sidebar Helper (browser extension)'
        $f[0].AgentId | Should -Be 'ext:kfakechatgptsidebarhelper000000a'
        @(Get-RacTestFinding $scan -AgentId 'chatgpt-desktop').Count | Should -Be 0
        ($f | ConvertTo-RacAllowListEntry -ApprovedBy 'Test Admin').Agent | Should -Be 'ext:kfakechatgptsidebarhelper000000a' -Because 'the extension ID survives updates, the version folder does not'
    }

    It 'finds the native messaging bridge and attributes it' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'NativeMessagingHost')
        $f.Count | Should -Be 1
        $f[0].Agent | Should -Be 'Claude Desktop'
    }

    It 'states that tenant-side OAuth grants are out of reach' {
        @($scan.Result.Coverage | Where-Object { $_.Source -eq 'Tenant OAuth consent grants' -and $_.Status -eq 'Skipped' }).Count | Should -Be 1
    }
}

Describe 'Category 6 - logs, transcripts and event patterns' {
    It 'summarizes transcripts with a tool-call count, never their content' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'AgentTranscript' -AgentId 'claude-code')
        $f.Count | Should -Be 1
        $f[0].Evidence['Files'] | Should -Be '2'
        $f[0].Evidence['Tool-call records'] | Should -Match '^3 record'
        $f[0].Evidence['Content'] | Should -Match 'not quoted'
    }

    It 'lists MCP servers seen in Claude Desktop logs' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'AgentLog' -AgentId 'claude-desktop')
        $f[0].Evidence['MCP servers in logs'] | Should -Match 'filesystem'
        $f[0].Evidence['MCP servers in logs'] | Should -Match 'gmail'
    }

    It 'finds project-level Aider chat history' {
        @(Get-RacTestFinding $scan -Breadcrumb 'AgentTranscript' -AgentId 'aider').Count | Should -Be 1
    }

    It 'flags a PowerShell script block that calls an LLM API, with a redacted sample' {
        @(Get-RacTestFinding $scan -Breadcrumb 'PowerShellScriptBlock').Count | Should -Be 2 -Because 'carol''s script and the one disguised as RAC are reported; the ordinary block and RAC''s own code are not'
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'PowerShellScriptBlock' | Where-Object { $_.Evidence['LLM host referenced'] -eq 'api.openai.com' })
        $f.Count | Should -Be 1
        $f[0].Indicators | Should -Contain 'LlmCallFromScript'
        $f[0].Evidence['Samples (redacted)'] | Should -Match '\[REDACTED\]'
    }

    It 'never reports script blocks from its own repository, even chunks without marker text' {
        $own = @(Get-RacTestFinding $scan -Breadcrumb 'PowerShellScriptBlock' | Where-Object { $_.Evidence['Script path'] -like ($scan.RepoRoot + '*') })
        $own.Count | Should -Be 0
    }

    It 'recognizes its own code logged by another copy of RAC, or with no path' {
        # The first v0.1.1 build, run from a second folder on the test VM, reported
        # the tests that the first copy had run.
        @(Get-RacTestFinding $scan -Breadcrumb 'PowerShellScriptBlock' | Where-Object { $_.Evidence['Script path'] -like 'D:\Tools\RAC-old\*' }).Count | Should -Be 0
        @(Get-RacTestFinding $scan -Breadcrumb 'PowerShellScriptBlock' | Where-Object { $_.Evidence['Samples (redacted)'] -match 'resolves hostnames through CNAME' }).Count | Should -Be 0
    }

    It 'still reports a script that hides behind RAC''s names and folder' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'PowerShellScriptBlock' | Where-Object { $_.Evidence['LLM host referenced'] -eq 'api.groq.com' })
        $f.Count | Should -Be 1
        $f[0].Indicators | Should -Contain 'LlmCallFromScript'
        $f[0].Evidence['Note'] | Should -Match 'not part of the RAC copy that ran this scan'
    }

    It 'groups Sysmon DNS and network events per process and hides ordinary browsers' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'SysmonLlmTraffic')
        $f.Count | Should -Be 1
        $f[0].Evidence['Events'] | Should -Match '^3 '
        $f[0].Agent | Should -Be 'Script host (possible custom agent)'
    }

    It 'attributes Sysmon process launches to the agent that started them' {
        $oc = @(Get-RacTestFinding $scan -Breadcrumb 'SysmonAgentProcess' -AgentId 'openclaw')
        $oc[0].Indicators | Should -Contain 'AgentSpawnedShell'
        @(Get-RacTestFinding $scan -Breadcrumb 'SysmonAgentProcess' -AgentId 'claude-desktop').Count | Should -Be 1
    }
}

Describe 'Category 7 - behavior' {
    It 'flags OpenClaw for off-hours activity' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'OffHoursActivity' -AgentId 'openclaw')
        $f.Count | Should -Be 1
        $f[0].Indicators | Should -Contain 'OffHoursActivity'
    }

    It 'does not flag business-hours agents' {
        @(Get-RacTestFinding $scan -Breadcrumb 'OffHoursActivity' -AgentId 'claude-code').Count | Should -Be 0
        @(Get-RacTestFinding $scan -Breadcrumb 'OffHoursActivity' -AgentId 'claude-desktop').Count | Should -Be 0
    }

    It 'never merges unrelated unidentified processes into one timeline' {
        @(Get-RacTestFinding $scan -Breadcrumb 'OffHoursActivity' | Where-Object { $_.Agent -eq 'Unidentified process' }).Count | Should -Be 0
    }

    It 'flags cross-app reach and the lethal trifecta even for an approved agent' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'CrossAppReach' -AgentId 'claude-desktop')
        $f.Count | Should -Be 1
        $f[0].Indicators | Should -Contain 'CrossAppReach'
        $f[0].Indicators | Should -Contain 'LethalTrifecta'
        $f[0].AllowListEntry | Should -Be 'Claude Desktop - company standard'
        $f[0].Classification | Should -Be 'Suspicious'
        $f[0].Evidence['App categories'] | Should -Match 'email'
        $f[0].Evidence['App categories'] | Should -Match 'shell'
        $f[0].Evidence['Related findings'] | Should -Match '^RAC-\d{4}'
    }

    It 'flags an agent that installs packages on its own' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'PackageInstallActivity' -AgentId 'openclaw')
        $f[0].Indicators | Should -Contain 'AgentInstallsPackages'
        $f[0].Evidence['Most recent'] | Should -Match 'left-padz'
    }

    It 'flags an agent rewriting its own skills, confirmed by Sysmon' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'SelfModification' -AgentId 'openclaw')
        $f.Count | Should -Be 1
        $f[0].Indicators | Should -Contain 'SelfModificationByAgent'
        $f[0].Evidence['Examples'] | Should -Match 'skill\.md'
    }
}

Describe 'Classification and the allow-list' {
    It 'never trusts anything that is not on the allow-list' {
        @($findings | Where-Object { $_.Classification -eq 'Trusted' -and -not $_.AllowListEntry }).Count | Should -Be 0
        @($findings | Where-Object { $_.AgentId -eq 'openclaw' -and $_.Classification -eq 'Trusted' }).Count | Should -Be 0
    }

    It 'ignores an expired approval and says so' {
        $cursor = @(Get-RacTestFinding $scan -Breadcrumb 'AgentConfigDir' -AgentId 'cursor')
        $cursor[0].Classification | Should -Be 'Unknown'
        ($cursor[0].Reasons -join ' ') | Should -Match "Cursor pilot \(ended\).*expired on 2026-06-30"
    }

    It 'rejects an Agent * entry with no scope' {
        $scan.Result.AllowListWarnings -join ' ' | Should -Match 'Approve everything \(must be rejected\).*ignored'
        $scan.Result.AllowListEntryCount | Should -Be 6
    }

    It 'scopes approvals to the listed users' {
        $itadminClaude = @($findings | Where-Object { $_.AgentId -eq 'claude-code' -and $_.User -match 'itadmin' })
        $itadminClaude[0].Classification | Should -Not -Be 'Trusted' -Because 'the Claude Code approval names alice only'
    }

    It 'shows its arithmetic: score equals the unaccepted indicator weights' {
        $weights = @{}
        $sigPath = Join-Path -Path (Split-Path -Parent $script:RacModuleManifest) -ChildPath 'Data/signatures.json'
        $sig = Get-Content -LiteralPath $sigPath -Raw | ConvertFrom-Json
        foreach ($p in $sig.scoring.indicators.PSObject.Properties) { $weights[$p.Name] = [int]$p.Value.weight }
        foreach ($f in $findings) {
            $accepted = @($f.Reasons | Where-Object { $_ -like 'Accepted by the approval:*' } | ForEach-Object { ($_ -replace '^Accepted by the approval: (\w+).*$', '$1') })
            $expected = 0
            foreach ($i in $f.Indicators) { if ($accepted -notcontains $i) { $expected += $weights[$i] } }
            $f.Score | Should -Be $expected -Because "$($f.FindingId) $($f.Title)"
        }
    }

    It 'gives every finding reasons and a recommendation' {
        foreach ($f in $findings) {
            @($f.Reasons).Count | Should -BeGreaterThan 0
            $f.Recommendation | Should -Not -BeNullOrEmpty
        }
    }

    It 'sorts Suspicious first and numbers findings in order' {
        $ranks = @($findings | ForEach-Object { switch ($_.Classification) { 'Suspicious' { 0 } 'Unknown' { 1 } default { 2 } } })
        for ($i = 1; $i -lt $ranks.Count; $i++) { $ranks[$i] | Should -BeGreaterOrEqual $ranks[$i - 1] }
        $findings[0].FindingId | Should -Be 'RAC-0001'
        $findings[-1].FindingId | Should -Be ('RAC-{0:D4}' -f $findings.Count)
    }
}

Describe 'Report output' {
    It 'writes HTML, CSV, JSON and the scan log' {
        foreach ($k in 'Html', 'Csv', 'Json', 'Log') {
            Test-Path -LiteralPath $scan.Result.ReportFiles[$k] | Should -BeTrue -Because "$k report should exist"
        }
    }

    It 'writes one CSV row per finding' {
        @(Import-Csv -LiteralPath $scan.Result.ReportFiles['Csv']).Count | Should -Be $findings.Count
    }

    It 'writes JSON that parses and matches the summary' {
        $doc = Get-Content -LiteralPath $scan.Result.ReportFiles['Json'] -Raw | ConvertFrom-Json
        @($doc.findings).Count | Should -Be $findings.Count
        $doc.summary.Suspicious | Should -Be $scan.Result.Summary.Suspicious
        $doc.computerName | Should -Be 'FAKE-WS01'
    }

    It 'produces a self-contained HTML report with the summary, next steps and coverage' {
        $html = Get-Content -LiteralPath $scan.Result.ReportFiles['Html'] -Raw
        $html | Should -Match '<title>Rogue Agent Report - FAKE-WS01'
        $html | Should -Match 'What to do next'
        $html | Should -Match 'Coverage'
        $html | Should -Not -Match '<script src='
        $html | Should -Not -Match '<link[^>]+href="http'
    }

    It 'closes the scan log when the scan ends' {
        $before = (Get-Item -LiteralPath $scan.Result.ReportFiles['Log']).Length
        $null = Get-RacSignature
        (Get-Item -LiteralPath $scan.Result.ReportFiles['Log']).Length | Should -Be $before
        Get-Content -LiteralPath $scan.Result.ReportFiles['Log'] -Tail 1 | Should -Match 'Scan log closed'
    }

    It 'logs every scan step' {
        $log = Get-Content -LiteralPath $scan.Result.ReportFiles['Log'] -Raw
        $log | Should -Match '\[ACTION\] Scan started'
        $log | Should -Match '\[ACTION\] Analyzing category Persistence'
        $log | Should -Match '\[FINDING\] RAC-0001'
        $log | Should -Match '\[OUTPUT\] Wrote .*\.html'
    }
}

Describe 'Shipped examples and robustness' {
    It 'writes nothing to the error stream (no red text on the console)' {
        $scan.Errors | ForEach-Object { $_.ToString() } | Should -BeNullOrEmpty
    }

    It 'completes every category on the fake machine without an error' {
        @($scan.Result.Coverage | Where-Object { $_.Source -like 'Category:*' -and $_.Status -eq 'Error' }) | Should -BeNullOrEmpty
    }

    It 'loads the example allow-list <_> without warnings' -ForEach @('allowlist.example.json', 'allowlist.example.csv') {
        $path = [System.IO.Path]::Combine((Split-Path -Parent $script:RacModuleManifest), 'Data', $_)
        $list = Import-RacAllowList -Path $path -WarningAction SilentlyContinue
        $list.Warnings | Should -BeNullOrEmpty
        @($list.Entries).Count | Should -BeGreaterThan 3
    }

    It 'splits semicolon lists in the CSV allow-list' {
        $path = [System.IO.Path]::Combine((Split-Path -Parent $script:RacModuleManifest), 'Data', 'allowlist.example.csv')
        $entry = (Import-RacAllowList -Path $path -WarningAction SilentlyContinue).Entries | Where-Object { $_.Agent -eq 'claude-code' }
        $entry.Users | Should -Be @('jsmith', 'adeleon')
        $entry.McpServers | Should -Be @('github', 'filesystem')
    }

    It 'lists the agents it can recognize' {
        $ids = @(Get-RacSignature | ForEach-Object { $_.Id })
        foreach ($id in 'claude-code', 'claude-desktop', 'claude-in-chrome', 'openai-codex', 'github-copilot', 'openclaw', 'ollama', 'agent-framework') { $ids | Should -Contain $id }
    }
}

Describe 'ConvertTo-RacAllowListEntry' {
    It 'drafts a user-scoped entry with an approver and expiry' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'AgentConfigDir' -AgentId 'openai-codex')
        $entry = $f | ConvertTo-RacAllowListEntry -ApprovedBy 'Test Admin' -ExpiresInDays 30
        $entry.Agent | Should -Be 'openai-codex'
        $entry.Users | Should -Contain 'carol'
        $entry.ApprovedBy | Should -Be 'Test Admin'
        $entry.Expires | Should -Be ((Get-Date).Date.AddDays(30).ToString('yyyy-MM-dd'))
    }

    It 'scopes a draft for an unattributed finding narrowly' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'DnsCacheLlm' -TitleLike '*generativelanguage*')
        $entry = $f | ConvertTo-RacAllowListEntry -ApprovedBy 'Test Admin'
        $entry.Agent | Should -Be '*'
        $entry.Breadcrumbs | Should -Contain 'DnsCacheLlm'
    }

    It 'turns an Unknown agent into Trusted once the drafted entry is added' {
        $f = @(Get-RacTestFinding $scan -Breadcrumb 'AgentConfigDir' -AgentId 'openai-codex')
        $draft = $f | ConvertTo-RacAllowListEntry -ApprovedBy 'Test Admin'
        $fixture = Get-Content -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'Fixtures/allowlist.fixture.json') -Raw | ConvertFrom-Json
        $combined = @($fixture.entries) + @($draft)
        $path = Join-Path -Path $TestDrive -ChildPath 'allowlist.with-draft.json'
        Set-Content -LiteralPath $path -Value (ConvertTo-Json -InputObject @{ entries = $combined } -Depth 6) -Encoding UTF8

        $rescan = Invoke-RacFixtureScan -TestRoot (Join-Path -Path $TestDrive -ChildPath 'rescan') -AllowListPath $path
        $codexDir = @(Get-RacTestFinding $rescan -Breadcrumb 'AgentConfigDir' -AgentId 'openai-codex')
        $codexDir[0].Classification | Should -Be 'Trusted'
        $codexShell = @(Get-RacTestFinding $rescan -Breadcrumb 'McpServerConfig' -AgentId 'openai-codex')
        $codexShell[0].Classification | Should -Be 'Suspicious' -Because 'approval does not cover a shell server with a key in its config'
    }
}

Describe 'Helpers' {
    It 'marks an event log Partial when it no longer reaches back over the lookback window' {
        InModuleScope RogueAgentChecker {
            $start = (Get-Date).AddDays(-7)
            # Full and overwriting, oldest event an hour old: what the test VM's PowerShell log looked like.
            $wrapped = [pscustomobject]@{ LogName = 'Microsoft-Windows-PowerShell/Operational'; LogMode = 'Circular'; MaxBytes = 15MB; FileBytes = 15MB; OldestEvent = (Get-Date).AddHours(-1) }
            $r = Get-RacEventLogReach -Info $wrapped -LookbackStart $start
            $r.Partial | Should -BeTrue
            $r.Note | Should -Match 'only reaches back to'
            $r.Note | Should -Match 'overwrites the oldest events'

            $roomy = [pscustomobject]@{ LogName = 'x'; LogMode = 'Circular'; MaxBytes = 1GB; FileBytes = 15MB; OldestEvent = (Get-Date).AddDays(-30) }
            (Get-RacEventLogReach -Info $roomy -LookbackStart $start).Partial | Should -BeFalse
            (Get-RacEventLogReach -Info $roomy -LookbackStart $start).Note | Should -Match '^Log reaches back to'

            $fullButLongEnough = [pscustomobject]@{ LogName = 'x'; LogMode = 'Circular'; MaxBytes = 15MB; FileBytes = 15MB; OldestEvent = (Get-Date).AddDays(-9) }
            (Get-RacEventLogReach -Info $fullButLongEnough -LookbackStart $start).Partial | Should -BeFalse

            $notFull = [pscustomobject]@{ LogName = 'x'; LogMode = 'Circular'; MaxBytes = 1GB; FileBytes = 1MB; OldestEvent = (Get-Date).AddHours(-2) }
            (Get-RacEventLogReach -Info $notFull -LookbackStart $start).Partial | Should -BeFalse -Because 'a log that is not full has not overwritten anything'

            $retain = [pscustomobject]@{ LogName = 'x'; LogMode = 'Retain'; MaxBytes = 15MB; FileBytes = 15MB; OldestEvent = (Get-Date).AddDays(-30) }
            $r = Get-RacEventLogReach -Info $retain -LookbackStart $start
            $r.Partial | Should -BeTrue
            $r.Note | Should -Match 'stopped recording new ones'

            (Get-RacEventLogReach -Info $null -LookbackStart $start).Partial | Should -BeFalse
        }
    }

    It 'redacts every supported key format and keeps the label' {
        InModuleScope RogueAgentChecker {
            $s = Protect-RacText 'a sk-ant-api03-FAKEFAKEFAKE0000RACTESTKEY0000 b'
            $s | Should -Be 'a [REDACTED:anthropic-key] b'
            Protect-RacText 'x sk-proj-FAKEFAKEFAKE0000RACTESTKEY y' | Should -Match '\[REDACTED:openai-key\]'
            Protect-RacText 'gsk_FAKEFAKEFAKE0000RACTESTKEY0000' | Should -Be '[REDACTED:groq-key]'
            Protect-RacText 'AIzaSyFAKEFAKEFAKE0000RACTESTKEY0000aaa' | Should -Be '[REDACTED:google-api-key]'
        }
    }

    It 'redacts secrets it has no format for, by context' {
        InModuleScope RogueAgentChecker {
            Protect-RacText 'tool --api-key hunter2hunter2' | Should -Be 'tool --api-key [REDACTED]'
            Protect-RacText 'Authorization: Bearer abc.def.ghi123' | Should -Match 'Bearer \[REDACTED\]'
            Protect-RacText 'https://admin:s3cretpass@example.invalid/x' | Should -Be 'https://admin:[REDACTED]@example.invalid/x'
            Protect-RacText 'client_secret=abcd1234' | Should -Be 'client_secret=[REDACTED]'
        }
    }

    It 'redacts before truncating, so a key is never half-printed' {
        InModuleScope RogueAgentChecker {
            $s = Protect-RacText ('x' * 10 + ' sk-ant-api03-FAKEFAKEFAKE0000RACTESTKEY0000') -MaxLength 20
            $s | Should -Not -Match 'sk-ant'
        }
    }

    It 'opens only local script files: network paths are never read' {
        InModuleScope RogueAgentChecker {
            Mock Get-RacDriveType { 'Network' } -ParameterFilter { $Letter -eq 'Z' }
            Mock Get-RacDriveType { 'Fixed' } -ParameterFilter { $Letter -eq 'C' }
            Mock Read-RacTextFile { 'irm https://api.openai.com/v1/models' }
            Test-RacLocalFilePath '\\fileserver\scripts\sync.ps1' | Should -BeFalse
            Test-RacLocalFilePath '//fileserver/scripts/sync.ps1' | Should -BeFalse
            Test-RacLocalFilePath 'Z:\scripts\sync.ps1' | Should -BeFalse -Because 'Z: is a mapped network drive'
            Test-RacLocalFilePath 'C:\scripts\sync.ps1' | Should -BeTrue
            $ctx = [pscustomobject]@{ Signatures = $null; ScriptTexts = @{} }
            Get-RacScriptFileText -Context $ctx -Path '\\fileserver\scripts\sync.ps1' | Should -BeNullOrEmpty
            Get-RacScriptFileText -Context $ctx -Path 'Z:\scripts\sync.ps1' | Should -BeNullOrEmpty
            Should -Invoke Read-RacTextFile -Times 0 -Exactly
        }
    }

    It 'finds script paths in a command line, but not relative or %VARIABLE% paths' {
        InModuleScope RogueAgentChecker {
            $p = @(Get-RacScriptPathFromCommand 'tool.exe --script=C:\x\y.py "D:\a b\c.ps1" rel\z.ps1 %LOCALAPPDATA%\q.ps1 run.cmd')
            $p | Should -Be @('C:\x\y.py', 'D:\a b\c.ps1')
        }
    }

    It 'decodes -EncodedCommand and its short forms, and nothing else' {
        InModuleScope RogueAgentChecker {
            $b64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Get-Date'))
            ConvertFrom-RacEncodedCommand "powershell.exe -EncodedCommand $b64" | Should -Be 'Get-Date'
            ConvertFrom-RacEncodedCommand "powershell -enc $b64" | Should -Be 'Get-Date'
            ConvertFrom-RacEncodedCommand "powershell -e $b64" | Should -Be 'Get-Date'
            ConvertFrom-RacEncodedCommand 'powershell.exe -ExecutionPolicy AAAAAAAAAAAAAAAA' | Should -BeNullOrEmpty
            ConvertFrom-RacEncodedCommand 'powershell.exe -File C:\x.ps1' | Should -BeNullOrEmpty
        }
    }

    It 'lists AI key variable names a script uses, never values, and ignores ordinary names' {
        InModuleScope RogueAgentChecker {
            $sig = Import-RacSignatureFile -Path (Join-Path -Path $script:RacModuleRoot -ChildPath 'Data/signatures.json')
            $names = @(Get-RacAiKeyName -Signatures $sig -Text '$key = $env:OPENAI_API_KEY; $t = $env:GITHUB_TOKEN; os.environ["ANTHROPIC_API_KEY"]; $monkey = 1')
            $names | Should -Be @('OPENAI_API_KEY', 'ANTHROPIC_API_KEY')
        }
    }

    It 'scans .env text for names and formats only' {
        InModuleScope RogueAgentChecker {
            $sig = Import-RacSignatureFile -Path (Join-Path -Path $script:RacModuleRoot -ChildPath 'Data/signatures.json')
            $r = Get-RacSecretScan -Signatures $sig -Text "A=1`nOPENAI_API_KEY=sk-proj-FAKEFAKEFAKE0000RACTESTKEY`nANTHROPIC_API_KEY=your-key-here" -EnvStyle
            $r.KeyNames | Should -Be @('OPENAI_API_KEY')
            $r.LineNumbers | Should -Be @(2)
            ($r | ConvertTo-Json) | Should -Not -Match 'FAKEFAKE'
        }
    }

    It 'strips JSONC comments without touching // inside strings' {
        InModuleScope RogueAgentChecker {
            $out = Remove-RacJsonComment -Text "{ // c`n `"u`": `"https://x//y`", /* z */ `"a`": [1,2,], }"
            ($out | ConvertFrom-Json).u | Should -Be 'https://x//y'
        }
    }

    It 'matches LLM endpoints with wildcards and rejects look-alikes' {
        InModuleScope RogueAgentChecker {
            $sig = Import-RacSignatureFile -Path (Join-Path -Path $script:RacModuleRoot -ChildPath 'Data/signatures.json')
            (Find-RacLlmEndpoint -Signatures $sig -HostName 'api.individual.githubcopilot.com').provider | Should -Be 'GitHub Copilot'
            (Find-RacLlmEndpoint -Signatures $sig -HostName 'bedrock-runtime.us-east-1.amazonaws.com').provider | Should -Be 'AWS Bedrock'
            Find-RacLlmEndpoint -Signatures $sig -HostName 'api.openai.com.evil.example' | Should -BeNullOrEmpty
            'connect api.openai.com.evil.example:443' -match $sig._EndpointRegex | Should -BeFalse
            'CONNECT api.anthropic.com:443' -match $sig._EndpointRegex | Should -BeTrue
        }
    }

    It 'recognizes unpinned package launches' {
        InModuleScope RogueAgentChecker {
            Get-RacUnpinnedPackageSpec 'npx -y @modelcontextprotocol/server-filesystem C:\x' | Should -Be '@modelcontextprotocol/server-filesystem'
            Get-RacUnpinnedPackageSpec 'npx -y some-mcp@latest' | Should -Be 'some-mcp@latest'
            Get-RacUnpinnedPackageSpec 'npx @playwright/mcp@0.0.41' | Should -BeNullOrEmpty
            Get-RacUnpinnedPackageSpec 'uvx mcp-server-fetch' | Should -Be 'mcp-server-fetch'
            Get-RacUnpinnedPackageSpec 'uvx mcp-server-fetch==1.2.0' | Should -BeNullOrEmpty
        }
    }

    It 'expands path templates per profile' {
        InModuleScope RogueAgentChecker {
            $p = Expand-RacPathTemplate -Template '%APPDATA%/Claude/x.json' -ProfileRoot 'ROOT'
            ($p -split '[\\/]') -join '|' | Should -Be 'ROOT|AppData|Roaming|Claude|x.json'
            Expand-RacPathTemplate -Template '~/.codex' -ProfileRoot '' | Should -BeNullOrEmpty
        }
    }

    It 'reads leaf names from Windows paths on any OS' {
        InModuleScope RogueAgentChecker {
            Get-RacLeafName 'C:\Program Files\nodejs\node.exe' | Should -Be 'node.exe'
            Get-RacLeafName '/usr/bin/node' | Should -Be 'node'
        }
    }

    It 'applies business days and hours' {
        InModuleScope RogueAgentChecker {
            $days = @('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday')
            Test-RacOffHours -Time ([datetime]'2026-10-21 10:00') -StartHour 7 -EndHour 19 -BusinessDays $days | Should -BeFalse   # Wednesday
            Test-RacOffHours -Time ([datetime]'2026-10-21 02:00') -StartHour 7 -EndHour 19 -BusinessDays $days | Should -BeTrue
            Test-RacOffHours -Time ([datetime]'2026-10-24 10:00') -StartHour 7 -EndHour 19 -BusinessDays $days | Should -BeTrue    # Saturday
        }
    }
}
