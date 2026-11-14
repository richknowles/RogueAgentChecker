<#
    New-RacFakeAgentEnvironment.ps1 - builds FAKE user profiles on disk with fake
    agent folders, fake MCP configs, fake transcripts and FAKE API keys, so the
    file-based detectors can be tested without installing a real agent.

    Three fake users, three stories:
      alice  - sanctioned developer: Claude Code, Claude Desktop, Ollama, Copilot.
               Mostly approved, but her Claude Desktop is wired into email, chat,
               files and a shell.
      bob    - rogue agent: OpenClaw with a gateway, skills it rewrites itself,
               keys in a .env, activity at 2 a.m.
      carol  - shadow-AI tinkerer: Codex CLI with a shell MCP server and a key in
               its config, Aider, CrewAI, a world-readable .env in Downloads.

    Every key below is fake. They are shaped like real keys only so the format
    detectors fire; the tests then prove none of them ever reach a report.
#>

function Join-FakePath {
    # [System.IO.Path]::Combine works the same on Windows PowerShell 5.1 and PowerShell 7.
    return [System.IO.Path]::Combine([string[]]$args)
}

function New-RacFakeAgentEnvironment {
    param([Parameter(Mandatory = $true)][string]$Root)

    $now = Get-Date

    # A recent weekday at 10:00 = inside business hours.
    $biz = $now.Date.AddDays(-1)
    while (@('Saturday', 'Sunday') -contains $biz.DayOfWeek.ToString()) { $biz = $biz.AddDays(-1) }
    $biz = $biz.AddHours(10)

    # Small hours of the morning = outside business hours on any day.
    $off1 = $now.Date.AddDays(-1).AddHours(2).AddMinutes(14)
    $off2 = $now.Date.AddDays(-1).AddHours(2).AddMinutes(41)
    $off3 = $now.Date.AddDays(-2).AddHours(3).AddMinutes(5)
    $old = $now.AddDays(-60)

    $secrets = [ordered]@{
        Anthropic = 'sk-ant-api03-FAKEFAKEFAKE0000RACTESTKEY0000aaaa1111bbbb'
        OpenAI    = 'sk-proj-FAKEFAKEFAKE0000RACTESTKEY0000cccc2222'
        Groq      = 'gsk_FAKEFAKEFAKE0000RACTESTKEY0000dddd3333'
        GitHub    = 'ghp_FAKEFAKEFAKE0000RACTESTKEY0000eeee4444'
        Slack     = 'xoxb-0000-FAKE-RACTESTKEY'
        CodexJwt  = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJGQUtFLVJBQy1URVNUIn0.FAKESIGNATURE0000RACTEST'
        Bearer    = 'FAKEBEARERTOKEN0000RACTEST'
        Telegram  = '123456789:FAKETELEGRAMTOKEN0000RACTEST'
    }

    $users = Join-FakePath $Root 'Users'
    $alice = Join-FakePath $users 'alice'
    $bob = Join-FakePath $users 'bob'
    $carol = Join-FakePath $users 'carol'
    $times = @{}

    function Write-Fake {
        param([string]$Path, [string]$Content = '', [object]$Time = $null)
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
        if ($Time) { $times[$Path] = $Time }
    }
    function New-FakeDir {
        param([string]$Path, [object]$Time = $null)
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
        if ($Time) { $times[$Path] = $Time }
    }

    # =====================================================================
    # alice - sanctioned developer
    # =====================================================================
    Write-Fake (Join-FakePath $alice '.claude' 'settings.json') '{ "permissions": { "allow": [ "Bash(git status)" ] } }'
    Write-Fake (Join-FakePath $alice '.claude' 'CLAUDE.md') '# House rules for this machine' $old
    Write-Fake (Join-FakePath $alice '.claude' 'skills' 'code-review' 'SKILL.md') '# Code review skill' $old
    Write-Fake (Join-FakePath $alice '.claude' 'projects' 'C--src-webapp' 'session-1.jsonl') (@(
            '{"type":"user","message":"run the tests"}',
            '{"type":"assistant","content":[{"type":"tool_use","name":"Bash","input":{"command":"npm test"}}]}',
            '{"type":"assistant","content":[{"type":"tool_use","name":"Edit","input":{"file":"app.js"}}]}'
        ) -join "`n")
    Write-Fake (Join-FakePath $alice '.claude' 'projects' 'C--src-webapp' 'session-2.jsonl') '{"type":"assistant","content":[{"type":"tool_use","name":"Read","input":{"file":"README.md"}}]}'

    $claudeJson = @{
        numStartups = 12
        mcpServers  = @{
            github = @{ command = 'npx'; args = @('-y', '@modelcontextprotocol/server-github@2025.4.8'); env = @{ GITHUB_PERSONAL_ACCESS_TOKEN = $secrets.GitHub } }
        }
        projects    = @{ 'C:/src/webapp' = @{ allowedTools = @(); mcpServers = @{} } }
    } | ConvertTo-Json -Depth 6
    Write-Fake (Join-FakePath $alice '.claude.json') $claudeJson

    $desktopConfig = @{
        mcpServers = [ordered]@{
            filesystem          = @{ command = 'npx'; args = @('-y', '@modelcontextprotocol/server-filesystem', 'C:\Users\alice\Documents') }
            gmail               = @{ command = 'npx'; args = @('-y', '@gongrzhe/server-gmail-autoauth-mcp') }
            slack               = @{ command = 'npx'; args = @('-y', '@modelcontextprotocol/server-slack'); env = @{ SLACK_BOT_TOKEN = $secrets.Slack; SLACK_TEAM_ID = 'T0000FAKE' } }
            'desktop-commander' = @{ command = 'npx'; args = @('-y', '@wonderwhy-er/desktop-commander@latest') }
        }
    } | ConvertTo-Json -Depth 6
    Write-Fake (Join-FakePath $alice 'AppData' 'Roaming' 'Claude' 'claude_desktop_config.json') $desktopConfig
    Write-Fake (Join-FakePath $alice 'AppData' 'Roaming' 'Claude' 'logs' 'mcp.log') 'mcp started'
    Write-Fake (Join-FakePath $alice 'AppData' 'Roaming' 'Claude' 'logs' 'mcp-server-filesystem.log') 'server started'
    Write-Fake (Join-FakePath $alice 'AppData' 'Roaming' 'Claude' 'logs' 'mcp-server-gmail.log') 'server started'

    Write-Fake (Join-FakePath $alice 'AppData' 'Roaming' 'npm' 'node_modules' '@anthropic-ai' 'claude-code' 'package.json') '{ "name": "@anthropic-ai/claude-code", "version": "2.1.3" }'

    # VS Code user MCP config written as JSONC: comments and trailing commas.
    Write-Fake (Join-FakePath $alice 'AppData' 'Roaming' 'Code' 'User' 'mcp.json') (@(
            '{',
            '  // Playwright for UI tests, pinned on purpose. URL in a string: "https://example.invalid/a//b"',
            '  "servers": {',
            '    "playwright": { "command": "npx", "args": ["@playwright/mcp@0.0.41"] }, /* trailing comma follows */',
            '  },',
            '}'
        ) -join "`n")
    New-FakeDir (Join-FakePath $alice '.vscode' 'extensions' 'github.copilot-1.350.0')
    New-FakeDir (Join-FakePath $alice '.vscode' 'extensions' 'github.copilot-chat-0.31.0')
    New-FakeDir (Join-FakePath $alice '.vscode' 'extensions' 'ms-python.python-2026.10.0')

    $extBase = Join-FakePath $alice 'AppData' 'Local' 'Google' 'Chrome' 'User Data' 'Default' 'Extensions'
    Write-Fake (Join-FakePath $extBase 'fcoeoabgfenejglbffodgkkbkcdhcgfn' '1.0.36_0' 'manifest.json') '{ "manifest_version": 3, "name": "__MSG_appName__", "version": "1.0.36", "permissions": ["debugger", "nativeMessaging", "tabs", "sidePanel"] }'
    Write-Fake (Join-FakePath $extBase 'fcoeoabgfenejglbffodgkkbkcdhcgfn' '1.0.36_0' '_locales' 'en' 'messages.json') '{ "appName": { "message": "Claude" } }'
    Write-Fake (Join-FakePath $extBase 'aapocclcgogkmnckokdopfmhonfmgoek' '0.10_0' 'manifest.json') '{ "manifest_version": 2, "name": "Slides", "version": "0.10" }'

    $nativeHostManifest = Join-FakePath $alice 'AppData' 'Local' 'AnthropicClaude' 'ChromeNativeHost' 'com.anthropic.claude_browser_extension.json'
    Write-Fake $nativeHostManifest '{ "name": "com.anthropic.claude_browser_extension", "description": "Claude Browser Extension Native Host", "path": "C:\\Users\\alice\\AppData\\Local\\AnthropicClaude\\chrome-native-host.exe", "type": "stdio", "allowed_origins": ["chrome-extension://fcoeoabgfenejglbffodgkkbkcdhcgfn/"] }'

    Write-Fake (Join-FakePath $alice '.ollama' 'history') 'why is the sky blue'
    Write-Fake (Join-FakePath $alice 'AppData' 'Local' 'Ollama' 'server.log') 'Listening on [::]:11434'

    $webapp = Join-FakePath $alice 'Documents' 'src' 'webapp'
    Write-Fake (Join-FakePath $webapp '.env') ("NODE_ENV=development`nOPENAI_API_KEY=" + $secrets.OpenAI + "`nDATABASE_URL=postgres://localhost/dev")
    Write-Fake (Join-FakePath $webapp '.env.example') "OPENAI_API_KEY=your-key-here"
    Write-Fake (Join-FakePath $webapp '.mcp.json') '{ "mcpServers": { "sentry": { "type": "http", "url": "https://mcp.sentry.dev/mcp" } } }'
    New-FakeDir (Join-FakePath $webapp 'node_modules' 'left-pad')
    Write-Fake (Join-FakePath $webapp 'node_modules' 'left-pad' '.env') ('OPENAI_API_KEY=' + $secrets.OpenAI)   # inside node_modules: must be skipped

    # =====================================================================
    # bob - rogue OpenClaw agent, busiest at 2 a.m.
    # =====================================================================
    Write-Fake (Join-FakePath $bob '.openclaw' 'openclaw.json') (@(
            '// OpenClaw config (JSON5: comments and unquoted keys)',
            '{',
            '  gateway: { port: 18789, bind: "lan" },',
            '  agents: { defaults: { workspace: "~/.openclaw/workspace" } },',
            '}'
        ) -join "`n")
    Write-Fake (Join-FakePath $bob '.openclaw' '.env') ("ANTHROPIC_API_KEY=" + $secrets.Anthropic + "`nTELEGRAM_BOT_TOKEN=" + $secrets.Telegram)
    Write-Fake (Join-FakePath $bob '.openclaw' 'workspace' 'skills' 'autoupdate' 'SKILL.md') '# Auto-update: install whatever packages the task needs' $off3
    Write-Fake (Join-FakePath $bob '.openclaw' 'workspace' 'MEMORY.md') '- remembered: run nightly' $off1
    Write-Fake (Join-FakePath $bob '.openclaw' 'agents' 'main' 'sessions' '2f9c.jsonl') (@(
            '{"role":"assistant","content":[{"type":"tool_use","name":"exec","input":{"cmd":"npm install -g left-padz"}}]}',
            '{"role":"assistant","content":[{"type":"tool_use","name":"browser","input":{"url":"https://mail.example.invalid"}}]}'
        ) -join "`n") $off1
    Write-Fake (Join-FakePath $bob '.openclaw' 'agents' 'main' 'sessions' '7a1d.jsonl') '{"role":"assistant","content":[{"type":"tool_use","name":"exec","input":{"cmd":"whoami"}}]}' $off2
    Write-Fake (Join-FakePath $bob 'AppData' 'Roaming' 'npm' 'node_modules' 'openclaw' 'package.json') '{ "name": "openclaw", "version": "2026.10.2" }'
    Write-Fake (Join-FakePath $bob 'AppData' 'Local' 'Temp' 'openclaw' 'openclaw-2026-10-25.log') 'gateway listening' $off3

    # =====================================================================
    # carol - shadow AI tinkerer
    # =====================================================================
    $bot = Join-FakePath $carol 'Downloads' 'bot'
    Write-Fake (Join-FakePath $bot '.env') ("GROQ_API_KEY=" + $secrets.Groq)
    Write-Fake (Join-FakePath $bot '.aider.chat.history.md') "# aider chat started`n> /add main.py"
    Write-Fake (Join-FakePath $carol '.local' 'pipx' 'venvs' 'aider-chat' 'pyvenv.cfg') 'home = C:\Python312'
    Write-Fake (Join-FakePath $carol 'AppData' 'Roaming' 'Python' 'Python312' 'site-packages' 'crewai-0.86.0.dist-info' 'METADATA') 'Name: crewai'

    Write-Fake (Join-FakePath $carol '.codex' 'config.toml') (@(
            'model = "gpt-5-codex"',
            '',
            '[mcp_servers.shell]',
            'command = "npx"',
            'args = [',
            '  "-y",',
            '  "mcp-shell-server"',
            ']',
            '',
            '[mcp_servers.shell.env]',
            ('OPENAI_API_KEY = "' + $secrets.OpenAI + '"')
        ) -join "`n")
    Write-Fake (Join-FakePath $carol '.codex' 'auth.json') ('{ "tokens": { "id_token": "' + $secrets.CodexJwt + '" } }')
    Write-Fake (Join-FakePath $carol '.codex' 'sessions' '2026' '10' '25' 'rollout-1.jsonl') '{"type":"function_call","name":"shell","arguments":"{\"command\":[\"ls\"]}"}'

    Write-Fake (Join-FakePath $carol '.cursor' 'mcp.json') '{ "mcpServers": { "linear": { "url": "https://mcp.linear.app/sse" } } }'

    Write-Fake (Join-FakePath $carol '.continue' 'config.yaml') (@(
            'name: carol-assistant',
            'mcpServers:',
            '  - name: sqlite',
            '    command: uvx',
            '    args:',
            '      - mcp-server-sqlite',
            '      - --db-path',
            '      - C:\Users\carol\data.db'
        ) -join "`n")

    # =====================================================================
    # A proxy log (Squid format) with LLM traffic from the office network
    # =====================================================================
    $proxyLog = Join-FakePath $Root 'proxy' 'access.log'
    Write-Fake $proxyLog (@(
            '1761400000.101    250 10.0.0.42 TCP_TUNNEL/200 5234 CONNECT api.openai.com:443 - HIER_DIRECT/162.159.140.245 -',
            '1761400001.202    180 10.0.0.42 TCP_TUNNEL/200 1200 CONNECT api.openai.com:443 - HIER_DIRECT/162.159.140.245 -',
            '1761400002.303    210 10.0.0.50 TCP_TUNNEL/200 9100 CONNECT api.anthropic.com:443 - HIER_DIRECT/160.79.104.10 -',
            '1761400003.404     90 10.0.0.61 TCP_TUNNEL/200  800 CONNECT www.microsoft.com:443 - HIER_DIRECT/23.0.0.1 -',
            '1761400004.505    300 10.0.0.42 TCP_TUNNEL/200 4400 CONNECT api.groq.com:443 - HIER_DIRECT/104.18.2.2 -',
            '1761400005.606    300 10.0.0.42 TCP_TUNNEL/200 4400 CONNECT api.openai.com.evil.example:443 - HIER_DIRECT/203.0.113.9 -'
        ) -join "`n")

    # =====================================================================
    # Timestamps: each profile gets a default time, then specific overrides.
    # Directories are set too, so nothing carries the time the test ran.
    # =====================================================================
    $defaults = @{ $alice = $biz; $bob = $off1; $carol = $biz; (Join-FakePath $Root 'proxy') = $biz }
    foreach ($profilePath in $defaults.Keys) {
        foreach ($item in @(Get-ChildItem -LiteralPath $profilePath -Recurse -Force)) { $item.LastWriteTime = $defaults[$profilePath] }
    }
    foreach ($p in $times.Keys) { (Get-Item -LiteralPath $p -Force).LastWriteTime = $times[$p] }

    return [pscustomobject]@{
        Root               = $Root
        ProfilePaths       = @($alice, $bob, $carol)
        Alice              = $alice
        Bob                = $bob
        Carol              = $carol
        NativeHostManifest = $nativeHostManifest
        ProxyLog           = $proxyLog
        Secrets            = $secrets
        Now                = $now
        BusinessTime       = $biz
        OffHours           = @($off1, $off2, $off3)
        Old                = $old
    }
}
