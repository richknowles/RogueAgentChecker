<#
    FakeSystem.ps1 - a FAKE Windows machine, expressed as the exact objects the
    Sources.ps1 functions return. Tests mock each Get-RacRaw* function with the
    matching list below, so the analyzers see fake processes, fake scheduled
    tasks, fake services, fake WMI subscriptions, fake connections and fake
    events - on any OS, with nothing installed.

    Read it as a story; the comments say what each item should produce.
#>

function Get-RacFakeSystem {
    param([Parameter(Mandatory = $true)]$Environment, [string]$RepoRoot = '')

    $e = $Environment
    $s = $e.Secrets
    $now = $e.Now
    $biz = $e.BusinessTime
    $off1, $off2, $off3 = $e.OffHours

    function New-FakeProcess($ProcessId, $ParentProcessId, $Name, $Path, $CommandLine, $Started, $Owner) {
        [pscustomobject]@{
            ProcessId = $ProcessId; ParentProcessId = $ParentProcessId; Name = $Name; ExecutablePath = $Path
            CommandLine = $CommandLine; CreationDate = $Started; Owner = $Owner
        }
    }
    function New-FakeTcp($LocalAddress, $LocalPort, $RemoteAddress, $RemotePort, $State, $ProcessId, $Created) {
        [pscustomobject]@{
            LocalAddress = $LocalAddress; LocalPort = $LocalPort; RemoteAddress = $RemoteAddress; RemotePort = $RemotePort
            State = $State; OwningProcess = $ProcessId; CreationTime = $Created
        }
    }
    function New-FakeEvent($LogName, $Id, $Time, [hashtable]$Data) {
        [pscustomobject]@{ LogName = $LogName; Id = $Id; TimeCreated = $Time; RecordId = Get-Random; Data = $Data }
    }

    # A real chunk of RAC's own test file, word for word, as Windows would log it
    # when ANOTHER copy of RAC runs its tests. It mentions api.openai.com, so it
    # would be reported if RAC did not recognize its own code.
    $ownChunk = ''
    if ($RepoRoot) {
        $ownText = [System.IO.File]::ReadAllText([System.IO.Path]::Combine($RepoRoot, 'Tests', 'RogueAgentChecker.Tests.ps1')).Replace("`r`n", "`n")
        $at = $ownText.IndexOf("Should -Be 'api.openai.com'")
        $ownChunk = $ownText.Substring([Math]::Max(0, $at - 400), 800).Replace("`n", "`r`n")
    }

    # 'powershell -EncodedCommand' takes Base64 of UTF-16LE text. Single quotes: $env stays literal.
    $encodedGroq = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('irm https://api.groq.com/openai/v1/models -Headers @{ Authorization = "Bearer $env:GROQ_API_KEY" }'))

    $node = 'C:\Program Files\nodejs\node.exe'
    $openclawCmd = '"C:\Program Files\nodejs\node.exe" C:\Users\bob\AppData\Roaming\npm\node_modules\openclaw\dist\index.js gateway --port 18789'

    [pscustomobject]@{

        # ---------------------------------------------------------------- processes
        Processes = @(
            New-FakeProcess 4 0 'System' '' '' $null 'NT AUTHORITY\SYSTEM'
            New-FakeProcess 800 600 'svchost.exe' 'C:\Windows\System32\svchost.exe' 'C:\Windows\system32\svchost.exe -k netsvcs -p' $now.AddDays(-5) 'NT AUTHORITY\SYSTEM'     # benign
            New-FakeProcess 801 700 'explorer.exe' 'C:\Windows\explorer.exe' 'C:\Windows\Explorer.EXE' $now.AddDays(-5) 'CORP\alice'                                         # benign
            New-FakeProcess 900 801 'chrome.exe' 'C:\Program Files\Google\Chrome\Application\chrome.exe' '"C:\Program Files\Google\Chrome\Application\chrome.exe"' $biz 'CORP\alice'   # ordinary browser
            New-FakeProcess 901 900 'chrome.exe' 'C:\Program Files\Google\Chrome\Application\chrome.exe' '"chrome.exe" --type=renderer --lang=en-US' $biz 'CORP\alice'             # renderer child: ignored
            New-FakeProcess 4100 801 'claude.exe' 'C:\Users\alice\AppData\Local\AnthropicClaude\app-1.0.1307\claude.exe' '"C:\Users\alice\AppData\Local\AnthropicClaude\app-1.0.1307\claude.exe"' $biz 'CORP\alice'   # Claude Desktop
            New-FakeProcess 4200 4100 'node.exe' $node 'node C:\Users\alice\AppData\Roaming\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js C:\Users\alice\Documents' $biz.AddMinutes(1) 'CORP\alice'   # MCP server launched by Claude Desktop
            New-FakeProcess 4300 801 'claude.exe' 'C:\Users\alice\.local\bin\claude.exe' 'claude.exe' $biz 'CORP\alice'                                                     # Claude Code (approved for alice)
            New-FakeProcess 7100 801 'ollama.exe' 'C:\Users\alice\AppData\Local\Programs\Ollama\ollama.exe' '"ollama.exe" serve' $biz.AddHours(-2) 'CORP\alice'          # Ollama (approved, but see network)
            New-FakeProcess 5000 700 'explorer.exe' 'C:\Windows\explorer.exe' 'C:\Windows\Explorer.EXE' $now.AddDays(-4) 'CORP\bob'
            New-FakeProcess 5100 5000 'node.exe' $node ($openclawCmd + ' --token ' + $s.Anthropic) $now.AddDays(-3) 'CORP\bob'                                         # OpenClaw gateway, 3 days up, key on the command line
            New-FakeProcess 5200 5100 'chrome.exe' 'C:\Users\bob\AppData\Local\ms-playwright\chromium-1187\chrome-win\chrome.exe' 'chrome.exe --headless=new --remote-debugging-port=9222 --user-data-dir=C:\Users\bob\AppData\Local\Temp\playwright_profile' $now.AddDays(-3).AddMinutes(5) 'CORP\bob'   # headless browser driven by OpenClaw
            New-FakeProcess 5201 5200 'chrome.exe' 'C:\Users\bob\AppData\Local\ms-playwright\chromium-1187\chrome-win\chrome.exe' 'chrome.exe --type=renderer --headless=new --remote-debugging-port=9222' $now.AddDays(-3).AddMinutes(5) 'CORP\bob'   # its renderer: ignored
            New-FakeProcess 6100 801 'python.exe' 'C:\Users\carol\Downloads\bot\.venv\Scripts\python.exe' ('python.exe -m crewai run --api-key=' + $s.Groq) $biz 'CORP\carol'   # CrewAI agent from Downloads
            New-FakeProcess 802 600 'powershell.exe' 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' 'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBSAGUAcwB0AE0AZQB0AGgAbwBkAA==' $now.AddMinutes(-40) 'NT AUTHORITY\SYSTEM'   # hidden SYSTEM PowerShell (see network)
            New-FakeProcess 6600 800 'powershell.exe' 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' ('"powershell.exe" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $e.RogueScript + '"') $now.AddMinutes(-70) 'CORP\bob'   # the live test's rogue: no open connection RAC can name, but its script calls OpenAI
            New-FakeProcess 6700 700 'python.exe' 'C:\Python312\python.exe' ('python.exe "' + $e.SdkScript + '" --once') $biz 'CORP\carol'   # visible script using the OpenAI SDK
            New-FakeProcess 6800 801 'powershell.exe' 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' ('powershell.exe -NoProfile -File "' + $e.PlainScript + '"') $biz 'CORP\alice'   # ordinary script: ignored
        )

        # ---------------------------------------------------------------- network
        DnsCache = @(
            [pscustomobject]@{ Entry = 'api.anthropic.com'; Name = 'api.anthropic.com'; Type = '1'; Data = '160.79.104.10'; TimeToLive = 120 }
            [pscustomobject]@{ Entry = 'api.openai.com'; Name = 'api.openai.com'; Type = '5'; Data = 'api.openai.com.cdn.cloudflare.net'; TimeToLive = 120 }
            [pscustomobject]@{ Entry = 'api.openai.com'; Name = 'api.openai.com.cdn.cloudflare.net'; Type = '1'; Data = '162.159.140.245'; TimeToLive = 120 }
            [pscustomobject]@{ Entry = 'chatgpt.com'; Name = 'chatgpt.com'; Type = '1'; Data = '104.18.32.47'; TimeToLive = 120 }
            [pscustomobject]@{ Entry = 'claude.ai'; Name = 'claude.ai'; Type = '1'; Data = '160.79.104.20'; TimeToLive = 120 }               # DNS only, approved provider
            [pscustomobject]@{ Entry = 'generativelanguage.googleapis.com'; Name = 'generativelanguage.googleapis.com'; Type = '1'; Data = '142.250.72.10'; TimeToLive = 120 }   # DNS only, not approved
            [pscustomobject]@{ Entry = 'www.microsoft.com'; Name = 'www.microsoft.com'; Type = '1'; Data = '23.0.0.1'; TimeToLive = 120 }
        )
        TcpConnections = @(
            New-FakeTcp '10.0.0.50' 50001 '160.79.104.10' 443 'Established' 4300 $biz.AddHours(1)            # Claude Code -> Anthropic (approved)
            New-FakeTcp '10.0.0.50' 50002 '162.159.140.245' 443 'Established' 802 $now.AddMinutes(-35)       # hidden SYSTEM PowerShell -> OpenAI
            New-FakeTcp '10.0.0.50' 50003 '160.79.104.10' 443 'Established' 5100 $now.AddHours(-26)          # OpenClaw -> Anthropic, open for a day
            New-FakeTcp '10.0.0.50' 50004 '104.18.32.47' 443 'Established' 900 $now.AddMinutes(-5)           # ordinary browser -> chatgpt.com (not itemized)
            New-FakeTcp '0.0.0.0' 11434 '0.0.0.0' 0 'Listen' 7100 $biz                                       # Ollama on ALL interfaces
            New-FakeTcp '::' 11434 '::' 0 'Listen' 7100 $biz
            New-FakeTcp '10.0.0.50' 11434 '10.0.0.77' 51515 'Established' 7100 $now.AddMinutes(-3)           # ...and another machine is using it
            New-FakeTcp '127.0.0.1' 18789 '0.0.0.0' 0 'Listen' 5100 $now.AddDays(-3)                          # OpenClaw gateway, loopback
            New-FakeTcp '127.0.0.1' 9222 '0.0.0.0' 0 'Listen' 5200 $now.AddDays(-3)                           # Chrome DevTools Protocol
            New-FakeTcp '0.0.0.0' 135 '0.0.0.0' 0 'Listen' 800 $now.AddDays(-5)                               # benign
        )

        # ---------------------------------------------------------------- persistence
        ScheduledTasks = @(
            [pscustomobject]@{
                TaskPath = '\'; TaskName = 'OpenClaw Gateway'; State = 'Ready'; Author = 'CORP\bob'; Description = ''
                UserId = 'CORP\bob'; RunLevel = 'Limited'; Hidden = $false; Triggers = @('Logon'); RegistrationDate = $now.AddDays(-3).ToString('s')
                Actions = @([pscustomobject]@{ Execute = $node; Arguments = 'C:\Users\bob\AppData\Roaming\npm\node_modules\openclaw\dist\index.js gateway --port 18789'; WorkingDirectory = '' })
            }
            [pscustomobject]@{
                # Hidden, but otherwise low risk: HiddenTask must stay its own indicator (v0.1.0 glued it onto PersistenceAutostart)
                TaskPath = '\'; TaskName = 'Codex Sync'; State = 'Ready'; Author = 'CORP\carol'; Description = ''
                UserId = 'CORP\carol'; RunLevel = 'Limited'; Hidden = $true; Triggers = @('Daily'); RegistrationDate = $now.AddDays(-2).ToString('s')
                Actions = @([pscustomobject]@{ Execute = 'C:\Users\carol\.codex\bin\codex.exe'; Arguments = 'exec "sync notes"'; WorkingDirectory = '' })
            }
            [pscustomobject]@{
                TaskPath = '\'; TaskName = 'SystemHealthUpdater'; State = 'Ready'; Author = ''; Description = 'Keeps the system healthy'
                UserId = 'SYSTEM'; RunLevel = 'Highest'; Hidden = $true; Triggers = @('Boot'); RegistrationDate = $now.AddDays(-1).ToString('s')
                Actions = @([pscustomobject]@{ Execute = 'powershell.exe'; Arguments = '-NoProfile -WindowStyle Hidden -Command "npx -y @modelcontextprotocol/server-everything"'; WorkingDirectory = '' })
            }
            [pscustomobject]@{
                # The live test's rogue task: nothing in the command names AI; the script it runs does
                TaskPath = '\'; TaskName = 'OneDrive Sync Helper'; State = 'Running'; Author = 'CORP\bob'; Description = ''
                UserId = 'CORP\bob'; RunLevel = 'Limited'; Hidden = $true; Triggers = @('Logon'); RegistrationDate = $now.AddDays(-1).ToString('s')
                Actions = @([pscustomobject]@{ Execute = 'powershell.exe'; Arguments = ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $e.RogueScript + '"'); WorkingDirectory = '' })
            }
            [pscustomobject]@{
                # An encoded command that calls Groq: RAC decodes it and reads it; nothing is run
                TaskPath = '\'; TaskName = 'Telemetry Refresh'; State = 'Ready'; Author = ''; Description = ''
                UserId = 'CORP\carol'; RunLevel = 'Limited'; Hidden = $false; Triggers = @('Daily'); RegistrationDate = $now.AddDays(-1).ToString('s')
                Actions = @([pscustomobject]@{ Execute = 'powershell.exe'; Arguments = ('-NoProfile -EncodedCommand ' + $encodedGroq); WorkingDirectory = '' })
            }
            [pscustomobject]@{
                # An ordinary script task: RAC reads the script, finds nothing about AI, reports nothing
                TaskPath = '\'; TaskName = 'Nightly Backup'; State = 'Ready'; Author = 'CORP\alice'; Description = ''
                UserId = 'CORP\alice'; RunLevel = 'Limited'; Hidden = $false; Triggers = @('Daily'); RegistrationDate = $now.AddDays(-30).ToString('s')
                Actions = @([pscustomobject]@{ Execute = 'powershell.exe'; Arguments = ('-NoProfile -File "' + $e.PlainScript + '"'); WorkingDirectory = '' })
            }
            [pscustomobject]@{
                TaskPath = '\Microsoft\Windows\Defrag\'; TaskName = 'ScheduledDefrag'; State = 'Ready'; Author = 'Microsoft Corporation'; Description = ''
                UserId = 'SYSTEM'; RunLevel = 'Highest'; Hidden = $false; Triggers = @('Time'); RegistrationDate = ''
                Actions = @([pscustomobject]@{ Execute = '%windir%\system32\defrag.exe'; Arguments = '-c -h -o -$'; WorkingDirectory = '' })
            }
        )
        ScheduledTaskRunInfo = [pscustomobject]@{ LastRunTime = $off1; NextRunTime = $now.AddDays(1); LastTaskResult = 0 }
        Services = @(
            [pscustomobject]@{ Name = 'Spooler'; DisplayName = 'Print Spooler'; PathName = 'C:\Windows\System32\spoolsv.exe'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem'; ProcessId = 1500 }
            [pscustomobject]@{ Name = 'n8n'; DisplayName = 'n8n Automation'; PathName = '"C:\Program Files\nodejs\node.exe" "C:\agents\n8n\node_modules\n8n\bin\n8n" start'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem'; ProcessId = 3100 }
        )
        RunKeys = @(
            [pscustomobject]@{ Hive = 'HKU\S-1-5-21-1-2-3-1001'; User = 'CORP\alice'; KeyPath = 'HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run'; ValueName = 'Claude'; Command = '"C:\Users\alice\AppData\Local\AnthropicClaude\claude.exe" --startup' }
            [pscustomobject]@{ Hive = 'HKLM'; User = ''; KeyPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; ValueName = 'SecurityHealth'; Command = '%windir%\system32\SecurityHealthSystray.exe' }
        )
        StartupItems = @(
            [pscustomobject]@{ User = 'alice'; Path = 'C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Ollama.lnk'; TargetPath = 'C:\Users\alice\AppData\Local\Programs\Ollama\ollama app.exe'; Arguments = ''; LastWriteTime = $biz.AddDays(-1) }
        )
        WmiSubscriptions = @(
            [pscustomobject]@{ Name = 'AgentKeepAlive'; ClassName = 'CommandLineEventConsumer'; CommandLine = ('cmd.exe /c start /min node C:\Users\bob\.openclaw\workspace\keepalive.js --token ' + $s.Anthropic); ScriptText = ''; FilterName = 'AgentKeepAliveFilter'; FilterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" }
            [pscustomobject]@{ Name = 'SCM Event Log Consumer'; ClassName = 'NTEventLogEventConsumer'; CommandLine = ''; ScriptText = ''; FilterName = 'SCM Event Log Filter'; FilterQuery = 'select * from MSFT_SCMEventLogEvent' }   # Windows default: ignored
        )

        # ---------------------------------------------------------------- secrets, tokens, browser bridges
        EnvironmentVariables = @(
            [pscustomobject]@{ Scope = 'Machine'; User = ''; Name = 'OPENAI_API_KEY' }        # every user and service inherits it
            [pscustomobject]@{ Scope = 'Machine'; User = ''; Name = 'PATH' }
            [pscustomobject]@{ Scope = 'User'; User = 'CORP\alice'; Name = 'ANTHROPIC_API_KEY' }
            [pscustomobject]@{ Scope = 'User'; User = 'CORP\carol'; Name = 'TEMP' }
        )
        CredentialTargets = @(
            [pscustomobject]@{ Target = 'Claude Code-credentials' }
            [pscustomobject]@{ Target = 'git:https://github.com' }
            [pscustomobject]@{ Target = 'virtualapp/didlogical' }
        )
        NativeMessagingHosts = @(
            [pscustomobject]@{ Browser = 'Chrome'; Scope = 'User'; User = 'CORP\alice'; HostName = 'com.anthropic.claude_browser_extension'; ManifestPath = $e.NativeHostManifest }
            [pscustomobject]@{ Browser = 'Edge'; Scope = 'Machine'; User = ''; HostName = 'com.microsoft.browsercore'; ManifestPath = '' }
        )

        # ---------------------------------------------------------------- event logs
        Events = @{
            'Microsoft-Windows-PowerShell/Operational' = @(
                New-FakeEvent 'Microsoft-Windows-PowerShell/Operational' 4104 $off1.AddMinutes(10) @{
                    ScriptBlockText = ('$h = @{ Authorization = "Bearer ' + $s.Bearer + '" }; Invoke-RestMethod -Uri "https://api.openai.com/v1/chat/completions" -Method Post -Headers $h -Body $body')
                    Path            = 'C:\Users\carol\Downloads\bot\ask-gpt.ps1'
                }
                New-FakeEvent 'Microsoft-Windows-PowerShell/Operational' 4104 $biz @{ ScriptBlockText = 'Get-ChildItem C:\temp'; Path = '' }   # ordinary: ignored
                New-FakeEvent 'Microsoft-Windows-PowerShell/Operational' 4104 $biz @{ ScriptBlockText = $ownChunk; Path = 'D:\Tools\RAC-old\RogueAgentChecker\Tests\RogueAgentChecker.Tests.ps1' }   # RAC's own code from ANOTHER copy: ignored by content
                New-FakeEvent 'Microsoft-Windows-PowerShell/Operational' 4104 $biz @{ ScriptBlockText = $ownChunk; Path = '' }   # RAC's own code, no path: ignored by content
                New-FakeEvent 'Microsoft-Windows-PowerShell/Operational' 4104 $off1.AddMinutes(12) @{
                    ScriptBlockText = ("function New-RacFinding { } # RacModuleRoot Invoke-RogueAgentScan`r`n" + 'Invoke-RestMethod -Uri "https://api.groq.com/openai/v1/chat/completions" -Method Post -Headers @{ Authorization = "Bearer $env:GROQ_API_KEY" } -Body $prompt')
                    Path            = 'C:\Users\bob\AppData\Local\Temp\RogueAgentChecker\Private\Core.ps1'
                }   # NOT RAC: a script hiding behind RAC's names and folder must still be reported
                New-FakeEvent 'Microsoft-Windows-PowerShell/Operational' 4104 $biz @{
                    ScriptBlockText = ("It 'flags OpenClaw' { `$f.Evidence['Remote host'] | Should -Be 'api.openai.com'; `$env:OPENAI_API_KEY }")
                    Path            = $(if ($RepoRoot) { [System.IO.Path]::Combine($RepoRoot, 'Tests', 'RogueAgentChecker.Tests.ps1') } else { '' })
                }   # a CHUNK of RAC's own test file (no marker text): must be ignored by path
            )
            'PowerShellCore/Operational' = @()
            'Microsoft-Windows-Sysmon/Operational' = @(
                New-FakeEvent 'Microsoft-Windows-Sysmon/Operational' 22 $off1 @{ Image = $node; QueryName = 'api.anthropic.com'; User = 'CORP\bob' }
                New-FakeEvent 'Microsoft-Windows-Sysmon/Operational' 22 $off2 @{ Image = $node; QueryName = 'api.anthropic.com'; User = 'CORP\bob' }
                New-FakeEvent 'Microsoft-Windows-Sysmon/Operational' 3 $off3 @{ Image = $node; DestinationHostname = 'api.anthropic.com'; DestinationIp = '160.79.104.10'; User = 'CORP\bob' }
                New-FakeEvent 'Microsoft-Windows-Sysmon/Operational' 22 $biz @{ Image = 'C:\Program Files\Google\Chrome\Application\chrome.exe'; QueryName = 'chatgpt.com'; User = 'CORP\alice' }   # ordinary browser: hidden
                New-FakeEvent 'Microsoft-Windows-Sysmon/Operational' 1 $off3.AddMinutes(2) @{
                    Image = 'C:\Windows\System32\cmd.exe'; CommandLine = 'cmd.exe /d /s /c "npm install -g left-padz"'
                    ParentImage = $node; ParentCommandLine = $openclawCmd; User = 'CORP\bob'
                }   # OpenClaw installs a package on its own, at 3 a.m.
                New-FakeEvent 'Microsoft-Windows-Sysmon/Operational' 1 $biz.AddMinutes(1) @{
                    Image = $node; CommandLine = 'node C:\Users\alice\AppData\Roaming\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js C:\Users\alice\Documents'
                    ParentImage = 'C:\Users\alice\AppData\Local\AnthropicClaude\app-1.0.1307\claude.exe'; ParentCommandLine = 'claude.exe'; User = 'CORP\alice'
                }   # Claude Desktop starting its MCP server
                New-FakeEvent 'Microsoft-Windows-Sysmon/Operational' 11 $off3 @{ Image = $node; TargetFilename = 'C:\Users\bob\.openclaw\workspace\skills\autoupdate\SKILL.md' }   # agent rewriting its own skill
            )
            'Security' = @()   # as if the Security log were not readable
        }
    }
}
