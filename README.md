# Rogue Agent Checker

**Find the AI agents nobody told you about.**

Rogue Agent Checker (RAC) is RogueChecker for agentic AI. RogueChecker finds DHCP
servers that aren't on your authorized list. RAC finds AI agents (Claude Code,
OpenClaw, Codex, Copilot agent mode, MCP servers, homemade Python bots) that aren't
on your approved list. It shows you where each one is and what it can reach, and
hands you a report you can give to a manager or an auditor.

It is plain PowerShell. There is no binary to trust, nothing to install, and
nothing leaves the machine. Version 0.1 is **report-only**: it never disables,
blocks, or deletes anything.

```
Windows PowerShell 5.1 or PowerShell 7  |  no external modules  |  read-only  |  local-only
```

---

## Quick start

```powershell
# 1. Copy the RogueAgentChecker folder to the machine. If it came from the internet,
#    unblock it first (Windows marks downloaded scripts):
Get-ChildItem -Recurse .\RogueAgentChecker | Unblock-File

# 2. Start from the example allow-list and edit it for your environment:
Copy-Item .\RogueAgentChecker\RogueAgentChecker\Data\allowlist.example.json .\RogueAgentChecker\allowlist.json

# 3. Run it. A standard user account works; an elevated session sees more (see Coverage below).
.\RogueAgentChecker\Start-RogueAgentScan.ps1
```

If execution policy blocks the script, run it for this one process only:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RogueAgentChecker\Start-RogueAgentScan.ps1
```

As a module:

```powershell
Import-Module .\RogueAgentChecker\RogueAgentChecker\RogueAgentChecker.psd1
Invoke-RogueAgentScan -AllowListPath .\allowlist.json -OutputPath C:\RAC\Reports
```

See `docs/sample-report/sample-report.html` for a full report, generated from the
fake test machine described under *Tests*.

You get four files in the output folder:

| File | For |
|---|---|
| `RogueAgentReport_<PC>_<time>.html` | The report. Opens offline, prints cleanly, no external resources. |
| `..._findings.csv` | One row per finding, for Excel or your SIEM. |
| `....json` | The full result, for tooling. |
| `..._scan.log` | Every step the scan took, timestamped. Secrets redacted. |

---

## What it finds

Every finding carries evidence: where it is, when it was active, what matched, and why.

| # | Category | What RAC looks at | Examples of what it catches |
|---|---|---|---|
| 1 | **Processes** | Process table with command lines, parents, start times | A Claude Code or OpenClaw process up for 3 days. A `node.exe` MCP server, and which agent launched it. Chrome running `--headless --remote-debugging-port`. A CrewAI bot running from Downloads. |
| 2 | **Network** | TCP connections, the local DNS cache, optional proxy logs | A hidden SYSTEM PowerShell talking to `api.openai.com`. Ollama listening on `0.0.0.0` with a LAN client attached. Recent lookups of Gemini, Anthropic, Groq and 40 other LLM endpoints. |
| 3 | **Config, memory and secrets** | Agent folders in every readable profile, MCP configs, `.env` files, environment variable names, installed packages, IDE extensions | `~/.openclaw` with skills and `MEMORY.md`. Every MCP server in Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Codex, Gemini CLI, Continue, Cline, Roo. A `GROQ_API_KEY` in a world-readable `.env`. An AI key set machine-wide. |
| 4 | **Persistence** | Scheduled tasks, services, Run/RunOnce keys, Startup folders, WMI event subscriptions | An "OpenClaw Gateway" logon task. A hidden SYSTEM task launching an MCP server. n8n running as LocalSystem. A WMI consumer that keeps an agent alive. |
| 5 | **Tokens and OAuth** | Credential Manager target names, agent token files, browser extensions, native messaging hosts | Codex `auth.json` and Gemini OAuth files (by presence only). The Claude browser extension with `debugger` permission and the native host it talks to. |
| 6 | **Logs and events** | Agent transcripts and logs, PowerShell 4104, Sysmon 1/3/11/22, Security 4688 | "312 tool-call records in 14 session files, newest Sunday 02:41." A script block calling an LLM API. Which process looked up `api.anthropic.com`. |
| 7 | **Behavior** | Derived from all of the above | Agent activity at 2 a.m. One agent wired into email + chat + files + shell (the "lethal trifecta": private data, untrusted input, outbound channel). An agent installing npm packages by itself. An agent rewriting its own skills. |

The detection catalog is `Data\signatures.json`. It covers 22 agents and platforms,
41 LLM endpoint patterns, 14 key formats, and the generic patterns for MCP servers,
headless browsers and agent frameworks. Run `Get-RacSignature` to list the agents.

## What it does *not* find

Be clear about these before you call a machine clean:

- **Other machines.** v0.1 scans the machine it runs on. For a fleet, see *Running at scale*.
- **Tenant-side OAuth grants.** Consents granted to AI apps in Entra ID or Google
  Workspace live in the cloud, not on the endpoint. Review them in the admin consoles.
- **Agents inside WSL2, Docker or a VM.** RAC sees their ports and connections from
  the Windows side, not their files.
- **Quiet network history without Sysmon.** The DNS cache only holds recent lookups.
  Sysmon Event 22 gives durable per-process DNS history, and RAC uses it when present.
- **Brand-new or fully custom agents** that use no known product, framework, MCP
  pattern, or LLM endpoint. Add them to `signatures.json`.
- **Other users' data when not elevated.** See Coverage.
- **Users who are not logged on**, for Run keys and environment variables. RAC never
  loads offline registry hives, because loading one is a write.

The report's **Coverage** section lists every source as Checked, Partial, Skipped or
Error, with the reason. "Nothing found" only means something for sources marked Checked.

---

## How findings are labeled

| Label | Meaning |
|---|---|
| **Trusted** | Matches an allow-list entry, and any remaining risk is below the threshold. |
| **Unknown** | Not on the allow-list. Someone needs to decide: approve it or remove it. |
| **Suspicious** | Risk score at or above the threshold (default 40), whether approved or not. |

Each finding gets a score from named indicators, for example `+50 PersistenceWmi`,
`+40 StealthLaunch`, `+35 ListensOnAllInterfaces`, `+30 LethalTrifecta`, `+15
SecretInPlaintext`. The report lists the arithmetic for every finding. Weights and the
threshold are in `signatures.json` under `scoring`.

Two rules matter most:

1. **Not on the list means flagged, never blocked.** At minimum it's Unknown.
2. **Approval is not a blank check.** An allow-list entry only cancels the indicators
   it explicitly accepts in `AllowedIndicators`. An approved Ollama that is suddenly
   listening on every network interface is still Suspicious.

---

## The allow-list

JSON (comments allowed) or CSV. Start from `Data\allowlist.example.json` or
`Data\allowlist.example.csv`.

```jsonc
{
  "entries": [
    {
      "Name": "Claude Code - Engineering team",
      "Agent": "claude-code",                      // id from Get-RacSignature, a name, a wildcard, or "*"
      "Users": [ "jsmith", "adeleon" ],            // optional scope; every scope you set must match
      "Endpoints": [ "api.anthropic.com" ],        // approved API hosts for network findings
      "McpServers": [ "github", "filesystem" ],    // approved MCP server names
      "AllowedIndicators": [ "LongRunning" ],      // risks accepted by design
      "ApprovedBy": "IT Security (Jane Admin)",
      "ApprovedOn": "2026-10-01",
      "Expires": "2027-04-01",                     // stops matching on this date
      "Ticket": "CHG-1042"
    }
  ]
}
```

| Field | Notes |
|---|---|
| `Agent` | Required. `"*"` is only accepted when `Categories` or `Breadcrumbs` narrow it, so nobody can approve everything in one line. |
| `Users`, `Computers`, `PathPattern` | Wildcards allowed. `alice` matches `CORP\alice`. |
| `Categories`, `Breadcrumbs` | Limit the entry to some kinds of findings, for example `"Breadcrumbs": ["DnsCacheLlm"]`. |
| `McpServers` | Only these MCP servers are covered. Others under the same agent stay flagged. |
| `Endpoints` | For network findings: only these hosts are covered. |
| `AllowedIndicators` | Risk indicators you accept for this agent. Anything not listed still counts. |
| `ApprovedBy`, `ApprovedOn`, `Expires`, `Ticket`, `Notes` | Audit trail. The report records the allow-list's SHA-256. |

Check an allow-list before deploying it:

```powershell
Import-RacAllowList -Path .\allowlist.json     # prints warnings: missing approver, bad dates, unknown indicators
```

Approving something you found doesn't need typing from scratch:

```powershell
$scan = Invoke-RogueAgentScan -AllowListPath .\allowlist.json -PassThru
$scan.Findings | Where-Object { $_.Agent -eq 'Claude Code' -and $_.User -like '*jsmith*' } |
    ConvertTo-RacAllowListEntry -ApprovedBy 'IT Security (Jane Admin)' -Ticket CHG-1050 -AsJson
```

It prints a draft entry scoped to that agent and user, with a 90-day expiry. Review it,
then paste it into your allow-list. Nothing is written for you.

---

## Acting on a report

Work top to bottom. The report's **What to do next** box is generated in this order.

**1. Suspicious findings: treat as possible incidents.**
- Confirm with the user or owner shown on the finding. A sanctioned tool set up badly
  is the common case; a rogue agent is the case you can't afford to miss.
- **Preserve evidence before removing anything.** Keep the report and the JSON. For a
  live process, capture it first (for example a memory dump with your EDR or Sysinternals).
- Contain it through your normal incident process. RAC v0.1 deliberately doesn't do this for you.
- **Rotate any key or token** the report shows on that machine, at the provider. Moving
  a leaked key is not enough.
- Specific playbooks are in each finding's *Recommended next step*. For example, the
  WMI-persistence recommendation explains how to capture the consumer before removing it.

**2. Unknown findings: get an owner decision.**
- Ask the user what the agent is for and who approved it.
- If it's approved, add an allow-list entry with an approver and an expiry.
- If not, schedule removal through change control.

**3. Trusted findings: nothing to do now.** Re-validate before each approval expires.

**4. Coverage gaps.** If sources were Skipped or Partial, rerun elevated before signing
off on the machine.

**5. File the report with the ticket and rescan after changes.** The before/after pair
is your evidence that the issue was closed.

### Coverage by privilege

RAC never elevates itself. What elevation adds:

| Data | Standard user | Elevated |
|---|---|---|
| Other users' process command lines | hidden | visible |
| Other users' profiles (configs, `.env`, transcripts) | usually denied | readable |
| Security log (4688), Sysmon log | usually denied | readable |
| WMI event subscriptions | usually denied | readable |
| Credential Manager | current user only | current user only |

---

## Safety guarantees, and how to check them yourself

| Promise | How you can verify it |
|---|---|
| **Read-only.** Nothing is changed, stopped, deleted or disabled. | `Tests\Safety.Tests.ps1` parses every file and fails if any state-changing command (`Stop-Process`, `Remove-Item`, `Set-ItemProperty`, `Unregister-ScheduledTask`, `Start-Process`, `Invoke-Expression`, `Add-Type`, and about 60 more) appears. The one WMI method used is `Win32_Process.GetOwner`. |
| **Local-only.** No network calls. | The same tests ban web, DNS, socket and mail commands and .NET networking types. Hostnames come from the existing DNS cache; RAC never resolves anything. |
| **One place to audit.** | Every OS query is in `Private\Sources.ps1`, and a test enforces that. File writes happen only in the logging and report code. |
| **Secrets never land in a report.** | Keys are detected by name and format; values are never stored. Command lines, configs and script snippets are redacted. The tests plant fake keys in a `.env`, a process command line, an MCP config, a WMI consumer and a PowerShell script block, then assert that neither the keys nor *fragments* of them appear in the HTML, CSV, JSON or log. |
| **Every action is logged.** | The `_scan.log` records each source read, skip, error, finding and file written. |
| **Runs on Windows PowerShell 5.1.** | ASCII-only source (5.1 misreads BOM-less UTF-8), plus PSScriptAnalyzer's 5.1 syntax and command checks in the test suite. |

Two things RAC can't promise for Windows itself:

- With `-CheckSignatures`, Windows may contact a certificate authority to check
  revocation. That's why the switch is off by default.
- Looking up a process owner can make Windows consult a domain controller, the same
  as Task Manager does.

Reading a file can update its last-access time if NTFS last-access tracking is turned
on. For a forensic case, image the disk first.

---

## Running at scale

v0.1 is a local scanner. To cover a fleet today, push the folder with your RMM
(Tactical RMM, NinjaOne, Datto, ConnectWise) or a GPO scheduled task, and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-RogueAgentScan.ps1 -OutputPath C:\ProgramData\RogueAgentChecker -RmmMode
```

`-RmmMode` prints one line and exits with a code your RMM check can alert on:

| Exit | Meaning |
|---|---|
| 0 | Nothing unapproved |
| 1 | Unknown items only (need an owner decision) |
| 2 | At least one Suspicious finding |
| 3 | The scan failed |

Collect the JSON files centrally to build a fleet view.

## Parameters (Invoke-RogueAgentScan)

| Parameter | Default | Purpose |
|---|---|---|
| `-OutputPath` | `.\RogueAgentReports` | Where the report and log go |
| `-AllowListPath` | none | JSON or CSV allow-list. Without one, nothing can be Trusted. |
| `-ProfileRoot` | all readable profiles | Limit to specific profile folders |
| `-SearchRoot` | none | Extra folders to search for `.env`, project MCP configs, transcripts (for example `D:\Source`) |
| `-ProxyLogPath` | none | Proxy log files or folders to scan for LLM hosts |
| `-LookbackDays` | 7 | Window for event logs, recent changes, off-hours analysis |
| `-BusinessHoursStart` / `-BusinessHoursEnd` / `-BusinessDays` | 7 / 19 / Mon-Fri | Defines off-hours |
| `-LongRunningHours` | 8 | Uptime that counts as long-running |
| `-NetworkSamples` / `-SampleIntervalSeconds` | 1 / 15 | Take several TCP snapshots to confirm persistent connections |
| `-MaxEventsPerLog` | 5000 | Cap per event-log query |
| `-Category` | all seven | Run only some categories |
| `-IncludeBrowserAiSessions` | off | Itemize ordinary browser use of ChatGPT, Claude, Gemini (counted but hidden by default) |
| `-CheckSignatures` | off | Record Authenticode signers (may trigger an OS revocation check) |
| `-NoReport` / `-PassThru` | off | Skip the report files / return the result object |

Project folders are searched to depth 4 under Desktop, Documents, Downloads, source,
src, dev, code, repos, projects, git, GitHub, workspace and work. `node_modules`,
`.git`, virtual environments and OneDrive are skipped. Cloud-only placeholder files
are never opened, because opening one triggers a download.

---

## Tests

The tests need **Pester 5 or later**. Windows ships with Pester 3.4, which is too old:

```powershell
Install-Module Pester -MinimumVersion 5.3 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser      # optional: enables the 5.1 compatibility test

Invoke-Pester -Path .\Tests -Output Detailed
```

| File | What it proves |
|---|---|
| `RogueAgentChecker.Tests.ps1` | Detection and classification across all 7 categories, against a **fake machine**: fake processes, connections, tasks, services, WMI subscriptions and events (`Fixtures\FakeSystem.ps1`), plus fake user profiles with fake agent folders, configs, transcripts and fake keys written to TestDrive (`Fixtures\New-RacFakeAgentEnvironment.ps1`). Nothing real is installed. |
| `Safety.Tests.ps1` | The guarantees above: read-only, local-only, auditable, no secret leaks (whole or partial), 5.1 compatible. |
| `Integration.Windows.Tests.ps1` | **Opt-in, Windows only.** Starts a harmless sleeping process that looks like an MCP server, and registers a *disabled* task in your account that looks like an OpenClaw gateway. Then it scans the real machine and removes both. Run with `$env:RAC_INTEGRATION = '1'`. |

The fake machine tells three stories. **alice** is a sanctioned developer whose
approved Claude Desktop has quietly been wired into Gmail, Slack and a shell.
**bob** runs a rogue OpenClaw that persists through WMI, rewrites its own skills and
works at 2 a.m. **carol** runs Codex, Aider and CrewAI from Downloads, with a
world-readable `.env`.

Verified so far: 105 tests pass on PowerShell 7.4 with Pester 5.7 and Pester 6.2.
Windows PowerShell 5.1 compatibility is checked statically. The suite has not yet
been run on a live Windows box; the integration tests exist for exactly that.

---

## Extending detection

Add an agent to `Data\signatures.json`; no code changes needed. Each entry can declare
process names and paths, command-line patterns, keywords, config, skill, token and log
locations (using `~`, `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`), MCP config files and
their format (`json`, `toml`, `yaml`), packages (npm, PyPI), IDE extension IDs,
Credential Manager targets, and the endpoints it normally uses. Order matters: the
first matching agent wins, so put specific entries before generic ones.

Architecture notes, design decisions and the roadmap are in `docs\ARCHITECTURE.md`.

## Requirements

- Windows 10/11 or Windows Server 2016+, with Windows PowerShell 5.1 or PowerShell 7.2+
- No modules beyond what ships with Windows (Pester and PSScriptAnalyzer for tests only)
- A standard user account; administrator for full coverage

## Roadmap

- **0.2:** fleet collection and a merged multi-machine report.
- **0.3:** optional actions in a *separate* module. Each action is per-item, confirmed
  (`-Confirm`, ConfirmImpact High), logged before and after, and captures evidence
  first. Containment (disable, stop) comes before deletion. The scanner never imports it.
- **Later:** GUI and VS Code extension on top of the JSON output. The PowerShell core stays.
