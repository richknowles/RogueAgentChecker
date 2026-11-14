# Rogue Agent Checker: Architecture Notes (v0.1.0 MVP)

Rogue Agent Checker (RAC) is to agentic AI what RogueChecker is to DHCP: it
inventories every AI agent it can find on a machine, compares each one against
an allow-list of approved agents, and flags whatever isn't on the list. It
reports. It does not disable, block, or delete anything.

---

## 1. Design principles

| Principle | What it means in code |
|---|---|
| **Read-only** | No cmdlet that changes system state appears anywhere in the module. A Pester test parses every file and fails the build if one shows up. |
| **Local-only** | No network calls: no web requests, no DNS lookups, no reverse lookups. IP-to-hostname mapping uses the existing DNS client cache. A Pester test enforces this too. |
| **Evidence over verdicts** | Every finding carries the raw facts (path, PID, command line, timestamps, counts) that led to it, so an auditor can verify it without rerunning the tool. |
| **Explainable scoring** | Classification is a sum of named, weighted indicators against one threshold. The report shows the arithmetic. No black box. |
| **Secrets never leave the box, and never enter the report** | API keys are detected by *name* and *format*. Their values are never written anywhere. |
| **Least privilege** | Runs as a standard user. Elevation widens coverage but is never requested or performed. The report says what wasn't visible and why. |
| **Readable by a sysadmin** | Plain PowerShell, comment-heavy, no obfuscated one-liners, no runtime C# (`Add-Type`), no external modules. Works on Windows PowerShell 5.1 and PowerShell 7. |

---

## 2. Pipeline

```
 +----------------+    +--------------------+    +----------------+    +-----------------+
 |    SOURCES     | -> |     ANALYZERS      | -> |   CLASSIFIER   | -> |    REPORTER     |
 | read-only OS   |    | pure logic, one    |    | allow-list +   |    | HTML, CSV, JSON |
 | queries        |    | per breadcrumb     |    | weighted       |    | + scan log      |
 | (Sources.ps1)  |    | category           |    | indicators     |    | (Report.ps1)    |
 +----------------+    +--------------------+    +----------------+    +-----------------+
        ^                       ^                        ^
        |                       |                        |
   Pester mocks           signatures.json          allowlist.json/.csv
   replay fake systems    (what agents look like)  (what is approved)
```

1. **Sources** (`Private/Sources.ps1`) is the *only* file that queries the operating
   system: CIM/WMI, registry, event logs, TCP table, DNS cache, file system, Credential
   Manager target names. Every function returns plain objects with stable property names.
2. **Analyzers** (`Private/Analyze-*.ps1`) turn raw objects into *findings*. They contain
   no OS calls, only matching logic driven by `signatures.json`.
3. **Classifier** (`Private/Classify.ps1`) scores each finding, applies the allow-list,
   and assigns **Trusted / Unknown / Suspicious** with written reasons.
4. **Reporter** (`Private/Report.ps1`) writes the HTML (for managers and auditors), CSV
   (for Excel and SIEM import), JSON (for future GUI or VS Code tooling), and the scan log.

### Why the Sources seam matters

- **Auditing:** to learn everything RAC touches on a machine, read one file.
- **Testing:** Pester mocks the Sources functions and replays a fake system (fake
  processes, tasks, services, WMI subscriptions, connections, events). The whole
  pipeline runs on any OS, including the Linux build box this MVP was tested on.
- **Enforcement:** `Safety.Tests.ps1` fails if a system-query cmdlet
  (`Get-CimInstance`, `Get-WinEvent`, `Get-NetTCPConnection`, ...) appears outside
  `Sources.ps1`.

---

## 3. Module layout

```
RogueAgentChecker/                       repo root
|-- Start-RogueAgentScan.ps1             wrapper: run a scan, optional RMM exit codes
|-- README.md                            sysadmin guide
|-- docs/ARCHITECTURE.md                 this file
|-- RogueAgentChecker/                   the module (copy this folder to deploy)
|   |-- RogueAgentChecker.psd1           manifest (PS 5.1+, Desktop and Core)
|   |-- RogueAgentChecker.psm1           loader: dot-sources Private/ then Public/
|   |-- Data/
|   |   |-- signatures.json              agent catalog, LLM endpoints, secret formats, weights
|   |   |-- allowlist.example.json       starter allow-list (JSON)
|   |   `-- allowlist.example.csv        same idea, Excel-friendly
|   |-- Private/
|   |   |-- Core.ps1                     logging, coverage, redaction, finding factory, helpers
|   |   |-- Sources.ps1                  ALL operating-system reads (read-only)
|   |   |-- Signatures.ps1               load + match the signature catalog
|   |   |-- Analyze-Processes.ps1        1. agent processes, headless browsers, MCP servers
|   |   |-- Analyze-Network.ps1          2. LLM API connections, DNS cache, listeners, proxy logs
|   |   |-- Analyze-ConfigAndSecrets.ps1 3. config/memory/skills dirs, MCP configs, .env, env vars, packages
|   |   |-- Analyze-Persistence.ps1      4. tasks, services, Run keys, Startup, WMI subscriptions
|   |   |-- Analyze-Tokens.ps1           5. Credential Manager, token files, browser extensions, native hosts
|   |   |-- Analyze-Logs.ps1             6. transcripts, tool-call histories, 4104, Sysmon, 4688
|   |   |-- Analyze-Behavior.ps1         7. off-hours, cross-app reach, package installs, self-modification
|   |   |-- Classify.ps1                 allow-list matching + weighted scoring
|   |   `-- Report.ps1                   HTML / CSV / JSON writers
|   `-- Public/
|       |-- Invoke-RogueAgentScan.ps1    the scan
|       |-- Export-RacReport.ps1         (re)write report files from a scan result
|       |-- Import-RacAllowList.ps1      load + validate an allow-list (JSON or CSV)
|       |-- ConvertTo-RacAllowListEntry.ps1  draft an allow-list entry from a finding
|       `-- Get-RacSignature.ps1         show what the tool knows how to detect
`-- Tests/
    |-- RogueAgentChecker.Tests.ps1      end-to-end detection + classification on a fake system
    |-- Safety.Tests.ps1                 read-only, no-egress, no-secret-leak, PS 5.1-compat proofs
    |-- Integration.Windows.Tests.ps1    opt-in: real fake process + real fake scheduled task
    `-- Fixtures/
        |-- FakeSystem.ps1               fake processes, tasks, services, WMI, net, events, ...
        |-- New-RacFakeAgentEnvironment.ps1  builds fake user profiles with fake agent dirs and fake keys
        `-- allowlist.fixture.json       allow-list used by the tests
```

---

## 4. The Finding object

| Field | Example | Notes |
|---|---|---|
| `FindingId` | `RAC-0007` | Stable within one report |
| `Classification` | `Suspicious` | Trusted / Unknown / Suspicious |
| `Score` | `55` | Sum of indicator weights (after allow-list exemptions) |
| `Category` | `Persistence` | One of the 7 breadcrumb categories |
| `Breadcrumb` | `WmiSubscription` | Specific detector |
| `Agent` / `AgentId` | `OpenClaw` / `openclaw` | From signatures; `Unidentified ...` when generic |
| `Title` | One-line summary | |
| `User` | `CORP\bob` | Owner, when knowable |
| `Location` | path, PID, registry key, WMI consumer | Where to look |
| `EventTime` | `2026-10-25 03:05` | When the artifact was created/active |
| `Evidence` | ordered key/value pairs | Redacted. Never contains secret values |
| `Indicators` | `PersistenceWmi, OffHoursActivity` | Named risk signals |
| `Reasons` | text | Why it got its label, including allow-list match/miss |
| `AllowListEntry` | `Claude Code - Engineering` | Which approval matched, if any |
| `Recommendation` | text | Next step for the admin |

Internal-only fields (`ActivityTimes`, `AppCategories`, `Signals`) feed the behavior
analyzer and are not written to the CSV.

---

## 5. Detection catalog (`Data/signatures.json`)

Detection content is data, not code, so an admin can add an agent without touching
PowerShell. Each agent entry can declare:

- `processes`: rules of `{ name, path?, commandLine? }` (regex on normalized text)
- `commandLinePatterns`: regex on normalized command lines (lowercase, `\` -> `/`)
- `keywords`: regex used against task/service/credential/registry names
- `configPaths`, `skillPaths`, `tokenFiles`, `logPaths`, `mcpConfigFiles`: path templates
  using `~`, `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%` (expanded *per profile*, so one
  scan covers every user profile it can read)
- `packages`: npm / PyPI package names (checked in npm global, pipx, uv tools, site-packages)
- `credentialTargets`: Credential Manager target-name regex
- `endpoints`: LLM API hostnames the agent normally talks to

Global sections: `llmEndpoints` (provider host patterns), `localServicePorts` (Ollama
11434, LM Studio 1234, OpenClaw 18789, CDP 9222), `genericPatterns` (MCP, headless
browser, agent framework, package install, stealth launch), `secretPatterns` (key
*formats*, used for detection and redaction), `secretEnvNamePattern`,
`mcpAppCategories`, `aiKeywordPattern`, and `scoring` (weights + threshold).

The shipped catalog is a **starter set** (Claude Desktop, Claude Code, Codex CLI,
ChatGPT, Gemini CLI, GitHub Copilot + VS Code MCP, Cursor, Windsurf, Cline, Roo Code,
Continue, Aider, OpenClaw (incl. legacy Clawdbot/Moltbot), Goose, OpenCode, Kiro/Amazon Q,
Ollama, LM Studio, n8n, Perplexity Comet, Microsoft Copilot, Python agent frameworks).
Vendors move files around. Treat it as living content.

---

## 6. Category design

| # | Category | Sources | Key logic | Example indicators |
|---|---|---|---|---|
| 1 | **Processes** | `Win32_Process` (cmdline, parent, start time), owner | Signature match on name/path/cmdline; generic MCP / headless / framework patterns; skip Chromium child processes (`--type=`); walk parent chain to attribute MCP servers and headless browsers to the agent that spawned them | `LongRunning`, `RemoteDebuggingPort`, `UserWritableExecPath`, `StealthLaunch`, `SystemContext` |
| 2 | **Network** | `Get-NetTCPConnection` (netstat fallback), `Get-DnsClientCache`, optional proxy logs | Remote IP -> hostname via DNS cache only (no lookups); LLM endpoint match; listener check on local agent/model ports; optional multi-sample persistence | `LlmFromNonAgentProcess`, `PersistentLlmConnection`, `ListensOnAllInterfaces`, `RemoteClientOnAgentPort` |
| 3 | **Config and secrets** | File system per profile, `HKLM`/`HKU` Environment (names only) | Agent config/memory/skills dirs; MCP server inventory from JSON/JSONC/TOML/YAML configs; `.env` key *names* and key *formats*; machine/user env var *names*; installed agent packages | `SecretInPlaintext`, `SecretWorldReadable`, `MachineWideSecret`, `ShellCapableMcp`, `RemoteMcpServer`, `UnpinnedPackage` |
| 4 | **Persistence** | Scheduled tasks, services, Run/RunOnce (HKLM + loaded HKU hives), Startup folders (.lnk resolved), `root\subscription` WMI | Same signature matching applied to each autostart command; every command-line/script WMI consumer is reported | `PersistenceAutostart`, `PersistenceWmi`, `HiddenTask`, `StealthLaunch`, `SystemContext` |
| 5 | **Tokens and OAuth** | `cmdkey /list` (target names only), token file presence, browser extension manifests, native messaging hosts | Name match only; token files reported by path/size/time, never opened | `StoredOAuthToken`, `BrowserControlPermission`, `BrowserControlBridge`, `SecretWorldReadable` |
| 6 | **Logs and events** | Agent log/transcript dirs, PowerShell 4104 (5.1 and 7 logs), Sysmon 1/3/11/22, Security 4688 | File counts, sizes, time ranges, tool-call *counts* (content never kept); event pattern match with short redacted snippets | `LlmCallFromScript`, `AgentSpawnedShell` |
| 7 | **Behavior** | Derived from everything above | Off-hours activity per agent; cross-app reach of one agent identity (MCP categories, "lethal trifecta" of private data + untrusted input + outbound channel); agent-driven package installs; recent writes to an agent's own skills/memory | `OffHoursActivity`, `CrossAppReach`, `LethalTrifecta`, `AgentInstallsPackages`, `SelfModification` |

---

## 7. Classification

```
score       = sum(weight of each distinct indicator on the finding)
entry       = first allow-list entry that matches the finding and is not expired

if entry:
    residual = score - sum(weights of indicators the entry explicitly accepts)
    label    = Suspicious if residual >= threshold else Trusted
else:
    label    = Suspicious if score >= threshold else Unknown
```

- Default threshold: **40** (tunable in `signatures.json`).
- **Not on the allow-list means flagged, never blocked.** At minimum it's Unknown.
- **Approval is not a blank check.** An approved agent that shows a risky indicator
  the entry doesn't accept (for example, Ollama bound to `0.0.0.0`) is still Suspicious,
  with the reason "Approved agent, but ...".
- Allow-list entries can be scoped by `Agent`, `Users`, `Computers`, `PathPattern`,
  `Categories`, `Breadcrumbs`, `McpServers`, `Endpoints`, and can accept specific
  `AllowedIndicators`. Each entry carries `ApprovedBy`, `ApprovedOn`, `Expires`, `Ticket`.
- Validation on import: an entry with `Agent: "*"` must be narrowed by `Categories` or
  `Breadcrumbs`, or it's rejected (prevents a one-line "approve everything").
  Expired entries never match, and the reason is recorded on the finding.
- The report records the SHA-256 of the allow-list and signature files used, so a
  finding can be tied to the exact policy version that produced it.

---

## 8. Secrets handling: three layers

1. **Never read.** Environment variable *values*, Credential Manager secrets, and
   token file *contents* are never accessed. RAC reads env var names from the registry
   with `GetValueNames()`, and Credential Manager target names with `cmdkey /list`.
2. **Read, never retained.** `.env` and config files are parsed in memory for key
   *names* (`OPENAI_API_KEY`) and value *formats* (looks like an Anthropic key). The
   value is discarded on the spot. Evidence records `name`, `format`, `line number`.
3. **Redacted at every boundary.** Command lines, script blocks, WMI consumer
   commands, and log messages pass through `Protect-RacText` (format regexes plus
   generic `key=`/`token:`/`Bearer` rules). The reporter runs a second redaction pass
   over every string before writing.

**Proof:** the test fixtures plant fake keys in a `.env` file, a process command line,
an MCP `env` block, a WMI consumer, and a 4104 script block. `Safety.Tests.ps1` asserts
none of them appear in the HTML, CSV, JSON, or scan log, and that the redaction
markers *do* appear.

---

## 9. Safety guarantees and how they are enforced

| Guarantee | Mechanism | Test |
|---|---|---|
| No system changes | Only read cmdlets used; WMI method use limited to `Win32_Process.GetOwner` | AST scan for a deny-list of state-changing commands |
| No network egress | No web/DNS/socket APIs; hostname mapping from local DNS cache | AST + type-name scan for a deny-list of network APIs |
| Writes only to the report folder | `New-Item`/`Add-Content`/`Set-Content`/`Export-Csv` only in `Core.ps1` (log) and `Report.ps1` | AST scan by file |
| OS queries are auditable in one place | System-query cmdlets only in `Sources.ps1` | AST scan by file |
| No secrets in output | Three-layer handling (section 8) | Planted fake keys never appear in any output |
| Runs on Windows PowerShell 5.1 | ASCII-only source (5.1 reads BOM-less files as ANSI), no PS7-only syntax | ASCII check + PSScriptAnalyzer `PSUseCompatibleSyntax` (5.1) |
| Every action logged | `Write-RacLog` on every source query, skip, error, and file written | Log contents asserted in tests |

Things RAC deliberately avoids: `Add-Type` (runtime compilation), `Invoke-Expression`,
`Start-Process`, `reg load` of offline hives (a write), reverse DNS, SID-to-name
translation (can query a domain controller). Authenticode checks are opt-in
(`-CheckSignatures`) because Windows may perform an online revocation check.

---

## 10. Privilege model and coverage

RAC never elevates. What changes with elevation:

| Data | Standard user | Elevated |
|---|---|---|
| Other users' process command lines | Not visible | Visible |
| Other users' profiles (configs, .env, transcripts) | Usually access denied | Readable |
| Security log (4688), often Sysmon log | Access denied | Readable |
| WMI `root\subscription` | Usually denied | Readable |
| Run keys of users not logged on | Not loaded (never loaded by RAC) | Not loaded |

Every source records a coverage row (`Checked` / `Partial` / `Skipped` / `Error`, item
count, reason). The report's **Coverage** section tells the auditor what *wasn't*
examined, so "no findings" is never confused with "didn't look".

---

## 11. Performance caps (defaults)

| Cap | Default | Parameter |
|---|---|---|
| Event log lookback | 7 days | `-LookbackDays` |
| Events per log query | 5,000 | `-MaxEventsPerLog` |
| Transcript file read for tool-call counting | 5 MB per file | (constant) |
| Files enumerated per log directory | 5,000 | (constant) |
| `.env` search depth under search roots | 4 | (constant) |
| Proxy log lines | 2,000,000 per file | (constant) |
| Network samples | 1 | `-NetworkSamples`, `-SampleIntervalSeconds` |

---

## 12. Known limitations (v0.1)

- Local machine only. Fleet scanning is a wrapper concern (see roadmap).
- Signature-driven plus generic patterns: a fully custom agent with no MCP, no known
  framework, and no LLM endpoint in DNS cache can slip through. Sysmon closes much of
  that gap.
- Network attribution depends on the DNS cache. Entries expire (TTL), so a quiet agent
  may show no network finding. Sysmon Event 22 gives durable per-process DNS history.
- Tenant-side OAuth grants (Entra ID enterprise apps, Google Workspace third-party
  access) are not visible from an endpoint.
- Agents running inside WSL2, Docker, or a VM are only visible from the Windows side
  (their listener ports and outbound connections), not by their files.
- Credential Manager targets are parsed from `cmdkey /list` by the `target=` token.
  Behavior on non-English Windows has not been verified.

---

## 13. Roadmap and extension points

- **v0.2 fleet mode:** `Invoke-Command -FilePath` fan-out over WinRM, or deploy via
  RMM (Tactical RMM / POTA4 script check). `Start-RogueAgentScan.ps1 -RmmMode` already
  returns exit codes (0 clean, 1 Unknown, 2 Suspicious) for RMM check status.
- **v0.3 actions (opt-in, separate module):** `RogueAgentChecker.Actions` consumes
  finding IDs from a JSON report. Each action is per-item, uses
  `SupportsShouldProcess` with `ConfirmImpact = 'High'`, captures evidence first, logs
  before and after, and prefers reversible containment (disable task, stop service)
  over deletion. Never imported by the scanner.
- **GUI / VS Code extension:** consume the JSON report schema
  (`Invoke-RogueAgentScan -PassThru -NoReport | ConvertTo-Json -Depth 6`). The core
  stays PowerShell.
- **Signature updates:** `signatures.json` is versioned; a signed signature feed is a
  later option, but RAC itself never downloads anything.
