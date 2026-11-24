# Live test: a staged rogue agent and a real OpenClaw

**When:** 2026-11-23, about 16:30 to 17:50 local time.
**Where:** the Windows 11 25H2 test VM (build 26200), Windows PowerShell 5.1.
**What ran:** Rogue Agent Checker 0.1.1, release candidate 4 (zip SHA-256 `01BA8380...`),
with no allow-list, so every finding is Unknown, or Suspicious at a score of 40 or more.

We wrote down what RAC would find before the test. The predictions are reproduced
below unchanged, next to what happened. Where we were wrong, this says so.

## What we planted

**A rogue agent disguised as a OneDrive helper** (`Stage-RogueAgent.ps1`, test VM only,
with a fake key marked `RACTEST`):

- `%LOCALAPPDATA%\OneDriveSyncHelper\sync.ps1`, a script that calls
  `https://api.openai.com/v1/models` every 30 seconds for two hours, with the key from
  `$env:OPENAI_API_KEY`
- a **hidden** scheduled task, "OneDrive Sync Helper", that starts it at logon with
  `powershell.exe -WindowStyle Hidden`, started at once
- the key in a user environment variable, `OPENAI_API_KEY`
- a `.env` with the key, readable by Everyone, and a `.mcp.json` that gives an agent a
  shell (`npx -y mcp-shell-server`), in `Documents\projects\sync-helper`

**A real OpenClaw**, installed with its official installer
(`iwr -useb https://openclaw.ai/install.ps1 | iex`). The installer added Node.js and
the `openclaw` npm package (2026.11.7), and onboarding set up a gateway on
`127.0.0.1:18789` that starts from the Startup folder.

## The scans

| Run | Time | Window | Result | Note |
|---|---|---|---|---|
| 1 | 16:33, 16:36 | normal, admin | baseline | Before anything was planted |
| 1b | 17:08 | normal | baseline folder, by accident | Ran after the OpenClaw install; caught the installer (B7 below) |
| 2 | 17:12, 17:14 | admin, normal | 1 Suspicious, 17 Unknown | The main test |
| 3 | 17:33 | admin | 1 Suspicious, 17 Unknown | Retry for the network catch |
| 4 | 17:36 | admin | 1 Suspicious, 17 Unknown | After `Resolve-DnsName api.openai.com` |
| 5 | 17:47 | admin | **2 Suspicious**, 17 Unknown | After `[System.Net.Dns]::GetHostAddresses('api.openai.com')` |

No run reported a coverage error, and the fake key appears in none of the reports,
CSV files, JSON files or scan logs.

## Predictions and results

**The rogue (A).** The predictions assumed the test would run on a Saturday. It ran on
a Monday afternoon, inside business hours, so the off-hours predictions don't apply.

| # | What | Predicted (admin window) | Result | Verdict |
|---|---|---|---|---|
| A1 | `.env` with the key | Suspicious, 55 | Suspicious, 55: key name only, readable by Everyone | Correct |
| A2 | `.mcp.json` shell server | Unknown, 25, filed under Claude Code | Unknown, 25, filed under Claude Code | Correct |
| A3 | User variable `OPENAI_API_KEY` | Unknown, 0 | Unknown, 15: RAC counts a real-looking key in a variable as plaintext | Wrong score, right label |
| A4 | The hidden PowerShell talking to `api.openai.com` | Suspicious, 80, "if the connection is open during the scan" | **Missed in runs 2, 3 and 4.** Caught in run 5: Suspicious, **90** | **Wrong** (see below) |
| A5 | DNS lookups of `api.openai.com` | Reported if A4 couldn't be tied to a connection | Not reported in runs 2 to 4: there was no entry to report | Wrong, for the same reason |
| A6 | Script block log entry of `sync.ps1` | Likely miss (logging not enabled) | Not logged by Windows, so not reported | Correct |
| A7 | The hidden task | Miss: RAC 0.1 doesn't read the script a task runs | Missed | Correct, and fixed in rc5 |
| A8 | The hidden PowerShell as a process | Miss: the process scan reports agents, not scripts | Missed | Correct, and fixed in rc5 |

**What went wrong with A4.** We predicted that a miss would mean the connection was
closed. It wasn't: the rogue opened one connection at 16:37:15 and kept it open for the
whole test (PID 3560, to `162.159.140.245:443`). RAC ties an IP address to a hostname
only through the Windows DNS cache, because it never makes a lookup of its own. Windows
kept `api.openai.com` for **60 seconds**. After that minute, the open connection had no
name RAC could see, so the network check had nothing to report.

Run 5 proved the logic itself: once `GetHostAddresses` put the name back in the cache,
RAC reported `powershell.exe (PID 3560) connected to api.openai.com (OpenAI)` at
Suspicious, 90: not an AI app (+40), launched hidden (+40), connection open 70 minutes
(+10). We had predicted 80; we left out the long-lived connection.

**A mistake in our own test design.** In run 4 we tried to fill the cache with
`Resolve-DnsName`. It returned the addresses, but the scan started right after found
no entry. `GetHostAddresses`, the route ordinary programs use, did leave one (run 5).
We didn't confirm the cache contents before run 4, which is why it took one more run
to tell a timing gap from a bug.

**OpenClaw (B).**

| # | What | Predicted | Result | Verdict |
|---|---|---|---|---|
| B1 | Config folder `~\.openclaw` | Unknown | Unknown, 0 | Correct |
| B2 | Autostart | Unknown, 10: a scheduled task, or a Startup entry if task creation is denied | Startup entry `OpenClaw Gateway.vbs`, Unknown, 10 | Correct |
| B3 | Gateway process | Unknown | Unknown, one finding per process (6: node, cmd and workers) | Correct, but noisy; one finding per agent is planned for 0.1.2 |
| B4 | Listener on 18789 | Reported | Loopback only, Unknown, 0 | Correct |
| B5 | npm package | Unknown, 10 | `openclaw 2026.11.7`, Unknown, 10, plus a package-install finding | Correct |
| B6 | Logs | Unknown, if written | Missed: OpenClaw writes to `~\.openclaw\tmp\openclaw`, which the catalog doesn't list | Catalog fix for 0.1.2 |
| B7 | Installer script blocks | Likely miss | Caught in run 1b (7 blocks, filed under OpenClaw); gone by run 2, when the full PowerShell log had overwritten them, and that log was reported Partial | Better than predicted |
| B8 | Off-hours | Unknown, 15 | Not applicable (weekday, business hours) | n/a |

One finding we didn't predict: **SelfModification, 20** for OpenClaw, because
onboarding had just written `soul.md` and `agents.md`. Files written at install time
shouldn't count as an agent rewriting itself; this is on the list for 0.1.2.

**Coverage (C).**

| # | Row | Predicted | Result |
|---|---|---|---|
| C1 | PowerShell Operational log | Partial, "only reaches back to ..." | Partial in every run. Before the test the 15 MB log reached back 2.7 days; after the OpenClaw install it reached back only 17 to 41 minutes. The Security log was Partial too, in admin runs (it reached back four days of the seven). |
| C2 | DNS cache and Security log, normal window | Partial | Partial |

**Lucy over SSH (D)** was skipped. Remote agents remain the known gap for 0.2.

## The fix: release candidate 5

The miss told us where RAC was looking: at a fact (a DNS entry) that expires within a
minute, while the evidence that never expires was sitting on disk. RC5 reads the script
a process or autostart entry runs, and decodes `-EncodedCommand`, then looks for LLM
API hostnames, AI SDK imports and AI key variable names. It reads; it never runs
anything, never opens a network path, and never copies a key value into a report.

Ten new tests cover it, using the same rogue on the fake test machine. All ten fail on
release candidate 4 and pass on release candidate 5. The other 89 detection tests pass
on both.

### The retest (18:40 to 18:47)

The VM was rolled back to its snapshot from before the test, so OpenClaw and Node.js
were gone. Release candidate 5 was copied in and its zip hash checked (`E62C42DF...`).

- Tests: 133 of 133 passed in a normal window; 132 passed and 1 skipped (the "not
  elevated" check) in an admin window.
- The rogue was planted again at 18:40:47. Three minutes later the DNS cache held no
  entry for `api.openai.com`, so the network check could not name its connection.
- The pass criteria, set before the scans: Suspicious 3 or more in both windows,
  including the PowerShell running `sync.ps1` and the task "OneDrive Sync Helper".

| What | Admin scan (18:45) | Standard-user scan (18:46) |
|---|---|---|
| Hidden task "OneDrive Sync Helper" (A7) | **Suspicious, 95**: starts automatically (+10), launched hidden (+40), hidden task (+20), its script calls an LLM API (+25) | the same |
| PowerShell running `sync.ps1` (A8, and A4 without DNS) | **Suspicious, 65**: launched hidden (+40), its script calls an LLM API (+25) | the same |
| `.env` with the key (A1) | Suspicious, 55 | the same |
| `.mcp.json` shell server (A2) | Unknown, 25 | the same |
| User variable `OPENAI_API_KEY` (A3) | Unknown, 15 | the same |
| Three AI browser extensions already on the VM | Unknown | the same |

Both scans: 8 findings, 3 Suspicious, 5 Unknown. The standard-user scan got an empty
DNS cache, as standard-user scans do on this VM, and caught the rogue anyway: the catch
no longer depends on DNS. Both findings name the script, the host it calls and the key
variable it uses, with a redacted sample of the line:
`Invoke-RestMethod -Uri 'https://api.openai.com/v1/models' -Headers @{ Authorization = "Bearer $env:OPENAI_API_KEY" }`.
The only Suspicious findings were the rogue's own pieces, no coverage source errored,
and the fake key appears in no output. The rogue was then removed with
`Stage-RogueAgent.ps1 -Remove`.

### Retest 2: the rogue and a real OpenClaw together (22:54 to 23:25)

The first retest had OpenClaw rolled away. The new check reads the scripts of
processes RAC doesn't already recognize, so the open question was whether it would
mistake a real agent for a rogue. This run put both on the machine at once.
Predictions E1 to E9 and the pass rules were written at about 19:15, before the run,
and are reproduced unchanged below.

What happened, in order:

- The VM was rolled back to the same clean snapshot. Release candidate 5 was copied in
  and its zip hash checked (`E62C42DF...`). No tests were run this time.
- The rogue was planted from an admin window at 22:58:47.
- OpenClaw 2026.11.7 was installed with its official installer in a new normal
  window (package in place at 23:04). Onboarding found the rogue's
  `OPENAI_API_KEY` and offered to use it. The key is fake, so the provider rejected
  it and the prompt came back. **Skip for now** finished setup, but that also skipped
  installing the gateway as a service. `openclaw gateway install`, from OpenClaw's
  Windows documentation, added the Startup entry `OpenClaw Gateway.vbs` at 23:15:13.
  That is the same per-user Startup fallback as in the first test. The gateway was
  listening on `127.0.0.1:18789` by 23:17.
- After a three-minute wait, `Get-DnsClientCache` showed no `openai` entry. The admin
  scan ran at 23:23 and the normal-window scan at 23:24. By then the rogue's
  PowerShell (PID 14488) had been running for 24 minutes.

| # | What | Predicted | Admin scan (23:23) | Normal-window scan (23:24) | Verdict |
|---|---|---|---|---|---|
| E1 | Hidden task "OneDrive Sync Helper" | Suspicious, 95 | Suspicious, 95 | Suspicious, 95 | Correct |
| E2 | PowerShell running `sync.ps1` | Suspicious, 65 | Suspicious, 65 (PID 14488) | Suspicious, 65 | Correct |
| E3 | `.env` with the key | Suspicious, 55 | Suspicious, 55 | Suspicious, 55 | Correct |
| E4 | `.mcp.json` shell server; user variable | Unknown, 25; Unknown, 15 | the same | the same | Correct |
| E5 | OpenClaw folder, Startup entry, processes, port, package, install | Unknown, 0 to 10 | Folder 0; Startup entry 10; 6 processes, 0 each; loopback listener 0; package 10; install activity 10. All filed under OpenClaw | the same | Correct |
| E6 | OpenClaw SelfModification | Unknown, 20 (known noise) | Unknown, 20 (`soul.md`, `agents.md`) | the same | Correct |
| E7 | An OpenClaw process reported by the new check | None | None. The only "Unidentified script" was the rogue | None | Correct |
| E8 | Suspicious total | 3 | 3 | 3 | Correct |
| E9 | Coverage errors; fake key in any output | none; none | none; none | none; none | Correct |

All six OpenClaw processes (the gateway and its supervisor, the `cmd.exe` between
them, a job anchor, the spawn broker and a SQLite worker) were recognized as OpenClaw from their command
lines, so the script check never looked at them. Each scan had 26 findings: 3
Suspicious, all of them the rogue's, and 23 Unknown. The normal-window scan again got
an empty DNS cache and no Security log events, and still caught the rogue in full.
`RACTEST` appears in none of the eight output files. **By the rules set before the
run, this is a pass.**

Two things we didn't predict, neither of which changes the verdict:

- **OpenClaw off-hours, Unknown, 15.** This run was on a Monday at 23:23, outside the
  default business hours, so OpenClaw's activity that evening counted (33
  timestamps). That is correct behavior. The first test ran in business hours and
  never exercised it.
- **Four PowerShell script-block findings, Unknown, score 0.** Three come from release
  candidate 3's test files, run on this VM on 21 November and still in the snapshot's
  PowerShell log. In the first retest, that day's test runs had pushed them out of the
  15 MB log. RAC files them under Aider, Claude Code and OpenAI Codex CLI because the
  test fixtures name those agents. Each carries RAC's note that the path names Rogue
  Agent Checker but the text isn't from the copy that ran the scan. The same old
  blocks gave Claude Code an off-hours finding (Unknown, 15). The fourth group, filed
  under OpenClaw, holds OpenClaw's installer blocks from 23:03 together with one
  release candidate 3 test file. It shows only that file's path, so a reader could
  think the installer text came from it. Grouping by agent should list every script
  path in the group; that is on the 0.1.2 list.

The rogue was removed with `Stage-RogueAgent.ps1 -Remove` after the scans.

## Still open after this test

- **Long-lived connections from compiled programs.** A program that isn't a script
  still can't be named after its DNS entry expires. Sysmon Event 22 closes that gap.
- **Scripts RAC can't read:** network paths, unexpanded `%VARIABLES%`, files over 1 MB,
  code downloaded or assembled at run time.
- **Remote agents** working over SSH, WinRM or RDP (0.2).
- **0.1.2:** the OpenClaw log path, one finding per agent instead of per process, no
  SelfModification for files written at install time, and every script path listed
  when script blocks from several scripts are grouped under one agent.
