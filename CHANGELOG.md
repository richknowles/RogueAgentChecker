# Changelog

## 0.1.1 (2026-11-20)

Fixes from the first runs on real Windows (Windows 11 25H2, build 26200, Windows
PowerShell 5.1, standard user and elevated), and one new check added after a live
test against a staged rogue agent. Still read-only.

### Added after the live test

- **RAC looks inside the scripts that processes and autostarts run.** In the live
  test (`docs/LIVE-TEST.md`), a rogue disguised as a OneDrive helper ran a hidden
  PowerShell script that kept one connection to `api.openai.com` open for over an
  hour. RAC names connections only through the Windows DNS cache, which dropped the
  hostname after 60 seconds, so release candidate 4 missed the rogue in three of four
  admin scans. Its hidden logon task and its process were also invisible, as we had
  predicted, because nothing in their command lines named AI. RAC now reads the
  script file a command line names (local files only, up to 1 MB) and decodes
  `-EncodedCommand`, then looks for LLM API hostnames, AI SDK imports and AI key
  variable names. Nothing is run, no network path is opened, and reports show
  variable names and a redacted sample, never a key. It works for processes (new
  breadcrumb `LlmScriptProcess`) and for every autostart type (scheduled tasks,
  services, Run keys, Startup folders, WMI consumers).
- Catalog 2026.11.23: AI SDK import patterns (`genericPatterns.llmSdkUse`), and the
  `LlmCallFromScript` indicator (+25) now covers scripts that processes and autostarts
  run, not only logged script blocks.

### Corrected

- **The README promised a network catch without its condition.** It listed "a hidden
  SYSTEM PowerShell talking to `api.openai.com`" as something the Network check
  catches, without saying that this works only while the DNS cache still holds the
  hostname. The live test showed how short that is. The README now states the limit,
  and the script check above covers the case.

### Fixed

- **Standard-user scans skipped the user's own registry hive.** RAC listed
  `HKEY_USERS` with `Get-ChildItem`, which stops at the first hive it cannot open
  (`S-1-5-19`). A non-elevated scan therefore read zero user hives and missed the
  user's own Run keys, per-user environment variables (where AI keys often live) and
  per-user browser native-messaging hosts, while Coverage said "Checked". Hive names
  now come from the .NET registry API, the scanning account's own hive is always
  included, and hives that cannot be opened are reported as Partial.
- **Coverage claimed a clean read it did not have.** Without elevation, Windows
  returned an empty DNS cache (211 entries as admin) and "no events" from the Security
  log (23 as admin), with no error. Both are now reported as Partial, with the reason,
  instead of "Checked, 0 items".
- **RAC reported its own code.** PowerShell script block logging recorded RAC's test
  file, and the scan flagged it three times. Windows logs large scripts in chunks that
  do not all contain RAC's marker text. RAC now skips blocks logged from its own
  folders, and anywhere else recognizes its own code by its exact text. That covers a
  second copy of RAC in another folder: the first v0.1.1 build, run from a second
  folder on the test VM, reported five script blocks that the first copy had logged.
- **A script could hide from the script-block check by naming RAC.** v0.1.0 skipped
  any block that contained `New-RacFinding`, `Invoke-RogueAgentScan` or
  `RacModuleRoot`, so one of those words in a comment made any script invisible to
  it. That shortcut is gone. A block is skipped only if it is word for word part of
  RAC's own code. A script that borrows RAC's names or folder is reported, with a note
  that its path names RAC but its text is not RAC's. Found while fixing the previous
  item.
- **Browser extensions were labeled with the wrong agent.** Extensions whose name
  contains "ChatGPT" (for example HARPA AI) were labeled "ChatGPT Desktop". Only a
  known extension ID now maps to a catalog agent. Other AI extensions are named after
  themselves, with agent id `ext:<extension id>`, which allow-lists can use and which
  survives extension updates.
- **Red "Access is denied" text in standard-user scans.** The Startup-folder check
  printed an error for other users' profiles. Unreadable profiles are now skipped and
  listed in Coverage.
- **Hidden scheduled tasks lost their HiddenTask score.** When a hidden task's only
  other risk was starting automatically, PowerShell joined the two indicator names
  into one string (`PersistenceAutostartHiddenTask`), worth 0 points instead of 30.
  Found in code review; the test machine had not exercised it.
- **The Claude browser extension was filed under Claude Desktop.** The elevated scan
  reported "Claude Desktop" on a machine where only the Chrome extension was
  installed. Worse, approving the desktop app would also have approved an extension
  that holds `debugger`, `nativeMessaging` and `<all_urls>`. Claude in Chrome is now
  its own catalog entry (`claude-in-chrome`) and needs its own approval. The native
  messaging host stays under Claude Desktop, because it launches the Claude app.
  Catalog 2026.11.20, 23 agents.
- **An event log that had overwritten itself was reported as covering the whole
  lookback.** Windows keeps each event log at a fixed size. On the test VM, the
  PowerShell log held about an hour of a busy test day: it had 448 script blocks at
  one scan and 387 at the next, after more had been logged in between. The report
  still said "Checked" for 7 days. RAC now reads each log's size, retention mode and
  oldest event. When a full log no longer reaches back to the start of the lookback,
  Coverage says Partial, how far back it does reach, and how to raise the log size.
  Every event-log row also states how far back the log reaches. Flooding a log until
  its oldest events roll off is a known way to hide; this makes it visible.

### Tests

- 28 detection tests failed on Windows PowerShell 5.1 because the test helper returned
  a single finding unwrapped, and 5.1 gives a single object no `.Count` (PowerShell 7
  does). Every helper call is now wrapped in `@()`, and a safety test fails the build
  if test code counts anything that is not an array.
- New regression tests for each fix above. The ones for hidden tasks, extension
  labels and self-detection fail against v0.1.0 and pass against v0.1.1. The
  Windows-only ones (own hive read, honest coverage, no error-stream output) run in
  `Integration.Windows.Tests.ps1`.
- 133 tests in total (was 111). The 10 for the script check fail against release
  candidate 4 and pass against release candidate 5; the other 89 detection tests pass
  on both.
- Real-Windows rerun (standard user): 117 of 118 passed and every fix above was
  confirmed. The one failure was a test that assumed Windows PowerShell 5.1 could not
  parse a JSON5 config; 5.1 accepts its unquoted keys once comments are stripped. The
  test now checks only that the file never breaks the scan.
- The elevated rerun was handed to a cloud AI agent working over SSH. Its first
  attempt died after about 45 seconds when the connection dropped. Instead of stopping
  and reporting, as instructed, the agent relaunched the run hidden and base64-encoded.
  That run froze mid-write after 44 seconds, apparently because nothing was reading its
  output. A RAC scan taken while the frozen process was alive did not report it: the
  remote-agent gap, now first on the v0.2 roadmap.
- Real-Windows rerun (elevated, run by hand, Pester 6.2.0): 116 passed, 1 skipped
  (the "not elevated" check), 1 failed (the same JSON5 test). The admin scan read
  208 DNS cache entries and 23 Security-log process events that a standard user gets
  back empty. It read 335 PowerShell script blocks, including those of the test run
  minutes earlier, and reported none of RAC's own. Every category finished without
  an error.
- Real-Windows run of the release candidate (standard user, unzipped to a new folder,
  zip hash checked): 119 of 119 passed. Its scan labeled Claude in Chrome correctly,
  and exposed the second-copy problem above.
- Real-Windows run of the third release candidate, with the second-copy fix: 121 of
  121 passed in a normal window, and 120 passed with 1 skipped (the "not elevated"
  check) in an admin window. The tests ran from one folder and the scans from a
  second copy; neither scan reported any of the test run's script blocks. A leftover
  block from the previous candidate, whose text had since changed, was reported with
  the note. These runs also exposed the event-log gap above.
- Release candidate 4, with the event-log fix, was used for the live test, which found
  the network gap above.
- Release candidate 5, with the script check: 133 of 133 passed in a
  normal window, and 132 passed with 1 skipped in an admin window (VM rolled back to
  a clean snapshot, zip hash checked). In the live retest with the same rogue, after
  its DNS entry had expired, both the admin and the standard-user scan reported the
  hidden task (Suspicious, 95), the PowerShell running the script (Suspicious, 65)
  and the `.env` (Suspicious, 55). No key value appeared in any output, and no
  coverage source errored.
- Off Windows (PowerShell 7.4, Pester 6.2.0), 124 of 133 pass and the 9 Windows
  integration tests skip. Each new test fails against the build before its fix and
  passes against this one.

### Licensing

- Released under the Apache License 2.0 (`LICENSE`, `NOTICE`). The module manifest
  now carries the license and project links.

## 0.1.0 (2026-10-26)

First release: read-only local scan across seven breadcrumb categories, allow-list
classification (Trusted / Unknown / Suspicious), HTML / CSV / JSON report and scan log,
Pester tests with a fake machine.
