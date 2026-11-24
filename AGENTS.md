# AGENTS.md

Guidance for AI agents and coding assistants working with Rogue Agent Checker (RAC).

## Using RAC or reading its reports

The rules in the README's *For AI agents* section apply. In short:

1. Don't act on findings yourself. RAC is report-only; removal goes through a person.
2. Keep reports where they are. Nothing goes to an outside service, including an AI
   API, unless the person explicitly asks.
3. Never reveal or reconstruct a secret. Reports carry key names, never values.
4. "No findings" is not "clean". Read `coverage`.
5. Don't edit the allow-list to make findings go away. Draft entries for a person to
   approve.
6. If RAC reports you, say so. Don't hide, rename, relaunch or reschedule yourself.

The README's *For AI agents* section also describes the JSON report format.

## Working on this repository

These constraints are the product. The test suite enforces most of them. Never weaken,
skip or delete a test to get a change through.

- **Read-only.** No command or .NET call that changes system state. `Tests/Safety.Tests.ps1`
  lists the banned commands and methods. File writes happen only in the logging and
  report code.
- **Local-only.** No web, DNS, socket or mail commands and no .NET networking types.
  RAC never resolves a name. Never open a file on a network path or a mapped network
  drive.
- **One place to audit.** Every operating-system query lives in
  `RogueAgentChecker/Private/Sources.ps1`. Analyzers get data only from there, which is
  also what lets the tests replace the machine with a fake one.
- **Secrets.** Detect keys by variable name and format. Never store, log or print a
  value. Pass any text that goes into evidence through `Protect-RacText` (or
  `Get-RacSnippet`, which redacts before it cuts).
- **Windows PowerShell 5.1.** ASCII-only source (5.1 misreads BOM-less UTF-8), no
  PowerShell 7-only syntax, and wrap pipeline results in `@()` before using `.Count`.
  LF line endings.
- **Data over code.** New agents, endpoints and patterns go in `Data/signatures.json`.
- **Proof.** A new detection needs a test against the fake machine in `Tests/Fixtures`
  that fails on the old code and passes on the new code. Fake keys must contain
  `RACTEST`, so nobody mistakes one for a real key.

Run the tests (Pester 5 or later):

```powershell
Invoke-Pester -Path .\Tests -Output Detailed
$env:RAC_INTEGRATION = '1'    # Windows only: also run the real-Windows tests
```

Off Windows, 124 of 133 pass and the 9 integration tests skip.

## Layout

| Path | What it is |
|---|---|
| `Start-RogueAgentScan.ps1` | Launcher for people and RMM tools |
| `RogueAgentChecker/Public/` | The exported commands |
| `RogueAgentChecker/Private/Sources.ps1` | Every operating-system query |
| `RogueAgentChecker/Private/Analyze-*.ps1` | One file per finding category |
| `RogueAgentChecker/Private/Classify.ps1` | Scoring and the allow-list |
| `RogueAgentChecker/Private/Report.ps1` | HTML, CSV and JSON output |
| `RogueAgentChecker/Data/signatures.json` | The detection catalog |
| `Tests/` | Pester tests; `Tests/Fixtures/` is the fake machine |
| `docs/ARCHITECTURE.md` | Design decisions and their reasons |
| `docs/LIVE-TEST.md` | The live test against a staged rogue agent |

Report security issues privately; see `SECURITY.md`.
