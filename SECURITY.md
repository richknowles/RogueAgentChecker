# Security policy

Rogue Agent Checker is a security tool, so a flaw in it matters twice: it can leave an
agent unreported, or it can harm the machine it was trusted to inspect.

## Report privately

Use **Report a vulnerability** on this repository's Security tab (GitHub private
vulnerability reporting). If you can't use it, email richard@wieldai.dev with
"RAC security" in the subject, and we'll agree on a private channel before you send
details. Please do not open a public issue for:

- anything that makes RAC write, change, delete or send data, or run code;
- a secret value reaching a report, the scan log or the console;
- a way for an agent to hide from RAC (an evasion technique).

Ordinary bugs, false positives, and new agents for the catalog are fine as public issues.

## What to include

The RAC version (first line of the scan log), the Windows and PowerShell versions, the
steps to reproduce, and the relevant part of the scan log. RAC redacts keys, but not
user names or paths, so remove anything you would not want published.

## Supported versions

Fixes go into the latest release only. RAC is at 0.1.x.
