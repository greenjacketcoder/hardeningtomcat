# Tutorial: Your First Compliance Audit

You'll audit a Windows machine against a hardening baseline and get a scored,
self-contained HTML report — without changing a single setting. Recon mode is
read-only, so this is safe to run on any machine. About five minutes.

## What you'll need

- Windows 10/11 or Server 2016+ with Windows PowerShell 5.1 or PowerShell 7+.
- An **elevated** PowerShell (Run as administrator). Without elevation the audit
  still runs, but user-rights, audit-policy, and security-policy findings are
  Skipped — the tool warns you up front with the exact count.
- A clone or download of this repository.

## Step 1: Import the module

From an elevated PowerShell in the repo root:

```powershell
# If Windows blocked the downloaded files (zip download), unblock once:
Get-ChildItem -Recurse | Unblock-File

Import-Module .\HardeningTomcat.psd1
```

No output means success. `Get-Command Invoke-HardeningTomcat` confirms the one
exported command is available.

## Step 2: Run Recon

```powershell
Invoke-HardeningTomcat -Mode Recon -ReportHtml
```

With no `-FindingList`, the engine detects your OS and picks the matching list
from `lists/` — you'll see a cyan line like:

```
No -FindingList given. Auto-selected for Windows 11 25H2: Microsoft_Windows_11_25H2_-_Machine.json
```

A progress bar ticks through the findings with live pass/fail/skip counts, then:

```
==== HardeningTomcat Recon complete ====

  List:       Microsoft Windows 11 25H2 - Machine
  Host:       MY-PC
  Mode:       Recon
  Total:      312
  Passed:     241
  Medium:     38
  High:       12
  Skipped:    21

  Score:      1034 / 1164  (88.8%)
  Duration:   14.2s

HTML report: .\hardeningtomcat_report_MY-PC_..._20260710-143000.html
```

(Your numbers will differ — an unhardened machine typically lands 40–70%.)

## Step 3: Open the report

Double-click the HTML file the run printed. It's fully self-contained (inline
CSS/JS, opens offline): score tiles, a result-distribution chart, failures by
category, and a filterable table of every finding — what was checked, the
observed value, the recommended value, and the operator used to compare them.

Prefer data over charts? Add `-Report` (alongside or instead of `-ReportHtml`)
to also write a per-finding **CSV** — same rows, machine-readable, ideal for
Excel filtering, diffing two audits, or feeding a script:

```powershell
Invoke-HardeningTomcat -Mode Recon -Report -ReportHtml
```

## What you built

A scored compliance picture of your machine against an authoritative baseline,
with zero changes made. From here:

- Audit against a specific list or CIS level — see the
  [Invoke-HardeningTomcat reference](reference-invoke-hardeningtomcat.md)
  (`-FindingList`, `-Level`, `-Filter`).
- Actually fix the failures — read
  [How to run a safe Strike](howto-safe-strike.md) **before** touching Strike
  mode; it writes to the system and has a specific safety workflow.
- Understand how the engine evaluated all of that in seconds —
  [engine architecture](explanation-architecture.md).
