# Invoke-HardeningTomcat Reference

The module's single exported command. Audits (Recon), inventories (Survey), or
hardens (Strike) a Windows system against a JSON finding list. Runs on Windows
PowerShell 5.1 and PowerShell 7+.

## Syntax

```powershell
Invoke-HardeningTomcat -Mode <Recon|Survey|Strike> [-FindingList <path>]
    [-Level <1|2>] [-Filter <scriptblock>] [-ExcludeHighImpact]
    [-Report] [-ReportFile <path>] [-ReportHtml] [-ReportHtmlFile <path>]
    [-Log] [-LogFile <path>] [-ShowDetails] [-PassThru]
    [-Force] [-WhatIf] [-Confirm] [-BackupDir <path>] [-SkipBackupCheck]
    [-RequireSignedHandlers]
```

## Parameters

| Parameter | Type | Default | Effect |
|---|---|---|---|
| `-Mode` | string (required) | — | `Recon` (read + grade), `Survey` (read only, no grading), `Strike` (read + grade + **write**). |
| `-FindingList` | string | auto-detect | Path to a JSON list. Optional for Recon/Survey (OS-matched list auto-selected from `lists/`); **required for Strike** — apply mode refuses to guess. |
| `-Level` | `'1'`/`'2'` | all | CIS level filter: `1` = L1 only, `2` = L1+L2. Findings without a `level` field always run (Microsoft lists carry no levels). |
| `-Filter` | scriptblock | — | Arbitrary finding filter, e.g. `{ $_.severity -eq 'High' }`. |
| `-ExcludeHighImpact` | switch | off | Skips findings flagged `highImpact` (VBS/Credential Guard, NTLM/Kerberos cluster, required SMB signing, RDP/remote-mgmt disables — the boot/lockout/remote-access class). |
| `-Report` / `-ReportFile` | switch/string | off / auto-named | Per-finding CSV: `hardeningtomcat_report_<HOST>_<list>_<timestamp>.csv` in the current directory unless `-ReportFile` names a path. |
| `-ReportHtml` / `-ReportHtmlFile` | switch/string | off / auto-named | Self-contained HTML report (inline CSS/JS, opens offline): score tiles, result-distribution + failed-by-category charts, filterable findings table. |
| `-Log` / `-LogFile` | switch/string | off / auto-named | Per-line-flushed text log. Each line hits disk immediately — after a crash or brick, the last line is the last action taken. |
| `-ShowDetails` | switch | off | Print every failed/skipped finding (and each would-change item under `-WhatIf`). Default output is the summary only. |
| `-PassThru` | switch | off | Return the structured `{Summary; Results}` object (see below). Off by default so interactive runs print only the formatted summary. |
| `-Force` | switch | off | **Required for Strike.** Without it Strike throws before touching anything. |
| `-WhatIf` | switch | off | Strike dry-run: full logic, zero configuration writes, ends with a would-change count. Backup dir is still created (proves the safety net). |
| `-BackupDir` | string | auto-named | Override the pre-Strike backup location (`hardeningtomcat_backup_<HOST>_<timestamp>` in the current dir by default). |
| `-SkipBackupCheck` | switch | off | Let Strike proceed despite an incomplete backup. Only with another safety net (VM snapshot). |
| `-RequireSignedHandlers` | switch | off | Verify Authenticode signatures on every handler/helper before dot-sourcing; abort on any invalid signature. |

## Strike gates

Strike refuses to run unless **all** hold:

1. `-Force` supplied.
2. `-FindingList` named explicitly.
3. The list's SHA256 is present in `lists/manifest.sha256` (a signed-manifest
   failure is a hard stop in *all* modes).
4. The pre-Strike backup completed (or `-SkipBackupCheck`).
5. The process is 64-bit on 64-bit Windows (32-bit registry redirection would
   write the wrong keys — Strike throws; Recon warns).

## Result statuses

| Status | Meaning |
|---|---|
| `Passed` | Observed value satisfies the operator vs `recommendedValue`. |
| `Low` / `Medium` / `High` | Failed, recorded at the finding's severity. |
| `Skipped` | Could not be evaluated — no handler, needs elevation, missing binary, test error, or a `manual` finding. **Never silently passed.** |
| `Survey` | Survey mode: observed value recorded, no judgment. |

## Scoring

`Passed = 4, Low = 2, Medium = 1, High = 0` points per graded finding
(Skipped findings are not graded). Score = earned / (graded × 4), shown as a
percentage.

## Operators

The engine owns all comparison semantics (handlers only observe):

| Operator | Passes when |
|---|---|
| `=` / `!=` | String equality / inequality. |
| `<=` `>=` `<` `>` | Int64 numeric comparison. Empty/absent observations **fail** (never coerced to 0 — an unreadable value can't masquerade as compliant). |
| `<=!0` | Numeric `<=` AND observed ≠ 0. |
| `contains` | Observed string contains `recommendedValue`; an empty recommended value never matches. |
| `=\|0` | Equal, or observed is empty. |
| `=or` | `recommendedValue` like `"2 or 1"` — any listed value passes. **Registry findings only** (its apply resolves to the first value). |
| `set=` | Order-independent set equality for SID lists; account names are resolved to SIDs on both sides. Two empty sets are equal. |
| `manual` | Not evaluated — reported Skipped with the finding's remediation text. |

## Report outputs

- **CSV (`-Report`)** — one row per finding with columns `ID`, `Category`,
  `Name`, `Method`, `Checked`, `Observed`, `Recommended`, `Operator`,
  `Severity`, `Level`, `Result`, `Detail`, `Hostname` (UTF-8, identical to the
  `Results` records below). Auto-named
  `hardeningtomcat_report_<HOST>_<list>_<timestamp>.csv` unless `-ReportFile`
  is given.
- **HTML (`-ReportHtml`)** — the same findings rendered as a self-contained
  page (score tiles, charts, filterable table). Both can be produced in one run.
- **Log (`-Log`)** — line-flushed execution trace, separate from the reports.

## -PassThru output

```powershell
$r = Invoke-HardeningTomcat -Mode Recon -PassThru
$r.Summary   # ListName, Mode, Total, Passed, Low, Medium, High, Skipped,
             # Applied, ApplyFailed, Score, Percent, Duration
$r.Results   # one record per finding: ID, Category, Name, Method, Checked,
             # Observed, Recommended, Operator, Severity, Level, Result,
             # Detail, Hostname
```

`Checked` is the human-readable target ("what was actually inspected"), e.g.
`HKLM:\...\Path\Value`, `Audit subcategory: Logon`, `Service: RemoteRegistry`.

## Elevation behavior

Non-elevated sessions get an up-front warning with the exact count of findings
that will be Skipped (user rights, audit policy, security policy). Handlers
declaring `RequiresAdminForApply` still *read* without elevation; only their
applies are skipped.

## Related

- [Tutorial: your first audit](tutorial-first-audit.md)
- [How to run a safe Strike](howto-safe-strike.md) — gates, backups, undo journal
- [Finding list format](reference-finding-list-format.md)
