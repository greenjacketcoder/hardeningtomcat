# HardeningTomcat (beta)

```
                                       :
                                     `=S+-                                     ```
                                     :-sSS+                               `:=cSs
                                     -*SSs#+ `::                ``` `:-=*s##S*-
                                     +%#@SSS`:``::::`   ``:::-:::--+cS#%#c=
                                     =#%%SSs-`::``-::--:-::::-=+c#%%#s+:
                                 ```:=cS#Ss#+*c:``+--+` `-+cS#%%#S*:
                                 :::-+SSsss#:::::`:+sc*sS#%@%Sc=
                               `:`:=cscc#c*#: -=-=cS%%@@%##+:
                               ::--*ccc+cS+S- `*ss*=s@S+:`:
                              -::+--:`+==++=-=*csc=*sS#:
                            ::--`--`:=+s*+c***++*sS+**S*:-```
                         :::` :=sSSSc+s*****+-::css#SS#c `::::::```
                      `:::`:=*cS%@%sSc*+s==-::::`sSS@%%=````
                   `::`:-+sS%@@%%S++*s#c*c`:::::`*%cc*%-
                  ``:=*S%%%#Sc+:   `::s%s#+ ::`++:=#sS#`
              ``:-*s#@@#s*-`        =*sc###+:-=*:   ---
            :-*s#%%Sc=:           ```+#s*c%s    +    ```
         -+s###s+:              `:`:`  c###-     +
     `:cSSs*-                 `:``       `        +
       ::                   `:`
                           ``

                          recon . survey . strike
                        Windows hardening, locked on
```

## What it is

**HardeningTomcat** audits and (optionally) hardens a Windows system against a finding list.
It reads settings from the registry, security policy, audit policy, user-rights assignments,
Defender, and exploit-protection; compares each against a recommended value; scores the
result; and can apply the recommended values to bring the system into compliance.

It is an independent, from-scratch implementation **inspired by**
[scipag/HardeningKitty](https://github.com/scipag/HardeningKitty) — **not a fork** — built
around a pluggable handler architecture, a unified audit/apply loop, and a typed JSON
finding format.

> **BETA. Recon freely. Strike (apply) only on a disposable VM with a snapshot.**

Per-version history and current implementation status live in [CHANGELOG.md](CHANGELOG.md).

## Requirements

- **Windows PowerShell 5.1 or PowerShell 7+**
- **English-language Windows** (analysis on other display languages may be incorrect)
- **Elevation (Run as Administrator) is recommended.** Non-elevated sessions still work
  for Recon/Survey, but findings that need admin rights (user-rights assignments, audit
  policy, security policy) are reported **Skipped** — you get an up-front warning with
  the exact count. Strike should always run elevated.
- Strike additionally requires a **64-bit PowerShell process on 64-bit Windows**
  (32-bit registry redirection would write the wrong keys — Strike refuses; Recon warns).

## Install

```powershell
git clone https://github.com/greenjacketcoder/hardeningtomcat.git
cd hardeningtomcat

# If you downloaded a zip instead of cloning, clear mark-of-the-web first,
# or PowerShell may refuse to load the module files:
Get-ChildItem -Recurse | Unblock-File

Import-Module .\HardeningTomcat.psd1
```

If script execution is disabled on the machine, allow it for your session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

## Quick start

Run in an **elevated** PowerShell (Administrator):

```powershell
Import-Module .\HardeningTomcat.psd1
Invoke-HardeningTomcat -Mode Recon -ReportHtml   # read-only audit + HTML report
```

That's a complete read-only compliance audit — the finding list is auto-selected to match
your OS, nothing is changed, and you get a scored, self-contained HTML report in the
current directory. The [tutorial](docs/tutorial-first-audit.md) walks through it step by step.

## The three modes

| Mode       | What it does                                                                                                                  | Changes the system? |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| **Recon**  | Reads each setting, compares to the recommended value, scores Pass/Fail. The everyday "how compliant is this machine?" audit. | No                  |
| **Survey** | Reads and reports the current value of each setting, with no pass/fail judgment. "Just show me what's set."                   | No                  |
| **Strike** | Reads, compares, **and writes** the recommended values to fix failing settings. Gated behind `-Force`.                        | **Yes**             |

`-WhatIf` is a modifier on **Strike**, not a fourth mode: it runs Strike's full logic but
writes **nothing** to system configuration — it reports what *would* change. Recon answers
"is this compliant?"; `Strike -WhatIf` answers "if I enforced this list, what exactly would
get modified?"

## Common commands

Work down this list in order — it's the recommended escalation path from
"look" to "change":

```powershell
# 1. Recon — read-only compliance audit. Auto-selects the OS-matched list.
Invoke-HardeningTomcat -Mode Recon -ReportHtml

#    Recon against a specific list, CIS Level 1 only, printing every
#    failed/skipped finding instead of just the summary:
Invoke-HardeningTomcat -Mode Recon -FindingList .\lists\cis\<list>.json -Level 1 -ShowDetails

# 2. Survey — inventory the current values, no pass/fail grading. CSV output.
Invoke-HardeningTomcat -Mode Survey -Report

# 3. Strike dry run — full Strike logic, ZERO configuration writes.
#    Shows exactly what would change. (The pre-Strike backup directory is
#    still created — that's deliberate: it proves the safety net works.)
Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\cis\<list>.json -WhatIf -ShowDetails

# 4. Strike — WRITES to the system. Snapshot your VM first.
#    Requires -Force AND an explicitly named -FindingList (apply mode never guesses).
#    -ExcludeHighImpact is strongly recommended on any machine you need to
#    log back into. Read docs/howto-safe-strike.md before running this.
Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\cis\<list>.json -Force -ExcludeHighImpact -Log
```

### Flag cheat sheet

The flags you'll actually reach for, and when:

| Flag                     | When to use it                                                                                                                       |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `-FindingList <path>`    | Optional for Recon/Survey (OS-matched list auto-selected from `lists/`); **mandatory for Strike** — apply mode refuses to guess.     |
| `-Level 1` / `-Level 2`  | CIS level filter: `1` = L1 only, `2` = L1+L2. Findings without a level (e.g. Microsoft lists) always run.                            |
| `-Filter <scriptblock>`  | Arbitrary finding filter, e.g. `{ $_.severity -eq 'High' }`.                                                                          |
| `-WhatIf`                | **Always run before a real Strike.** Previews every change; writes nothing.                                                          |
| `-Force`                 | The Strike gate. Without it, Strike throws before touching anything.                                                                 |
| `-ExcludeHighImpact`     | Skips the boot/lockout/remote-access class of findings (VBS/Credential Guard, NTLM/Kerberos cluster, required SMB signing, RDP disables). |
| `-ShowDetails`           | Print every failed/skipped finding (and every would-change item under `-WhatIf`). Default output is the summary only.                |
| `-Report` / `-ReportHtml`| Per-finding CSV / self-contained HTML report (auto-named with host + timestamp). Both can be produced in the same run.               |
| `-Log`                   | Line-flushed text log — after a crash, the last line on disk is the last action taken.                                               |
| `-PassThru`              | Return the structured `{Summary; Results}` object for scripting instead of the formatted console summary.                            |
| `-BackupDir <path>`      | Override where the pre-Strike backup + undo journal are written.                                                                     |

Every parameter, gate, result status, operator, and the `-PassThru` shape:
[Invoke-HardeningTomcat reference](docs/reference-invoke-hardeningtomcat.md).

## Safety model

Strike refuses to run unless **all** of these hold:

1. `-Force` is supplied.
2. `-FindingList` is named explicitly.
3. The list's SHA256 is present in `lists/manifest.sha256` — a tampered or
   unlisted list is a hard stop.
4. The pre-Strike backup completed (override only with `-SkipBackupCheck`,
   and only when you have another safety net such as a VM snapshot).
5. The process is 64-bit on 64-bit Windows.

Before applying anything, Strike exports security policy, audit policy, the
most-touched registry subtrees, service start types, and Defender preferences
to a backup directory — and during the apply it appends every finding's
**pre-change value to an undo journal** (`undo-journal.jsonl`) in the same
directory, so each change is individually reversible. The full workflow,
every gate, backup contents, and how to undo are in
[How to run a safe Strike](docs/howto-safe-strike.md).

## Documentation

| Doc                                                                        | For                                                                                                   |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [Tutorial: your first audit](docs/tutorial-first-audit.md)                  | Zero to a scored HTML report in 3 steps (read-only)                                                    |
| [How to run a safe Strike](docs/howto-safe-strike.md)                       | The apply workflow, every safety gate, backup contents, and **undoing changes with the undo journal**  |
| [Invoke-HardeningTomcat reference](docs/reference-invoke-hardeningtomcat.md)| Every parameter, gate, result status, operator, and the `-PassThru` shape                              |
| [Finding list format](docs/reference-finding-list-format.md)                | The typed JSON schema, validation rules, and integrity model                                           |
| [Why the engine is built this way](docs/explanation-architecture.md)        | Handler registry, one-loop design, honest failure — with trade-offs                                    |
| [Importers](Importers/README.md)                                            | Generating lists from Microsoft SCT / CIS / STIG sources                                               |

## Where the finding lists come from

Lists are typed JSON (`Schema/Finding.schema.json`) generated from **authoritative
sources**, not hand-authored, via the scripts in `Importers/`:

- **Microsoft Security Compliance Toolkit (SCT)** — the official Microsoft baselines. The
  importer reads Microsoft's own `registry.pol` / `GptTmpl.inf` / `audit.csv` GPO
  artifacts. Server baselines are split by role (Member Server vs Domain Controller).
  *(Windows 11 23H2/24H2/25H2; Server 2016/2019/2022/2025.)*
- **CIS Benchmarks** — converted from HardeningKitty's published CSV lists (Apache-2.0,
  with attribution), carrying CIS L1/L2 levels. *(Windows 11 25H2; Server 2016/2019/2022.)*
- **DoD STIG** — two routes: the HardeningKitty Win10 CSV, and a parser for the
  **authoritative DISA SCAP benchmark** (XCCDF + OVAL) for Windows 11.

Generated lists live under `lists/` (`microsoft/`, `cis/`, `stig/`). Each list's hash is
recorded in `lists/manifest.sha256`; Strike refuses any list whose hash isn't in the
manifest. The manifest alone detects *accidental corruption*; **tamper resistance requires
the signed catalog** produced by `Sign-Module.ps1` (Strike warns when running without one).

## How it works

The short version — the [architecture doc](docs/explanation-architecture.md) has the
full design rationale and trade-offs:

- **Handler registry.** Each check method (registry, service, auditpol, secedit, and so
  on) is one file in `Handlers/`; adding a method means adding a file — the engine never
  changes.
- **One loop for audit and apply**, so there is no audit-vs-apply drift, and slow external
  tools (`auditpol`/`secedit`) run once per run, not once per finding.
- **Honest failure reporting.** A setting that can't be read (export failed, not elevated)
  is reported **Skipped** — never silently passed. Checks with no automated test are
  marked manual and reported Skipped with their remediation text.
- **Recoverable Strikes.** Pre-apply backups plus a per-finding undo journal — see
  [Safety model](#safety-model) above.
