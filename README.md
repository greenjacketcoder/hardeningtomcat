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
Defender, and exploit-protection; compares each against a recommended value; scores the result;
and can apply the recommended values to bring the system into compliance.

It is an independent, from-scratch implementation **inspired by**
[scipag/HardeningKitty](https://github.com/scipag/HardeningKitty) -- **not a fork** -- built
around a pluggable handler architecture, a unified audit/apply loop, and a typed JSON finding
format. It runs on **Windows PowerShell 5.1 and PowerShell 7+**, and was developed for English
systems (analysis on other languages may be incorrect).

> **BETA. Recon freely. Strike (apply) only on a disposable VM with a snapshot.**

Per-version history and current implementation status live in [CHANGELOG.md](CHANGELOG.md).

## The three modes

| Mode | What it does | Changes the system? |
|------|--------------|---------------------|
| **Recon** | Reads each setting, compares to the recommended value, scores Pass/Fail. The everyday "how compliant is this machine?" audit. | No |
| **Survey** | Reads and reports the current value of each setting, with no pass/fail judgment. "Just show me what's set." | No |
| **Strike** | Reads, compares, **and writes** the recommended values to fix failing settings. Gated behind `-Force`. | **Yes** |

`-WhatIf` is a modifier on **Strike**, not a separate mode: it runs Strike's full logic
but writes **nothing to system configuration** -- it reports *what it would change*. (To
prove the safety net works, the pre-Strike backup directory and the temporary policy
exports are still created; no registry/policy/service setting is modified.) So `Recon`
and `Strike -WhatIf` both leave configuration untouched, but answer different questions:
Recon asks "is this compliant?"; `Strike -WhatIf` previews "if I enforced this, what exactly
would get modified?"

## Where the finding lists come from

Lists are typed JSON (`Schema/Finding.schema.json`) generated from **authoritative sources**,
not hand-authored, via the scripts in `Importers/`:

- **Microsoft Security Compliance Toolkit (SCT)** -- the official Microsoft baselines. The
  importer reads Microsoft's own `registry.pol` / `GptTmpl.inf` / `audit.csv` GPO artifacts.
  Server baselines are split by role (Member Server vs Domain Controller).
  *(Windows 11 23H2/24H2/25H2; Server 2016/2019/2022/2025.)*
- **CIS Benchmarks** -- converted from HardeningKitty's published CSV lists (Apache-2.0, with
  attribution), carrying CIS L1/L2 levels. *(Windows 11 25H2; Server 2016/2019/2022.)*
- **DoD STIG** -- two routes: the HardeningKitty Win10 CSV, and a parser for the **authoritative
  DISA SCAP benchmark** (XCCDF + OVAL) for Windows 11.

Generated lists live under `lists/` (`microsoft/`, `cis/`, `stig/`). Each list's hash is
recorded in `lists/manifest.sha256`; Strike refuses any list whose hash isn't in the manifest.

## How it works

- **Handler registry.** Each check method (Registry, service, auditpol, secedit, accesschk,
  accountpolicy, localaccount, MpPreferenceAsr, RegistryList, ProcessmitigationApplication) is
  one file in `Handlers/` returning `@{ Name; Test; Apply; Prefetch }`. Adding a method = adding
  a file; the engine never changes.
- **One loop for audit and apply** -- no audit-vs-apply drift.
- **Prefetch batching.** Slow external tools (`auditpol`/`secedit`) run **once per run**, not
  once per finding; every check is then an in-memory lookup.
- **Honest failure reporting.** A setting that can't be read (export failed, not elevated) is
  reported **Skipped** -- never silently passed. Checks with no automated test are marked
  **manual** and reported Skipped with their remediation text.
- **Structurally validated lists** (required fields, operators, severities, duplicate ids --
  fail-fast at load) and **finding-list integrity** (SHA256 manifest; Strike refuses
  unlisted/tampered lists, Recon/Survey warn). Note the manifest alone detects *accidental
  corruption*; **tamper resistance requires the signed catalog** produced by
  `Sign-Module.ps1` (Strike warns when running without one).
- **Recoverable Strikes.** Before applying, Strike exports security policy, audit policy,
  the most-touched registry subtrees, service start types, and Defender preferences to a
  backup directory -- and during the apply it appends every finding's **pre-change value
  to an undo journal** (`undo-journal.jsonl`) in the same directory, so each change is
  individually reversible.

## How to run it

Run in an **elevated** PowerShell (Administrator) -- user-rights, audit policy, and security
policy require elevation. A non-elevated run warns up front and Skips those findings.

```powershell
Import-Module .\HardeningTomcat.psd1

# Recon -- read-only audit. No -FindingList = auto-detect the OS and pick the matching list.
Invoke-HardeningTomcat -Mode Recon -Report
# ...or name a list explicitly:
Invoke-HardeningTomcat -Mode Recon -FindingList .\lists\cis\CIS_Windows_11_25H2_L1-L2.json -Level 1 -Report

# Same audit, plus a self-contained HTML report (charts + filterable findings table):
Invoke-HardeningTomcat -Mode Recon -FindingList .\lists\cis\CIS_Windows_11_25H2_L1-L2.json -Level 1 -ReportHtml

# Survey -- dump current values, no pass/fail.
Invoke-HardeningTomcat -Mode Survey

# Strike DRY-RUN -- shows a count of what would change (add -ShowDetails to list them). No writes.
Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\cis\CIS_Windows_11_25H2_L1-L2.json -Level 1 -Force -WhatIf

# Strike FOR REAL -- writes to the system. ONLY on a throwaway VM with a snapshot.
Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\cis\CIS_Windows_11_25H2_L1-L2.json -Level 1 -Force
```

### Switches

| Switch | Effect |
|--------|--------|
| `-FindingList <path>` | The list to use. Required for Strike (never auto-selected). |
| `-Level 1\|2` | CIS level filter: `1` runs L1 only, `2` runs L1+L2. Lists without levels ignore it. |
| `-Report` | Write a per-finding CSV (auto-named, or use `-ReportFile`). |
| `-ReportHtml` | Write a self-contained HTML report (auto-named, or use `-ReportHtmlFile`): score tiles, result-distribution and failed-by-category charts, and a filterable findings table. Inline CSS/JS -- opens offline, no external dependencies. See [docs/example-report.html](docs/example-report.html) for a sample built from synthetic demo data (download and open locally -- GitHub shows raw HTML as source). |
| `-ShowDetails` | List each failed/skipped finding (and each would-change item in `-WhatIf`). Off by default. |
| `-Force` | Required for Strike. Without it, apply mode refuses to run. |
| `-WhatIf` | Strike dry-run: report what would change, write nothing. |
| `-Filter {…}` | Scriptblock over findings, e.g. `-Filter { $_.severity -eq 'High' }`. |
| `-BackupDir <path>` | Override the pre-Strike backup location. |
| `-SkipBackupCheck` | Let Strike proceed even if the pre-Strike backup fails (use only with a VM snapshot). |
| `-ExcludeHighImpact` | Skip findings flagged high-impact -- the boot/lockout/remote-access class (VBS/Credential Guard, NTLM/Kerberos auth, required SMB signing, RDP/WinRM/remote-mgmt service disables). Strongly recommended for a first Strike on a machine you can't easily recover. |
| `-RequireSignedHandlers` | Verify every handler's Authenticode signature before loading; abort if any is unsigned. |
| `-PassThru` | Return the `{Summary; Results}` object for scripting (off by default). |

### Recommended order when applying a baseline

1. **Recon** (elevated) -- see where the machine stands. Sanity-check a few findings.
2. **`-WhatIf` Strike** -- review what would change (`-ShowDetails` for the full list).
3. **Snapshot the VM.**
4. **Real Strike, with `-ExcludeHighImpact` first** -- apply the safe majority, then re-Recon
   to confirm findings flip to Passed. The high-impact settings (VBS, the NTLM/Kerberos auth
   cluster, SMB signing, RDP/remote-mgmt disables) can render a machine unbootable or
   unreachable; apply them separately and deliberately, one area at a time, after the rest is
   stable and verified.
5. **Roll back** the snapshot.

### Strike safety gates

Strike refuses to apply unless all of these hold: `-Force` is supplied; a `-FindingList` is
named explicitly (it never guesses); the list's hash is in `lists/manifest.sha256`; and the
pre-Strike backup completed (override with `-SkipBackupCheck` only when you have a snapshot).

## Regenerating lists

After importing or editing lists you trust, refresh the integrity manifest so Strike will
accept them:

```powershell
.\Importers\Update-ListManifest.ps1     # rehashes lists into lists/manifest.sha256 -- commit it
```

See `Importers/README.md` for per-source import commands and the post-import validation step.
Signing (for running under `AllSigned`) is handled by `Sign-Module.ps1`; the threat model and
signing procedure are documented in that script's header and tracked in the CHANGELOG.
