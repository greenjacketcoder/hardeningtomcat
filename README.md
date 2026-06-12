# HardeningTomcat (beta)

```
          ____
       __/ o.o\__     recon . survey . strike
   ~~ |  TOMCAT  |>==>
       \__\___/__/     Windows hardening, locked on
```

**HardeningTomcat** audits and hardens a Windows system against a finding list (JSON).
Settings are read from the registry, security policy, audit policy, and user-rights
assignments, scored, and can optionally be applied. It is an independent, from-scratch
implementation **inspired by** [scipag/HardeningKitty](https://github.com/scipag/HardeningKitty)
-- **not a fork** -- built around a pluggable handler architecture, a unified audit/apply
loop, and a typed JSON finding format.

Three modes: **Recon** (read-only audit), **Survey** (dump current values), **Strike**
(apply hardening -- gated behind `-Force`).

Versioning: the engine is independently versioned; finding-list content is versioned
separately per list. The tool was developed for English systems; analysis on other
languages may be incorrect.

> **BETA. Recon freely. Strike only on a disposable VM with a snapshot.** The `Strike`
> (apply) path writes to the system and is deliberately gated behind `-Force`. The engine
> and 5 of 21 check methods are implemented (Registry, service, auditpol, secedit,
> accesschk), plus direct import of Microsoft SCT baselines for Windows 11 and Server
> 2016/2019/2022/2025. Runs on Windows PowerShell 5.1 and PowerShell 7+.

## Why this exists / what's better

- **Handler registry, not a giant if/elseif.** Each method (`Registry`, `service`, `auditpol`,
  `secedit`, `accesschk`) is one file in `Handlers/` returning `@{ Name; Test; Apply; Prefetch }`.
  Adding a method = adding a file. The engine never changes.
- **One loop for audit and apply.** No duplicated per-method logic, so no audit-vs-apply drift.
- **Prefetch batching.** The old engine spawned `auditpol.exe`/`secedit.exe` once *per finding*
  (hundreds of process launches). Handlers here run those **once per run** in `Prefetch` and
  cache the parsed result; every check becomes an in-memory lookup.
- **Honest failure reporting.** If a setting can't be read (e.g. `secedit`/`auditpol` export
  fails, or the session isn't elevated), the finding is reported **Skipped** -- never silently
  passed. A security tool must not claim compliance it couldn't verify.
- **Typed JSON findings.** Structured `args` per finding. Schema in `Schema/Finding.schema.json`,
  enforced at load time (bad lists fail fast with all problems listed).
- **Finding-list integrity.** Lists are hashed into `lists/manifest.sha256`. Strike refuses a
  list whose hash isn't in the manifest; Recon/Survey warn but proceed. Defends against a
  tampered list silently weakening a system.
- **Runs on Windows PowerShell 5.1 and PowerShell 7+.** (5.1 support is why handlers are
  scriptblock-hashtables, not classes; sources are ASCII / UTF-8-BOM for 5.1 compatibility.)

## Layout

```
HardeningTomcat/
├── HardeningTomcat.psd1        manifest (Desktop + Core)
├── HardeningTomcat.psm1        engine: loader, unified loop, operators, scoring, progress
├── Handlers/
│   ├── _CONTRACT.md            the handler interface spec
│   ├── Registry.ps1            Test + Apply
│   ├── service.ps1             Test + Apply
│   ├── auditpol.ps1            Prefetch (batched) + Test + Apply
│   ├── secedit.ps1             Prefetch (batched) + Test + Apply
│   └── accesschk.ps1           Prefetch (batched) + Test  (user-rights; Apply gated in beta)
├── Importers/                  pull finding lists from authoritative baselines
│   ├── Import-MicrosoftBaseline.ps1   orchestrator: SCT baseline -> JSON list
│   ├── SctManifest.ps1         reads GPO manifest.xml; role selection for server baselines
│   ├── RegistryPolParser.ps1   parses the binary registry.pol format
│   ├── GptTmplInfParser.ps1    parses GptTmpl.inf (account policy / security options)
│   ├── AuditCsvParser.ps1      parses audit.csv (advanced audit policy)
│   ├── Regenerate-AllBaselines.ps1    rebuilds every list in one pass
│   ├── Update-ListManifest.ps1        (re)generates lists/manifest.sha256
│   └── tests/                  synthetic sample for parser validation
├── Private/
│   ├── _Helpers.ps1            shared helpers (registry read, etc.)
│   ├── _OsDetect.ps1           OS family/release detection for auto-select
│   ├── _Backup.ps1            pre-Strike state export (secedit/registry/auditpol)
│   └── _Integrity.ps1         finding-list hash/signature verification
├── Schema/Finding.schema.json  the finding format
├── lists/
│   ├── manifest.sha256         integrity manifest (trusted list hashes)
│   ├── sample_machine.json     small demo list
│   └── microsoft/              12 generated baselines (Win11 + Server, role-split)
└── Sign-Module.ps1             signs EVERY script in the tree (run when stable)
```

## Usage

```powershell
# Run elevated (Administrator) -- user-rights, audit policy, and security policy
# require elevation. Non-elevated runs warn up front and Skip those findings.
Import-Module .\HardeningTomcat.psd1

# 1) Recon (read-only, safe) -- observe and assess, change nothing.
#    With no -FindingList, it auto-detects the OS and picks the matching list.
Invoke-HardeningTomcat -Mode Recon -Report
#    Or name a list explicitly:
Invoke-HardeningTomcat -Mode Recon -FindingList .\lists\microsoft\Microsoft_Windows_11_25H2_-_Machine.json -Report

# 2) Survey (dump current values, no pass/fail) -- also auto-detects if no list given
Invoke-HardeningTomcat -Mode Survey

# 3) Dry-run the Strike path (shows what WOULD change, changes nothing)
Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\...json -Force -WhatIf

# 4) Strike for real -- ONLY on a throwaway VM with a snapshot.
#    Strike NEVER auto-selects a list; you must name it explicitly.
Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\...json -Force
```

### Switches

| Switch | Effect |
|--------|--------|
| `-Report` | Write a per-finding CSV (auto-named, or use `-ReportFile`). |
| `-ShowDetails` | Print every failed/skipped finding to the console (off by default; summary only). |
| `-Force` | Required for Strike. Without it, apply mode refuses to run. |
| `-WhatIf` | Strike dry-run: handlers report what they *would* change. |
| `-Filter {…}` | Scriptblock over findings, e.g. `-Filter { $_.severity -eq 'High' }`. |
| `-BackupDir <path>` | Override the pre-Strike backup location. |
| `-SkipBackupCheck` | Let Strike proceed even if the pre-Strike backup fails (use only with a VM snapshot). |
| `-PassThru` | Return the `{Summary; Results}` object for scripting (off by default). |

### List selection

- **Recon / Survey** (read-only): if `-FindingList` is omitted, HardeningTomcat detects the
  running OS (product family + release, e.g. "Windows 11 24H2") and auto-selects the
  best-matching list under `lists/`. Server baselines are role-specific, so if detection is
  ambiguous (Member Server vs Domain Controller) it warns. If nothing matches, it errors
  clearly rather than guessing. Override any time by naming a list.
- **Strike** (apply): **never** auto-selects -- applying changes from a guessed baseline is
  unsafe. You must pass `-FindingList` explicitly *and* `-Force`, and the list's hash must be
  in `lists/manifest.sha256`.

### Safety gates on Strike

Strike will refuse to apply when any of these fail:
1. `-Force` not supplied.
2. No explicit `-FindingList` (it never guesses for apply).
3. The list's hash is not in the integrity manifest (tampered / unknown list).
4. The pre-Strike backup did not complete (override with `-SkipBackupCheck`).

## Finding lists -- sourcing from Microsoft baselines

Finding lists are typed JSON (`Schema/Finding.schema.json`). Rather than hand-writing them or
depending on a third party's translation, `Importers/` pulls content **directly from Microsoft's
Security Compliance Toolkit (SCT)**.

Download the free SCT baseline, unzip it, and point the importer at its `GPOs\` folder:

```powershell
# Client baseline (single role):
.\Importers\Import-MicrosoftBaseline.ps1 `
    -BaselinePath "C:\...\Windows 11 v25H2 Security Baseline\GPOs" `
    -ListName "Microsoft Windows 11 25H2 - Machine"

# Server baselines bundle multiple GPOs (Member Server vs Domain Controller, etc.).
# Running with no -Role prints the available GPOs and stops. Then choose a role:
.\Importers\Import-MicrosoftBaseline.ps1 -BaselinePath "C:\...\Server 2022\GPOs" `
    -Role MemberServer    -ListName "Microsoft Windows Server 2022 - Member Server"
.\Importers\Import-MicrosoftBaseline.ps1 -BaselinePath "C:\...\Server 2022\GPOs" `
    -Role DomainController -ListName "Microsoft Windows Server 2022 - Domain Controller"
```

The importer reads Microsoft's own `registry.pol` / `GptTmpl.inf` / `audit.csv` artifacts,
including the `[Privilege Rights]` user-rights assignments (compared with the order-independent
`set=` operator). After importing or editing lists you trust, refresh the integrity manifest:

```powershell
.\Importers\Update-ListManifest.ps1     # rehashes lists into lists/manifest.sha256 -- commit it
```

`Regenerate-AllBaselines.ps1` rebuilds all 12 bundled lists in one pass (handy after an
importer change). See `Importers/README.md` for details and the post-import validation step.

**Levels (L1/L2).** Microsoft SCT baselines are single-tier and don't carry CIS-style levels.
Genuine L1/L2 tiering would require importing CIS Benchmark content (a separate, planned
source). Imported findings currently carry a defaulted severity.

## Comparison operators

Eight operators are supported: `=`, `!=`, `<=`, `>=`, `<=!0`, `contains`, `=|0`, and `set=`.
`set=` is order-independent set equality for user-rights SID lists, and resolves account names
to SIDs on both sides (so "Administrators" matches "S-1-5-32-544").

## Scoring

Passed = 4, Low = 2, Medium = 1, High = 0. Percentage is earned / max over graded (non-skipped)
findings.

## Staged testing plan (do these in order)

1. **Recon on the VM (elevated).** Confirm results look sane vs. a known state. Cross-check a
   few findings against the **baseline spreadsheet in the SCT** -- the imported
   `recommendedValue` should match.
2. **Survey mode.** Verify observed values are read correctly per method.
3. **`-WhatIf` Strike.** Read every "would set …" line. Make sure nothing is surprising.
4. **Real Strike on a snapshot.** Apply, re-Recon, confirm findings flip to Passed, then roll
   back the snapshot.

## Signing

Develop unsigned under `RemoteSigned` (or `Set-ExecutionPolicy -Scope Process Bypass`) while
iterating. Once the code is stable:

```powershell
# one-time cert (elevated)
New-SelfSignedCertificate -Subject "CN=Alex HardeningTomcat Signing" `
  -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5)
# trust it: export .cer, Import-Certificate into Cert:\CurrentUser\Root and \TrustedPublisher
# then sign the whole tree:
.\Sign-Module.ps1 -CertSubject "CN=Alex HardeningTomcat Signing"
```

Under `AllSigned`, **every** `.ps1` must be signed (the engine dot-sources handlers at
runtime), which is why `Sign-Module.ps1` globs the entire tree. The integrity check is already
signature-aware: if `lists/manifest.sha256` is signed, a broken signature is a hard failure in
all modes; signing it is the last step that closes the manifest-tampering gap.

## Status

**Implemented and exercised on a live Windows 11 system (Recon):**
- Engine: unified loop, 8 operators, scoring, schema validation, OS auto-detect, progress
  display (custom ASCII bar / native fallback), CSV report.
- 5 of 21 methods: Registry, service, auditpol, secedit, accesschk.
- Microsoft SCT import for Windows 11 (23H2/24H2/25H2) and Server 2016/2019/2022/2025, with
  role-splitting for server baselines (12 lists total).
- Finding-list integrity (SHA256 manifest; signature-aware).
- Pre-Strike backup + Strike safety gates.

**Implemented but not yet validated on a live system:**
- The Apply paths (Registry/service/auditpol/secedit) -- structurally complete, never executed
  against a real machine. Test on a snapshot before trusting.

**Not yet built:**
- 16 of 21 methods still to port (RegistryList, CimInstance, Mp* Defender family, BitLocker,
  Processmitigation, bcdedit, FirewallRule, ScheduledTask, WindowsOptionalFeature,
  accountpolicy, localaccount, LanguageMode, …).
- CIS importer (for L1/L2 levels) -- planned.
- accesschk Apply (user-rights write) -- read-only for now.
- Actual code-signing run (do last, once iteration settles).
