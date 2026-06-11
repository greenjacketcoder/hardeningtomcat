# HardeningTomcat (beta)

```
          ____
       __/ o.o\__     recon • survey • strike
   ~~ |  TOMCAT  |>==>
       \__\___/__/     Windows hardening, locked on
```

**HardeningTomcat** audits and hardens a Windows system against a finding list (JSON).
Settings are read from the registry and other sources, scored, and can optionally be
applied. It is an independent, from-scratch implementation **inspired by**
[scipag/HardeningKitty](https://github.com/scipag/HardeningKitty) — **not a fork** — built
around a pluggable handler architecture, a unified audit/apply loop, and a typed JSON
finding format.

Three modes: **Recon** (read-only audit), **Survey** (dump current values), **Strike**
(apply hardening — gated behind `-Force`).

Versioning: the engine is independently versioned (currently `0.1.0`); finding-list content
is versioned separately per list. The tool was developed for English systems; analysis on
other languages may be incorrect.

> **BETA. Recon freely. Strike only on a disposable VM with a snapshot.** The `Strike`
> (apply) path writes to the system and is deliberately gated behind `-Force`. The engine
> and 4 of 21 check methods are implemented (Registry, service, auditpol, secedit), plus
> direct import of Microsoft SCT baselines. Runs on Windows PowerShell 5.1 and PowerShell 7+.

## Why this exists / what's better

- **Handler registry, not a giant if/elseif.** Each method (`Registry`, `service`, `auditpol`,
  `secedit`, …) is one file in `Handlers/` returning `@{ Name; Test; Apply; Prefetch }`.
  Adding a method = adding a file. The engine never changes.
- **One loop for audit and apply.** No duplicated per-method logic, so no audit-vs-apply drift.
- **Prefetch batching.** The old engine spawned `auditpol.exe`/`secedit.exe` once *per finding*
  (hundreds of process launches). Handlers here run those **once per run** in `Prefetch` and
  cache the parsed result; every check becomes an in-memory lookup. This is the speedup that
  was impossible in the original without breaking its signature.
- **Typed JSON findings.** No more overloaded `MethodArgument` / `.Split(".")` hacks. Each
  finding has structured `args`. Schema in `Schema/Finding.schema.json`.
- **Runs on Windows PowerShell 5.1 and PowerShell 7+.** (5.1 support is why handlers are
  scriptblock-hashtables, not classes.)

## Layout

```
HardeningTomcat/
├── HardeningTomcat.psd1        manifest (Desktop + Core)
├── HardeningTomcat.psm1        engine: loader, unified loop, operators, scoring
├── Handlers/
│   ├── _CONTRACT.md            the handler interface spec
│   ├── Registry.ps1            Test + Apply
│   ├── service.ps1             Test + Apply
│   ├── auditpol.ps1            Prefetch (batched) + Test + Apply
│   └── secedit.ps1             Prefetch (batched) + Test  (Apply gated/null in beta)
├── Importers/                  pull finding lists from authoritative baselines
│   ├── Import-MicrosoftBaseline.ps1   orchestrator: SCT baseline → JSON list
│   ├── RegistryPolParser.ps1   parses the binary registry.pol format
│   ├── GptTmplInfParser.ps1    parses GptTmpl.inf (account policy / security options)
│   ├── AuditCsvParser.ps1      parses audit.csv (advanced audit policy)
│   └── tests/                  synthetic sample for parser validation
├── Private/_Helpers.ps1        shared helpers, dot-sourced before handlers
├── Schema/Finding.schema.json  the new finding format
├── lists/sample_machine.json   4-finding demo list
└── Sign-Module.ps1             signs EVERY script in the tree (run when stable)
```

## Usage

```powershell
Import-Module .\HardeningTomcat.psd1

# 1) Recon (read-only, safe) — observe and assess, change nothing
#    With no -FindingList, it auto-detects the OS and picks the matching list from lists/.
Invoke-HardeningTomcat -Mode Recon -Report
#    Or name a list explicitly:
Invoke-HardeningTomcat -Mode Recon -FindingList .\lists\microsoft\Microsoft_Windows_11_25H2_-_Machine.json -Report

# 2) Survey (dump current values, no pass/fail) — also auto-detects if no list given
Invoke-HardeningTomcat -Mode Survey

# 3) Dry-run the Strike path (shows what WOULD change, changes nothing)
Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\...json -Force -WhatIf

# 4) Strike for real — ONLY on a throwaway VM with a snapshot.
#    Strike NEVER auto-selects a list; you must name it explicitly (a deliberate safety barrier).
Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\...json -Force
```

### List selection (mirrors HardeningKitty's safe-default philosophy)

- **Recon / Survey** (read-only): if `-FindingList` is omitted, HardeningTomcat detects the
  running OS (product family + release, e.g. "Windows 11 24H2") and auto-selects the
  best-matching list under `lists/`. If nothing matches, it errors clearly rather than
  guessing wrong. You can always override by naming a list.
- **Strike** (apply): **never** auto-selects — applying changes from a guessed baseline is
  unsafe. You must pass `-FindingList` explicitly *and* `-Force`. This is the HardeningTomcat
  equivalent of HardeningKitty's deliberate refusal to default the apply path.

`-Filter` accepts a scriptblock over findings, e.g. `-Filter { $_.severity -eq 'High' }`.

## Finding lists — sourcing from authoritative baselines

Finding lists are typed JSON (`Schema/Finding.schema.json`). Rather than hand-writing them
or depending on a third party's translation, `Importers/` pulls content **directly from the
authoritative source**.

**Microsoft baselines (implemented).** Download the free **Security Compliance Toolkit (SCT)**
from the Microsoft Download Center, unzip the baseline you want, and point the importer at its
`GPOs\` folder:

```powershell
.\Importers\Import-MicrosoftBaseline.ps1 `
    -BaselinePath "C:\...\Windows 11 v24H2 Security Baseline\GPOs" `
    -ListName "Microsoft Windows 11 24H2 - Machine"
# writes lists\microsoft\<name>.json, then:
Invoke-HardeningTomcat -Mode Recon -FindingList .\lists\microsoft\<name>.json -Report
```

This reads Microsoft's own `registry.pol` / `GptTmpl.inf` / `audit.csv` artifacts — no
HardeningKitty in the chain — so every future Microsoft baseline works unchanged. See
`Importers/README.md` for coverage and the required post-import validation step.

**CIS / other (planned).** A CSV→JSON converter for HardeningKitty-format lists is the
intended path for CIS content, where those translations are a reasonable source.

## Staged testing plan (do these in order)

1. **Recon on the VM.** Confirm results look sane vs. a known state. For Microsoft lists,
   cross-check a few findings against the **baseline spreadsheet in the SCT** (the
   authoritative source) — the imported `recommendedValue` should match.
2. **Survey mode.** Verify observed values are being read correctly per method.
3. **`-WhatIf` Strike.** Read every "would set …" line. Make sure nothing surprising.
4. **Real Strike on a snapshot.** Apply, re-Recon, confirm findings flip to Passed,
   then roll back the snapshot.
5. Only after the 4 core handlers are trusted do we add the remaining 17 methods and
   wire up `secedit` apply (currently read-only by design).

## Scoring

Same model as the original: Passed = 4, Low = 2, Medium = 1, High = 0. Percentage is
earned / max over graded (non-skipped) findings.

## Signing

Develop unsigned under `RemoteSigned` (or `Set-ExecutionPolicy -Scope Process Bypass`)
while iterating. Once stable:

```powershell
# one-time cert (elevated)
New-SelfSignedCertificate -Subject "CN=Alex HardeningTomcat Signing" `
  -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5)
# trust it: export .cer, Import-Certificate into Cert:\CurrentUser\Root and \TrustedPublisher
# then sign the whole tree:
.\Sign-Module.ps1 -CertSubject "CN=Alex HardeningTomcat Signing"
```

Under `AllSigned`, **every** `.ps1` must be signed (the engine dot-sources handlers at
runtime), which is why `Sign-Module.ps1` globs the entire tree.

## Status / not yet built

- **Microsoft baseline import: working** (registry.pol / GptTmpl.inf / audit.csv → JSON).
  Pending: validation against a real SCT download, and `[Privilege Rights]` user-rights
  settings (need the `accesschk` handler).
- 17 of 21 methods still to port (RegistryList, accesschk, CimInstance, Mp* Defender
  family, BitLocker, Processmitigation, bcdedit, FirewallRule, ScheduledTask,
  WindowsOptionalFeature, accountpolicy, localaccount, LanguageMode).
- CIS importer (CSV→JSON converter) — planned.
- `secedit` apply (read-only for now).
- Backup/restore export before Strike (planned before apply is considered trustworthy).
- JSON Schema validation at load time (schema exists; runtime enforcement is a TODO).
- Imported findings carry a defaulted severity (Microsoft baselines lack CIS-style
  severities); per-finding severity tuning is a TODO.
