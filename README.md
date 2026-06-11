# HardeningTomcat (beta)

A ground-up, modular rewrite inspired by HardeningKitty's problem domain — **not** a fork.
Where HardeningKitty uses one ~3,400-line signed module with a 21-branch method ladder and
separate audit/apply loops, HardeningTomcat uses a **pluggable handler architecture** with a
**single unified loop** and a **typed JSON finding format**.

> **BETA. Recon freely. Strike only on a disposable VM with a snapshot.** The `Strike`
> (apply) path writes to the system and is deliberately gated behind `-Force`.

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
├── Private/_Helpers.ps1        shared helpers, dot-sourced before handlers
├── Schema/Finding.schema.json  the new finding format
├── lists/sample_machine.json   4-finding demo list
└── Sign-Module.ps1             signs EVERY script in the tree (run when stable)
```

## Usage

```powershell
Import-Module .\HardeningTomcat.psd1

# 1) Recon (read-only, safe) — observe and assess, change nothing
Invoke-HardeningTomcat -Mode Recon -FindingList .\lists\sample_machine.json -Report

# 2) Survey (dump current values, no pass/fail)
Invoke-HardeningTomcat -Mode Survey -FindingList .\lists\sample_machine.json

# 3) Dry-run the Strike path (shows what WOULD change, changes nothing)
Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\sample_machine.json -Force -WhatIf

# 4) Strike for real — ONLY on a throwaway VM with a snapshot
Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\sample_machine.json -Force
```

`-Filter` accepts a scriptblock over findings, e.g. `-Filter { $_.severity -eq 'High' }`.

## Staged testing plan (do these in order)

1. **Recon on the VM.** Confirm results look sane vs. a known state. Cross-check a few
   findings against HardeningKitty running the equivalent checks — they should agree.
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

- 17 of 21 methods still to port (RegistryList, accesschk, CimInstance, Mp* Defender
  family, BitLocker, Processmitigation, bcdedit, FirewallRule, ScheduledTask,
  WindowsOptionalFeature, accountpolicy, localaccount, LanguageMode).
- `secedit` apply (read-only for now).
- Backup/restore export before Strike (planned before apply is considered trustworthy).
- JSON Schema validation at load time (schema exists; runtime enforcement is a TODO).
