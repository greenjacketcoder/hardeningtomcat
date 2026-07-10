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

## Documentation

| Doc | For |
|---|---|
| [Tutorial: your first audit](docs/tutorial-first-audit.md) | Zero to a scored HTML report in 3 steps (read-only) |
| [How to run a safe Strike](docs/howto-safe-strike.md) | The apply workflow, every safety gate, backup contents, and **undoing changes with the undo journal** |
| [Invoke-HardeningTomcat reference](docs/reference-invoke-hardeningtomcat.md) | Every parameter, gate, result status, operator, and the -PassThru shape |
| [Finding list format](docs/reference-finding-list-format.md) | The typed JSON schema, validation rules, and integrity model |
| [Why the engine is built this way](docs/explanation-architecture.md) | Handler registry, one-loop design, honest failure — with trade-offs |
| [Importers](Importers/README.md) | Generating lists from Microsoft SCT / CIS / STIG sources |

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

## Quick start

Run in an **elevated** PowerShell (Administrator):

```powershell
Import-Module .\HardeningTomcat.psd1
Invoke-HardeningTomcat -Mode Recon -ReportHtml   # read-only audit + HTML report
```

That is a complete read-only audit -- the [tutorial](docs/tutorial-first-audit.md)
walks through it step by step. Every switch, mode, operator, and safety gate is in
the [Documentation](#documentation) table above. **Read
[How to run a safe Strike](docs/howto-safe-strike.md) before ever using Strike --
it writes to the system.**
