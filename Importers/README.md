# Importers — sourcing finding lists directly from authoritative baselines

This is the **sustainable, independent** path: HardeningTomcat reads Microsoft's own
baseline artifacts, with no third-party (e.g. HardeningKitty) translation in the chain.
Every future Microsoft baseline release works with these importers unchanged, because the
underlying file formats are stable and documented.

## Files

| File | Role |
|------|------|
| `RegistryPolParser.ps1` | Parses the binary `registry.pol` format (the core piece). Pure PowerShell, no external tools. |
| `GptTmplInfParser.ps1`  | Parses `GptTmpl.inf` security templates (account policy, security options). |
| `AuditCsvParser.ps1`    | Parses `audit.csv` advanced audit policy. |
| `Import-MicrosoftBaseline.ps1` | Orchestrator: walks an SCT baseline folder, runs the three parsers, maps to HardeningTomcat JSON. |

## How to get a Microsoft baseline

1. Download the **Security Compliance Toolkit (SCT)** from the Microsoft Download Center
   (search "Microsoft Security Compliance Toolkit"). It's a free, official package.
2. Inside, each baseline (e.g. "Windows 11 v24H2 Security Baseline") ships as a zip
   containing a `GPOs\` folder of GPO backups, plus `Documentation\` spreadsheets and
   the LGPO/PolicyAnalyzer tools.
3. Unzip the baseline you want.

## Run the importer

```powershell
.\Importers\Import-MicrosoftBaseline.ps1 `
    -BaselinePath "C:\path\to\Windows 11 v24H2 Security Baseline\GPOs" `
    -ListName "Microsoft Windows 11 24H2 - Machine" `
    -Scope machine
```

It writes a JSON list into `lists\microsoft\` and prints a per-method breakdown. Then:

```powershell
Import-Module .\HardeningTomcat.psd1
Invoke-HardeningTomcat -Mode Recon -FindingList .\lists\microsoft\<name>.json -Report
```

## IMPORTANT — validate before trusting

The `registry.pol` parser is proven against the documented format spec (and synthetic
test data in `tests/`). But a real baseline is the real test:

1. After importing, open the **baseline spreadsheet** that ships in the SCT `Documentation\`.
2. Pick ~5 settings (mix of registry, account policy, audit) and confirm the imported
   finding's `recommendedValue` matches the spreadsheet.
3. Only then run `Recon`, and only `Strike` on a snapshotted VM.

## Current coverage / known gaps

- **registry.pol** → Registry findings: full.
- **GptTmpl.inf [System Access]** → secedit findings: full.
- **GptTmpl.inf [Registry Values]** (security options) → Registry findings: full.
- **GptTmpl.inf [Privilege Rights]** (user-rights / SID lists) → **not yet** — needs the
  `accesschk` handler, which isn't built. These are skipped on import.
- **audit.csv** → auditpol findings: full.
- **Severity** is defaulted (Microsoft baselines don't carry CIS-style severity). Override
  per-finding after import, or we can add a severity-map later.

## Why not just use HardeningKitty's pre-made Microsoft lists?

That was the "bootstrap" shortcut. This importer exists so the tool doesn't depend on a
third party's translation cadence (the signed HardeningKitty repo hasn't moved in 18+
months). Sourcing from Microsoft directly is what makes HardeningTomcat sustainably
independent. The CSV-convert path still has a place for **CIS** content, where
HardeningKitty's translations are a reasonable source — that's a separate importer.
