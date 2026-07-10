# How to Run a Safe Strike (and Undo One)

You'll apply a baseline's recommended values to a machine with every safety net
engaged, and know exactly how to reverse any change afterward. Strike **writes
to system configuration** — this is the one mode that can break a machine.

> **The golden rule:** first Strike on a machine you can revert. A VM snapshot
> beats every rollback mechanism below.

## Prerequisites

- A completed [Recon audit](tutorial-first-audit.md) of the target machine.
- An elevated **64-bit** PowerShell (Strike refuses to run from a 32-bit
  process on 64-bit Windows — registry writes would land in the wrong view).
- A VM snapshot or full backup of the target.
- The exact finding list you intend to apply, reviewed in Recon. Strike never
  auto-selects a list.

## Steps

1. **Preview what would change** — dry-run with `-WhatIf`:

   ```powershell
   Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\cis\CIS_Windows_11_25H2_L1-L2.json -Level 1 -Force -WhatIf -ShowDetails
   ```

   This runs Strike's full logic but writes no configuration. `-ShowDetails`
   lists every would-change item. (The backup directory is still created — that
   proves the safety net works before you rely on it.)

2. **Snapshot the VM.** Do this after the dry-run, immediately before the real run.

3. **Apply the safe majority first** — exclude the boot/lockout/remote-access
   class on the first pass:

   ```powershell
   Invoke-HardeningTomcat -Mode Strike -FindingList .\lists\cis\CIS_Windows_11_25H2_L1-L2.json -Level 1 -Force -ExcludeHighImpact -Log
   ```

   Strike only proceeds when all gates hold: `-Force` supplied, list named
   explicitly, list hash present in `lists/manifest.sha256`, and the pre-Strike
   backup completed. `-Log` writes a flushed-per-line log file — if a specific
   apply hangs the machine, the log's last line names the exact setting.

4. **Re-Recon** to confirm findings flipped to Passed, and use the machine for a
   while (log in, RDP if you need it, reboot once).

5. **Apply the high-impact settings deliberately**, one area at a time, e.g.:

   ```powershell
   Invoke-HardeningTomcat -Mode Strike -FindingList <list> -Force -Filter { $_.highImpact -and $_.category -match 'SMB' }
   ```

## Verification

Re-run Recon with `-ReportHtml` and compare the score to the pre-Strike report.
Applied findings show as Passed; `Apply FAILED` items (if any) are counted red
in the Strike summary and detailed in the `-Log` file.

## What the backup directory contains

Every real Strike first writes `hardeningtomcat_backup_<HOST>_<timestamp>\`
(ACL-restricted to SYSTEM + Administrators):

| File | Contents | Restore with |
|---|---|---|
| `secpol-backup.inf` | Security policy: account policy, user rights, security options | `secedit /configure /db seceditrestore.sdb /cfg secpol-backup.inf` |
| `auditpol-backup.csv` | Advanced audit policy | `auditpol /restore /file:auditpol-backup.csv` |
| `reg-software-policies.reg` | `HKLM\SOFTWARE\Policies` subtree | double-click / `reg import` |
| `reg-lsa.reg` | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` subtree | `reg import` |
| `services-starttype.csv` | Every service's start type before the run | script per-service `Set-Service` |
| `defender-preferences.xml` | Defender/ASR preferences (CliXml, best-effort) | `Import-Clixml` + `Set-MpPreference` |
| `undo-journal.jsonl` | **Per-finding pre-change record for every applied finding** | see below |

The subtree exports can't cover every path Strike touches; the **undo journal
is the complete record**.

## Undo a Strike with the journal

`undo-journal.jsonl` gains one JSON line per applied finding, written *before*
each apply:

```json
{"ts":"2026-07-10T14:35:22.1234567-04:00","id":"1120","method":"Registry","args":{"path":"HKLM:\\SOFTWARE\\Policies\\Example","name":"ExampleValue"},"found":true,"observed":"0","recommended":"1"}
```

- `found: true` + `observed` — the value the setting had before Strike. To undo,
  set it back to `observed` (e.g. `Set-ItemProperty -LiteralPath $args.path -Name $args.name -Value $observed`).
- `found: false` — the setting **did not exist** before Strike. To undo, delete
  the value Strike created rather than writing `observed` back.
- Work bottom-up (last applied, first undone) if changes might interact.

For wholesale rollback of policy areas, prefer the table above (`secedit
/configure`, `auditpol /restore`, `reg import`) — the journal is for surgical,
per-finding reversals.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Strike mode WRITES to the system. Re-run with -Force` | The `-Force` gate — deliberate. Add `-Force` only once you have a snapshot. |
| `No finding list specified` | Strike never guesses. Pass `-FindingList` explicitly. |
| `Strike blocked: ...manifest...` | The list's hash isn't in `lists/manifest.sha256`. If you edited/imported the list intentionally, run `.\Importers\Update-ListManifest.ps1`. |
| `Strike halted: the pre-Strike backup did not complete` | Fix the logged backup failure, or accept the risk with `-SkipBackupCheck` **only** with a snapshot. |
| Warning about unsigned integrity manifest | `manifest.sha256` detects corruption, not tampering. Run `Sign-Module.ps1` for a signed catalog. |
| Machine unreachable after Strike | You applied the high-impact class — this is why `-ExcludeHighImpact` and snapshots exist. Restore the snapshot. |

## Related

- [Invoke-HardeningTomcat reference](reference-invoke-hardeningtomcat.md) — every switch and gate
- [Engine architecture](explanation-architecture.md) — why apply and audit share one loop
