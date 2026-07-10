# Finding List Format Reference

Finding lists are typed JSON validated against
[`Schema/Finding.schema.json`](../Schema/Finding.schema.json) — the cleaner
replacement for the legacy HardeningKitty CSV format. Lists under `lists/` are
**generated** from authoritative sources by the scripts in
[`Importers/`](../Importers/README.md), not hand-authored.

## List shape

```json
{
  "listName": "Windows Server 2022 Machine - CIS L1",
  "version": "1.0",
  "scope": "machine",
  "description": "optional",
  "findings": [ ... ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `listName` | yes | Human name; also used in report filenames (sanitized). |
| `version` | yes | List version, independent of engine version. |
| `scope` | no | `machine` (needs elevation) or `user`. |
| `findings` | yes | Array of finding objects. |

## Finding shape

```json
{
  "id": "1120",
  "name": "Interactive logon: Machine inactivity limit",
  "category": "Security Options",
  "method": "Registry",
  "args": { "path": "HKLM:\\SOFTWARE\\...\\System", "name": "InactivityTimeoutSecs" },
  "operator": "<=!0",
  "recommendedValue": "900",
  "defaultValue": "0",
  "severity": "Medium",
  "level": 1,
  "highImpact": false
}
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable unique ID. Duplicates fail list validation. |
| `name` | yes | Human-readable finding name. |
| `category` | no | Grouping used in reports and the failed-by-category chart. |
| `method` | yes | Which handler evaluates it — must match a handler's `Name`. |
| `args` | no | Method-specific arguments; each handler documents the keys it reads (e.g. Registry: `path`, `name`). |
| `operator` | yes | Comparison the engine applies — see the [operator table](reference-invoke-hardeningtomcat.md#operators). |
| `recommendedValue` | yes* | Target value (string/number/boolean; compared as string or int64 per operator). *May be legitimately empty, e.g. a user right held by no one. |
| `defaultValue` | no | Value assumed when the setting is absent (`Found=$false`). |
| `severity` | yes | `Low` / `Medium` / `High` — the grade if the finding **fails**. |
| `level` | no | CIS level `1` or `2`; drives the `-Level` filter. Absent on Microsoft lists. |
| `highImpact` | no | `true` marks the boot/lockout/remote-access risk class; `-ExcludeHighImpact` skips these. |

## Methods

The schema enumerates the full method vocabulary; a method is usable when a
matching handler file exists in `Handlers/`. Currently implemented:

`Registry`, `RegistryList`, `secedit`, `auditpol`, `accountpolicy`,
`localaccount`, `accesschk`, `service`, `MpPreferenceAsr`,
`ProcessmitigationApplication`

Schema-reserved for future handlers (findings using them are Skipped with "No
handler for method"): `WindowsOptionalFeature`, `CimInstance`,
`BitLockerVolume`, `LanguageMode`, `MpComputerStatus`, `MpPreference`,
`MpPreferenceExclusion`, `Processmitigation`, `bcdedit`, `FirewallRule`,
`ScheduledTask`. The `manual` method/operator marks findings requiring human
verification — reported Skipped with their remediation text.

## Load-time validation (fail-fast)

Every list is validated before any finding runs; **all** problems are reported
at once, and any problem aborts the run:

- Required fields present on every finding (`id`, `name`, `method`, `operator`,
  `recommendedValue`†, `severity`). †empty allowed.
- `operator` and `severity` values from the allowed sets.
- No duplicate `id`s.
- `=or` only on `Registry` findings (other methods would write the literal
  "X or Y" prose to the system).
- No wildcard characters (`* ? [ ]`) in `Registry`/`RegistryList` `args.path` —
  the registry provider glob-expands them, which would fan a single Strike
  write across every matching key.

## Integrity

`lists/manifest.sha256` records each list's SHA256. Strike refuses lists whose
hash isn't in the manifest; Recon/Survey warn and proceed (read-only). The list
file is read **once** into memory and both hashed and parsed from that same
buffer, so a file swapped mid-run can't pass verification. After editing or
importing a list you trust, refresh the manifest:

```powershell
.\Importers\Update-ListManifest.ps1
```

The plain-text manifest detects accidental corruption; tamper resistance
requires the signed catalog from `Sign-Module.ps1`.

## Related

- [Importers](../Importers/README.md) — generating lists from Microsoft SCT / CIS / STIG sources
- [Invoke-HardeningTomcat reference](reference-invoke-hardeningtomcat.md)
