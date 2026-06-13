# Changelog

All notable changes to HardeningTomcat are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/), and the project
uses semantic versioning. While in 0.x, minor versions may include breaking changes
(the schema and finding format are still settling).

## [0.5.0]

The "core proven, coverage filling in" release. Both audit (Recon) and enforcement
(Strike) have now been validated on a live Windows 11 system, the architecture is
stable, and coverage spans three benchmark families (Microsoft, CIS, DoD STIG).

### Added
- **CIS benchmark support.** Converter (`Import-HardeningKittyList.ps1`) turns
  HardeningKitty CSV finding lists (Apache-2.0) into HardeningTomcat JSON, with
  attribution. Six CIS lists: Windows 11 25H2 (L1 and L1+L2), Server 2016/2019/2022
  (L1), and Server 2022 (L1+L2).
- **CIS L1/L2 levels.** New `level` field in the schema and a `-Level 1|2` engine
  filter (L1 runs level-1 only; L2 runs L1+L2; findings without a level always run).
  Per-finding levels derived by cross-referencing the L1 list against the combined list.
- **DoD STIG support.** New `ProcessmitigationApplication` handler (Exploit Protection
  settings via `Get-ProcessMitigation`) and the DoD STIG Windows 10 v2r1 list
  (393 findings). Converter auto-routes output by family (stig/bsi/cis) and de-duplicates
  STIG V-IDs (which legitimately repeat across settings), preserving the original in a
  `sourceId` field.
- **Five new handlers** beyond the original four: `accesschk` (user rights),
  `accountpolicy`, `localaccount`, `MpPreferenceAsr` (Defender ASR rules),
  `RegistryList`, and `ProcessmitigationApplication`. Ten handlers total, covering
  every method used by real CIS, Microsoft, and STIG benchmarks.
- **Two comparison operators** `<` and `>` (strict), bringing the total to ten.
- **`set=` operator** for order-independent user-rights SID-set equality, resolving
  account names to SIDs on both sides.
- **Microsoft SCT importer** with server role-splitting: reads Microsoft's GPO backups
  (registry.pol / GptTmpl.inf / audit.csv) and splits server baselines into Member
  Server and Domain Controller lists via `-Role`. Twelve Microsoft baselines: Win11
  23H2/24H2/25H2 and Server 2016/2019/2022/2025 (each role-split).
- **Finding-list integrity.** SHA256 manifest (`lists/manifest.sha256`); Strike refuses
  unlisted or tampered lists, Recon/Survey warn. Signature-aware for when signing lands.
- **Pre-Strike backup** of secedit/registry/auditpol state, with the backup directory
  ACL-locked to SYSTEM + Administrators. Failed backup halts Strike (override with
  `-SkipBackupCheck`).
- **OS auto-detection** for Recon/Survey list selection (Strike never auto-selects).
- **Dual-mode progress display:** custom colored ASCII bar on capable hosts, native
  `Write-Progress` fallback on the legacy 5.1 console.
- **Up-front elevation warning** that counts how many findings will Skip when not admin.
- **CSV report** (`-Report`) with a `Level` column and readable per-method "Checked"
  descriptions. `-PassThru` returns the structured result object for scripting.
- **Clean formatted summary** block (replaced a raw hashtable dump).

### Fixed
- Forward-slash registry paths: `Split-Path` mangled backslashes into forward slashes
  when the importer ran on macOS. Fixed at the source and defensively in the handler;
  all lists regenerated.
- `accesschk` silent-pass: unreadable user-rights now report Skipped, never a false pass.
- Prefetch failures (secedit/auditpol/accesschk) now throw and Skip rather than being
  invisible.
- `set=` crash on empty SID sets (`Compare-Object` rejects empty input).
- `accountpolicy` secedit keys baked into args at import time (case-insensitive), instead
  of fragile runtime name matching.
- `auditpol` now matches subcategories by both name (Microsoft) and GUID (CIS).
- PowerShell 5.1 encoding: em-dashes mojibaked under 5.1's ANSI encoding and broke module
  import; all sources cleaned to ASCII and saved UTF-8-BOM.
- Cross-platform admin check (`GetCurrent()` threw on non-Windows).

### Security & performance
- Registry reads use a single `Get-ItemProperty` (removed redundant `Test-Path`, halving
  round-trips and closing a TOCTOU gap).
- Prefetch groups findings by method once (O(n)).
- Sensitive INF/policy dumps cleaned up after use.

### Validated on live Windows 11
- Recon: full read path across Registry/secedit/auditpol/accesschk on real hardware.
- Strike: applied the Win11 baseline; re-Recon confirmed findings flipped to Passed
  (16 -> 367 Passed, 28% -> 93.5%).

### Known limitations (the road to 1.0)
- Apply paths for most methods are implemented but unproven on a live system (only the
  Win11 Strike has run); `accesschk`/`accountpolicy`/`localaccount`/`ProcessmitigationApplication`
  Apply are intentionally read-only in beta.
- The newest handlers (`accountpolicy`, `localaccount`, `MpPreferenceAsr`,
  `ProcessmitigationApplication`) are validated structurally and via the engine, but not
  yet against live Windows data.
- Code signing (`Sign-Module.ps1`) not yet run; integrity verification activates fully
  once signing is done.

## [0.1.0]

Initial scaffolding: handler-registry engine, unified audit/apply loop, typed JSON
finding format with schema, four handlers (Registry, service, auditpol, secedit),
signing helper, and the first Microsoft baseline import.
