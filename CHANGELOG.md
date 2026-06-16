# Changelog

All notable changes to HardeningTomcat are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/), and the project
uses semantic versioning. While in 0.x, minor versions may include breaking changes
(the schema and finding format are still settling).

Versions 0.2.0 - 0.4.0 are reconstructed retroactively from the development history;
they were real milestones that predate formal version tagging.

## [0.7.1]

Root-cause hardening of the value fixes from 0.7.0, plus documentation, so the
corrections survive list regeneration rather than living only in the committed JSON.

### Fixed
- **CIS list converter now normalizes "X or Y" values at import.**
  `Import-HardeningKittyList` detects registry recommended values phrased as
  "either acceptable" (e.g. `1 or 2`, `2 or 1`, `256 or 287`) and emits the `=or`
  operator instead of `=`. In 0.7.0 the JSON lists were patched directly, but the
  source CIS CSVs still carry these values with operator `=`, so regenerating any
  CIS list would have silently reintroduced the false-failure bug. The converter is
  the origin of the data, so fixing it there makes regeneration correct. (The
  GptTmpl.inf quote-stripping fix from 0.7.0 already closed the equivalent root cause
  on the Microsoft import path.)

### Documentation
- README: documented the `-ExcludeHighImpact` switch in the switches table and folded
  it into the recommended apply order as the safe first Strike. The high-impact class
  (VBS/Credential Guard, the NTLM/Kerberos auth cluster, required SMB signing, and
  RDP/WinRM/remote-management service disables) can render a machine unbootable or
  unreachable and should be applied separately and deliberately, after the rest is
  stable.

### Audited (no changes needed)
- Swept all 20 lists (6,981 findings) for the value-shape problems fixed in 0.7.0.
  All 6 CIS lists: 0 mis-operatored "X or Y" values, 0 quote-wrapped values,
  highImpact tags present. Both STIG lists (Win10 v2r1 CSV, Win11 V2R8 SCAP): clean of
  both problems -- the DoD benchmarks and the DISA SCAP/OVAL importer never produced
  "X or Y" prose or INF-style quoting, so no STIG-side fix was required. The
  registry-type inference and quote-stripping live in the Registry handler, so they
  protect every list regardless of source.

### Note on validation status
- Live end-to-end Strike validation (apply -> reboot -> re-Recon with Passed rising,
  no brick) has been performed for **CIS Windows 11 25H2 L1 with `-ExcludeHighImpact`**
  on real Windows 11. The other CIS lists and the STIG lists are confirmed structurally
  correct but are not yet live-Strike-validated; that remains a per-OS exercise on a VM.

## [0.7.0]

Strike (apply) path hardened, debugged, and made safe to run -- driven by an extended
live-VM Strike campaign that surfaced (and fixed) the real reasons a full CIS apply could
brick a machine, silently no-op, or report false failures.

### Added
- **`-ExcludeHighImpact` switch.** Skips findings flagged `highImpact` in the list: the
  boot/lockout/remote-access class that can render a machine unbootable or unreachable
  (VBS / Credential Guard, the NTLM/Kerberos auth cluster, required SMB signing, and
  RDP/WinRM/RemoteRegistry/LanmanServer service disables). 120 findings tagged across the
  CIS lists (28 in Win11 L1-L2). Recommended for a first Strike on any machine you can't
  easily recover; apply the excluded settings deliberately, one area at a time, afterward.
- **`=or` comparison operator.** CIS expresses some settings as "either value is
  acceptable" (e.g. `2 or 1`, `256 or 287`). The operator passes if the observed value
  matches any listed option, preserving that intent. 16 registry findings retagged from
  `=` to `=or`.
- **Crash-resilient diagnostic logging (`-Log`).** Each line is flushed to disk atomically,
  so the log's final line survives even a hard brick; every apply is logged *before* it
  runs with the exact registry path/key/value, so the last line names the setting being
  written at the moment of any failure. Adds a session header (mode/list/host/level) and
  millisecond timestamps. This is what turned a long-standing "mysterious brick" into a
  concrete, fixable bug list.
- **Batched secedit apply (`FlushApply` engine hook).** secedit changes are queued during
  the run and written in a single `secedit /configure` at the end, instead of one heavy
  Security Configuration Engine (scesrv) invocation per finding -- dramatically reducing
  resource demand. Handlers can now expose a generic `FlushApply` for end-of-run batching.

### Fixed
- **Registry values were all written as String (REG_SZ).** Settings Windows reads as
  DWORDs (the large majority) were being written as strings, so they silently took no
  effect -- the root cause of the long-running "Strike applied N but Passed never moved"
  mystery. Type is now inferred at apply time exactly as HardeningKitty does: numeric ->
  DWord, named exceptions (ScRemoveOption, AutoAdminLogon, etc.) -> String, multi-string
  items (Machine, NullSessionPipes/Shares, EccCurves) -> MultiString.
- **"X or Y" values written/compared as literal prose.** On apply, the value `256 or 287`
  was written verbatim; on audit, observed `2` was compared against the literal string
  `2 or 1` and always failed. Apply now resolves to the first (preferred) listed value;
  audit uses the new `=or` operator. (16 findings, both sides.)
- **Literal quote-wrapped values (18 Microsoft-list findings).** `ScRemoveOption = "1"`
  and `RestrictRemoteSAM = "O:BAG..."` carried INF-style wrapping quotes that would have
  been written into the registry. Fixed at the data level, defensively in the Registry
  handler, and at the root cause in `GptTmplInfParser` (INF string values are quoted).
- **Pre-Strike backup was failing and blocking every real Strike.** `SupportsShouldProcess`
  propagated `-WhatIf` into the backup's own `New-Item`, so the backup directory was only
  simulated and the subsequent `Get-Acl` failed. Backup operations now force
  `-WhatIf:$false` and guard directory existence.
- **secedit/scesrv "Not enough memory resources" (exit 2)** is now detected and surfaced
  as a clear, actionable message (free memory / reboot, then re-run) instead of a generic
  skip. Policy findings are still skipped, never falsely passed.
- **Absent services are a benign no-op.** A service that isn't installed (e.g. Browser,
  irmon -- present in CIS lists but not on every SKU) is reported as compliant rather than
  logged as an apply error.
- **`-WhatIf` output noise.** Dry-run now shows a one-line "would change N" count by
  default (full itemized list with `-ShowDetails`), and the spurious "What if: Set Alias"
  / per-finding cleanup chatter is suppressed.

### QA
- Scanned all 6,981 findings across the 20 lists for malformed values. Confirmed as *not*
  bugs (left as-is): 678 numeric registry value-names (legitimate IE-zone names),
  `Success and Failure` audit values (the correct auditpol value), AppLocker XML payloads,
  and 42 empty values (LegalNotice text/caption, NullSession pipes/shares -- empty *is* the
  hardened state).

### Validated on live Windows 11 (elevated)
- A full CIS Win11 25H2 L1-L2 Strike runs start-to-finish with per-apply logging; the
  diagnostic log proved the engine itself does not hang or crash mid-apply (any brick is
  the applied settings taking effect on reboot, e.g. VBS on a VM -- now fenced behind
  `-ExcludeHighImpact`).

### Still open (road to 1.0)
- End-to-end Strike verification on a clean, adequately-provisioned VM using
  `-ExcludeHighImpact` (apply -> gpupdate/reboot -> re-Recon should now show Passed rise,
  with the registry-type fix making applies effective).
- The ~83 mappable-but-manual STIG findings (audit/account/user-rights) remain `manual`
  by deliberate deferral.
- Code signing not yet run.

## [0.6.1]

Live-Windows validation of the CIS and STIG paths, plus report-clarity fixes.

### Validated on live Windows 11 (elevated)
- **CIS Windows 11 25H2 L1-L2** (591 findings, 0 skipped) and **DoD STIG Win11 V2R8**
  (115 registry findings; 108 manual correctly Skipped) ran fully elevated on real
  hardware. This closes the gap noted in 0.4.0/0.6.0: the CIS and STIG paths are no
  longer structurally-validated-only.
- **All ten handlers confirmed reading real system state**, including the five that had
  never run on live Windows: accountpolicy (password age/lockout), localaccount (Guest
  status, account names), MpPreferenceAsr (ASR actions), ProcessmitigationApplication
  (Exploit Protection ON/OFF values), and RegistryList.
- `manual` findings confirmed reporting as Skipped with their fixtext.

### Fixed
- **Malformed Detail string.** Finding detail read `Result=, Recommended=X` when the
  observed value was empty. Now reads `Observed=(not set), Recommended=X` -- and the
  label is `Observed=` (the value read) rather than the confusing `Result=` (which
  collides with the pass/fail Result column).
- **Opaque process-mitigation results.** When `Get-ProcessMitigation` has no data for a
  target, the handler now attaches a Note distinguishing "no data for this process (app
  may not be installed)" from "process exists but this property is unset." These remain
  genuine findings (not suppressed to pass -- an unset mitigation the STIG requires is
  real non-compliance), but the report is now interpretable instead of a bare blank.

### Still open (road to 1.0)
- Strike (apply) path validated only for the Microsoft baseline; needs a snapshotted-VM
  apply run across CIS/other handlers.
- The ~83 mappable-but-manual STIG findings (audit/account/user-rights) remain `manual`
  by deliberate deferral.
- Code signing not yet run.

## [0.6.0]

Authoritative DISA Windows 11 STIG support via a SCAP (XCCDF + OVAL) importer.

### Added
- **`Import-DisaStigScap.ps1`** -- parses a DISA SCAP 1.3 benchmark (the official
  XCCDF + OVAL data-stream from cyber.mil) directly, rather than relying on a third
  party's interpretation. Walks each XCCDF Rule to its OVAL definition, follows
  `extend_definition` wrapper chains to the real check, and resolves the test's
  object (what to read) and state (expected value + operation).
- **DoD STIG Windows 11 V2R8 list** -- 223 findings: 115 auto-converted to runnable
  `Registry` findings (paths, OVAL operations mapped to engine operators, CAT I/II/III
  mapped to severity), and 108 emitted as `manual` (carrying their real V-ID and
  fixtext) for checks that need human verification or use OVAL test types with no
  handler (WMI, NTFS effective rights, SID membership, cert-store enumeration).
- **`manual` as a first-class finding type.** The engine now treats a `manual` method
  or operator as Skipped, surfacing the remediation fixtext as the detail -- so manual
  STIG rules appear in the report instead of being dropped or falsely passed. Schema
  operator enum extended with `manual`.

### Notes
- Non-registry but mappable STIG checks (audit policy, account/lockout policy, user
  rights -- ~83 findings) are currently emitted as `manual`; extracting their OVAL
  args into runnable findings for the existing handlers is a planned follow-up.
- The Win11 STIG list and the importer are validated structurally and through the
  engine; the registry findings have not yet been run elevated on live Windows.

## [0.5.1]

QA and security-audit hardening. No new features -- correctness and safety fixes to
existing behavior.

### Fixed
- **Pre-Strike backup could silently report success.** The backup runs external exes
  (`secedit`/`reg`/`auditpol`) that set `$LASTEXITCODE` rather than throwing, so a
  failed export slipped past the `try/catch` and the backup reported `Complete=$true`.
  Because Strike's safety gate depends on that flag, a failed backup could have let
  Strike proceed without a real rollback. Now verifies exit codes and that output files
  exist with content.
- **secedit Apply always reported `Changed=$true`**, even when `secedit /configure`
  failed (external exe, no throw). Now checks `$LASTEXITCODE` and reports honestly.
- **secedit Apply INF-injection hardening:** the account-policy key/value are validated
  before being written into the security template (defense in depth on top of the list
  integrity manifest).
- **`contains` operator** treated an empty recommended substring as "matches everything";
  now rejects an empty needle (a security tool must not report an unjustifiable pass).

### Added
- `-RequireSignedHandlers` switch: the engine verifies each handler/helper Authenticode
  signature before loading and fails closed, independent of the OS execution policy.
- Signed file-catalog support (`HardeningTomcat.cat`) so the finding lists and manifest
  get a real, verifiable signature; `_Integrity.ps1` verifies it when present.
- Threat-model, execution-policy, upstream-trust, and non-exportable-key guidance in the
  README and signer; `.gitignore` now excludes cert/key artifacts.

## [0.5.0]

Coverage completion across benchmark families: full CIS method coverage plus DoD STIG.

### Added
- **`RegistryList` handler** -- checks whether a value appears among the enumerated
  entries under a key (e.g. device-installation deny lists). Completes coverage of every
  method used by real CIS / Microsoft / BSI benchmarks.
- **DoD STIG support:** new `ProcessmitigationApplication` handler (per-app Exploit
  Protection via `Get-ProcessMitigation`) and the DoD STIG Windows 10 v2r1 list
  (393 findings). Converter auto-routes output by family (stig/bsi/cis) and de-duplicates
  STIG V-IDs (which repeat across settings), preserving the original in `sourceId`.
- Version bumped from the declared 0.1.0; added this CHANGELOG.

## [0.4.0]

CIS integration and the first live-Windows validation. (Reconstructed.)

### Added
- **CIS benchmark support:** `Import-HardeningKittyList.ps1` converts HardeningKitty CSV
  lists (Apache-2.0, with attribution) to HardeningTomcat JSON. Six CIS lists: Windows 11
  25H2 (L1 and L1+L2), Server 2016/2019/2022 (L1), Server 2022 (L1+L2).
- **CIS L1/L2 levels:** `level` schema field and a `-Level 1|2` engine filter; per-finding
  levels derived by cross-referencing the L1 list against the combined list.
- **Three handlers for CIS coverage:** `accountpolicy`, `localaccount`, and
  `MpPreferenceAsr` (Defender Attack Surface Reduction rules).
- `auditpol` handler now matches subcategories by both name (Microsoft) and GUID (CIS).
- `Level` column in the CSV report; richer per-method "Checked" descriptions.
- UX: dual-mode progress display (custom colored ASCII bar / native `Write-Progress`
  fallback), concise summary by default with `-ShowDetails`, `-PassThru` for scripting,
  up-front elevation warning, clean aligned summary (replaced a raw hashtable dump).

### Fixed
- **Forward-slash registry paths:** `Split-Path` mangled backslashes into forward slashes
  when the importer ran on macOS; fixed at source and defensively in the handler, all
  lists regenerated.
- **`set=` crash on empty SID sets** (`Compare-Object` rejects empty input).
- **CIS level mis-tagging:** combined lists were flat-tagged all-L2; now correctly split.
- **`accountpolicy` name fragility:** secedit keys baked into args at import time.
- **PowerShell 5.1 encoding:** em-dashes broke module import under 5.1's ANSI encoding;
  all sources cleaned to ASCII and saved UTF-8-BOM.
- Cross-platform admin check (`GetCurrent()` threw on non-Windows).

### Validated on live Windows 11
- Scope: the **Microsoft** Win11 baseline with the original handlers (Registry, secedit,
  auditpol, accesschk). The CIS handlers added in this version (accountpolicy,
  localaccount, MpPreferenceAsr) were NOT validated on live hardware -- only structurally
  and via the engine on macOS.
- Recon read path across Registry/secedit/auditpol/accesschk on real hardware.
- Strike applied the Microsoft Win11 baseline; re-Recon confirmed findings flipped to
  Passed (16 -> 367 Passed, 28% -> 93.5%).

## [0.3.0]

Enforcement, integrity, and the security/performance hardening pass. (Reconstructed.)

### Added
- **`accesschk` handler** (user-rights assignments) and the **`set=` operator** for
  order-independent SID-set equality, resolving account names to SIDs on both sides.
- **Schema validation** at load (fail-fast, collects all problems).
- **Pre-Strike backup** of secedit/registry/auditpol state, ACL-locked to SYSTEM +
  Administrators; a failed backup halts Strike (override with `-SkipBackupCheck`).
- **secedit Apply** path.
- **Finding-list integrity:** SHA256 manifest (`lists/manifest.sha256`); Strike refuses
  unlisted/tampered lists, Recon/Survey warn. Signature-aware for later signing.

### Fixed / Security
- Prefetch failures (secedit/auditpol/accesschk) now Skip rather than silently passing.
- Cleaned up sensitive temp policy dumps.

### Performance
- Single registry read per finding (was double; closes a TOCTOU gap).
- Group findings by method once (O(n)); hoist hostname lookup out of the per-finding loop.

## [0.2.0]

Real baseline content: the Microsoft Security Compliance Toolkit importer. (Reconstructed.)

### Added
- **Microsoft SCT baseline importer** (`Import-MicrosoftBaseline.ps1` and parsers for
  registry.pol / GptTmpl.inf / audit.csv) -- turns Microsoft's own GPO backups into
  finding lists rather than relying on hand-authored or third-party content.
- **Server role-splitting:** server baselines bundle multiple GPOs, so the importer reads
  the GPO manifest and splits each into Member Server and Domain Controller lists via
  `-Role`. Twelve Microsoft baselines: Win11 23H2/24H2/25H2 and Server
  2016/2019/2022/2025 (each role-split).
- **OS auto-detection** for Recon/Survey list selection; Strike never auto-selects.
  Warns on risky auto-select (server role ambiguity, release mismatch).
- Richer per-column CSV report (observed/recommended) and console failure display.

## [0.1.0]

Initial scaffolding.

### Added
- Handler-registry engine (scriptblock hashtables, not classes, for PowerShell 5.1
  compatibility), unified audit/apply loop, three modes (Recon / Survey / Strike).
- Typed JSON finding format with a JSON schema.
- Four handlers: Registry, service, auditpol, secedit.
- Signing helper and the first Microsoft baseline import.
- Runs on Windows PowerShell 5.1 and PowerShell 7+.
