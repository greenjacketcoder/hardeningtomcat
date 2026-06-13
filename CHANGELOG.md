# Changelog

All notable changes to HardeningTomcat are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/), and the project
uses semantic versioning. While in 0.x, minor versions may include breaking changes
(the schema and finding format are still settling).

Versions 0.2.0 - 0.4.0 are reconstructed retroactively from the development history;
they were real milestones that predate formal version tagging.

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
- Recon read path across Registry/secedit/auditpol/accesschk on real hardware.
- Strike applied the Win11 baseline; re-Recon confirmed findings flipped to Passed
  (16 -> 367 Passed, 28% -> 93.5%).

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
