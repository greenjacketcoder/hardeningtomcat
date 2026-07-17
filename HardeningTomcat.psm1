#Requires -Version 5.1

<#
.SYNOPSIS
    HardeningTomcat - a modular, handler-based Windows configuration audit & hardening engine.
    A ground-up rewrite inspired by HardeningKitty's problem domain, with a pluggable
    handler architecture, a unified audit/apply loop, and a typed JSON finding format.

.DESCRIPTION
    BETA SOFTWARE. The Recon and Survey modes only read. Strike mode WRITES to the
    system and must be run with -Confirm or -Force, ideally on a disposable VM with a
    snapshot. Recon thoroughly before you ever Strike.

.NOTES
    Runs on Windows PowerShell 5.1 and PowerShell 7+. Because of 5.1 constraints the
    handler model uses scriptblock hashtables, not classes.
#>

function Invoke-HardeningTomcat {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Recon', 'Survey', 'Strike')]
        [string] $Mode,

        # Optional for Recon/Survey (auto-detected from OS if omitted).
        # REQUIRED for Strike -- apply mode refuses to guess.
        [string] $FindingList,

        [switch] $Log,
        [string] $LogFile,
        [switch] $Report,
        [string] $ReportFile,

        # Self-contained HTML report: summary tiles, result-distribution and
        # failed-by-category charts, and a filterable findings table. Inline CSS/JS,
        # no network dependency -- opens offline and archives next to the CSV.
        [switch] $ReportHtml,
        [string] $ReportHtmlFile,

        # Required guard for Strike. Without it, apply mode refuses to run.
        [switch] $Force,

        # Optional override for the pre-Strike backup directory.
        [string] $BackupDir,

        # Proceed with Strike even if the pre-Strike backup fails. Use only when you
        # have another safety net (e.g. a VM snapshot) and accept the risk.
        [switch] $SkipBackupCheck,

        # Print every failed/skipped finding to the console. Off by default -- the run
        # shows a progress bar then the summary; full detail goes to the -Report CSV.
        [switch] $ShowDetails,

        # Return the {Summary; Results} object to the pipeline for scripting. Off by
        # default so interactive runs show only the formatted summary, not a raw dump.
        [switch] $PassThru,

        # Optional filter scriptblock over findings, e.g. { $_.severity -eq 'High' }
        [scriptblock] $Filter,

        # CIS level filter: 1 runs only L1 findings, 2 runs L1+L2. Findings without a
        # level field are always included (e.g. Microsoft-baseline lists carry no level).
        [ValidateSet('1','2')][string] $Level,

        # Defense-in-depth (Finding 5): when set, every handler/helper script must carry
        # a Valid Authenticode signature or the run aborts -- independent of the OS
        # execution policy. Off by default so unsigned development still works; turn on
        # once the tree is signed for belt-and-suspenders protection on top of AllSigned.
        [switch] $RequireSignedHandlers,

        # Skip findings flagged highImpact=true in the list. These are settings known to
        # risk bricking boot, locking out logon, or cutting remote access (e.g. VBS/
        # Credential Guard, the NTLM/Kerberos auth cluster, SMB signing required, RDP/
        # remote-management service disables). Recommended for Strike on machines you
        # can't easily recover, or when applying a baseline for the first time. Apply
        # the excluded settings deliberately, one area at a time, after the rest is stable.
        [switch] $ExcludeHighImpact
    )

    $ModuleRoot = $PSScriptRoot
    $script:StartTime = Get-Date

    # ---- Session context -------------------------------------------------------
    $script:HtHostname = $env:COMPUTERNAME   # read once; reused by every result row
    # Admin check is Windows-only; GetCurrent() throws on non-Windows, so guard it.
    $IsAdmin = $false
    try {
        $IsAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        $IsAdmin = $false   # not Windows, or identity unavailable
    }

    # 32-bit PowerShell on 64-bit Windows sees the WOW6432Node registry view: audits
    # would silently read -- and Strike would WRITE -- the wrong keys for hundreds of
    # HKLM\SOFTWARE findings. Refuse to apply from a redirected view; warn for reads.
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        if ($Mode -eq 'Strike') {
            throw "This is a 32-bit PowerShell process on 64-bit Windows: registry access is " +
                  "redirected to the WOW6432Node view, so hardening values would be written to " +
                  "the wrong keys. Re-run from a 64-bit PowerShell."
        }
        Write-Warning ("32-bit PowerShell on 64-bit Windows: registry reads are redirected " +
            "(WOW6432Node), so results for HKLM\SOFTWARE findings will be wrong. Use a 64-bit PowerShell.")
    }

    $Context = @{
        Mode      = $Mode
        IsAdmin   = $IsAdmin
        WhatIf    = $false      # set per-finding below for ShouldProcess dry-runs
        PSVersion = $PSVersionTable.PSVersion.Major
        Log       = {
            param($Text, $Level = 'Info')
            $stamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')
            Write-Verbose "[$stamp][$Level] $Text"
            if ($script:LogEnabled) {
                # AppendAllText opens, writes, and CLOSES the file each call -- so the
                # line is on disk immediately. Critical when diagnosing a crash/brick:
                # the LAST line in the log is the last thing the tool did before dying.
                # Logging must never take down a run: on write failure, note it via the
                # verbose stream (visible with -Verbose) and keep going.
                try { [System.IO.File]::AppendAllText($script:LogPath, "[$stamp][$Level] $Text`r`n") }
                catch { Write-Verbose "Log write to $script:LogPath failed: $($_.Exception.Message)" }
            }
        }
    }

    # ---- Logging setup ---------------------------------------------------------
    $script:LogEnabled = [bool]$Log
    if ($Log) {
        $script:LogPath = if ($LogFile) { $LogFile } `
            else { Join-Path (Get-Location) ("hardeningtomcat_log_{0:yyyyMMdd-HHmmss}.txt" -f $script:StartTime) }
        & $Context.Log "===== HardeningTomcat session start ====="
        & $Context.Log "Mode=$Mode List=$FindingList Level=$Level Force=$Force WhatIf=$WhatIfPreference"
        & $Context.Log "Host=$env:COMPUTERNAME Admin=$IsAdmin PSVersion=$($PSVersionTable.PSVersion)"
    }

    # ---- Strike safety gate ----------------------------------------------------
    if ($Mode -eq 'Strike' -and -not $Force) {
        throw "Strike mode WRITES to the system. Re-run with -Force to confirm you understand. " +
              "Strongly recommended: take a VM snapshot / backup first, and run Recon mode beforehand."
    }
    # Strike never guesses a list. It must be named explicitly.
    if ($Mode -eq 'Strike' -and -not $FindingList) {
        throw "No finding list specified. Strike mode will not auto-select a list -- applying " +
              "changes from a guessed baseline is unsafe. Specify -FindingList explicitly, and " +
              "choose it deliberately after reviewing it in Recon mode."
    }
    if ($Mode -eq 'Strike') {
        Write-Warning "Strike mode applies changes to THIS system. Ensure you have a backup/snapshot."
    }

    # Pre-load CimCmdlets now (with WhatIf forced off) so its alias registration doesn't
    # later auto-trigger inside a -WhatIf scope and spray "What if: Set Alias" lines when
    # a handler first calls Get-CimInstance. Windows-only; harmless if already loaded.
    if ($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows) {
        try { Import-Module CimCmdlets -ErrorAction SilentlyContinue -WhatIf:$false }
        catch { Write-Verbose "CimCmdlets preload failed ($($_.Exception.Message)); continuing -- handlers load it on demand." }
    }

    # ---- Load handlers ---------------------------------------------------------
    # Optional defense-in-depth: verify Authenticode signatures before dot-sourcing.
    $verifySig = {
        param($FilePath)
        if (-not $RequireSignedHandlers) { return }
        if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
            throw "RequireSignedHandlers was specified but Authenticode verification is unavailable on this platform (Windows-only). Aborting rather than running unverified."
        }
        $s = $null
        try { $s = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop } catch {
            throw "RequireSignedHandlers: could not read signature for $(Split-Path $FilePath -Leaf): $($_.Exception.Message)"
        }
        if ($s.Status -ne 'Valid') {
            throw "RequireSignedHandlers: $(Split-Path $FilePath -Leaf) is not validly signed (status: $($s.Status)). Aborting."
        }
    }

    # Dot-source private helpers first (shared utilities), then every handler file.
    Get-ChildItem -Path (Join-Path $ModuleRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue |
        ForEach-Object { & $verifySig $_.FullName; . $_.FullName }

    $Handlers = @{}
    Get-ChildItem -Path (Join-Path $ModuleRoot 'Handlers') -Filter '*.ps1' -ErrorAction SilentlyContinue |
        ForEach-Object {
            & $verifySig $_.FullName
            $h = & $_.FullName        # each handler file returns its hashtable
            if ($h -and $h.Name) { $Handlers[$h.Name] = $h }
            else { Write-Warning "Handler $($_.Name) did not return a valid handler object; skipped." }
        }
    & $Context.Log "Loaded $($Handlers.Count) handlers: $($Handlers.Keys -join ', ')"

    # ---- Resolve finding list (auto-detect for Recon/Survey if omitted) --------
    if (-not $FindingList) {
        # Strike already refused above, so this is Recon/Survey.
        $resolved = Resolve-HtDefaultList -ModuleRoot $ModuleRoot
        if ($resolved.Path) {
            $FindingList = $resolved.Path
            Write-Host "No -FindingList given. Auto-selected for $($resolved.Os.Product) $($resolved.Os.Release): $(Split-Path $FindingList -Leaf)" -ForegroundColor Cyan
            & $Context.Log "Auto-selected list: $($resolved.Reason)"
            foreach ($w in $resolved.Warnings) {
                Write-Warning $w
                & $Context.Log "Auto-select caution: $w" 'Warn'
            }
        } else {
            throw "No -FindingList specified and no list under lists/ matched this system " +
                  "($($resolved.Os.Product) $($resolved.Os.Release); $($resolved.Reason)). " +
                  "Specify -FindingList explicitly."
        }
    }
    if (-not (Test-Path $FindingList)) { throw "Finding list not found: $FindingList" }

    # ---- Read the list ONCE into memory (TOCTOU defense) -----------------------
    # Read the file's raw bytes a single time, hash THOSE bytes, and decode THOSE bytes
    # to the JSON text we parse. Integrity verification and parsing then operate on the
    # exact same buffer -- a process racing to swap the file between a hash and a separate
    # parse read cannot present verified content to the hasher and malicious content to
    # the parser. (StreamReader with BOM detection strips a leading BOM that would
    # otherwise make ConvertFrom-Json choke on PS 5.1.)
    try { $listBytes = [System.IO.File]::ReadAllBytes($FindingList) }
    catch { throw "Could not read finding list: $($_.Exception.Message)" }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $listHash = ([System.BitConverter]::ToString($sha256.ComputeHash($listBytes)) -replace '-','').ToLower() }
    finally { $sha256.Dispose() }
    $ms = New-Object System.IO.MemoryStream(,$listBytes)
    $reader = New-Object System.IO.StreamReader($ms, $true)
    try { $listRaw = $reader.ReadToEnd() } finally { $reader.Dispose(); $ms.Dispose() }

    # ---- Integrity check (defense against tampered lists) ----------------------
    $integrity = Test-HtListIntegrity -FindingList $FindingList -ModuleRoot $ModuleRoot -ActualHash $listHash
    switch ($integrity.Status) {
        'verified' { & $Context.Log $integrity.Message }
        'manifest-tampered' {
            # A signed manifest that fails signature check is a hard stop in ALL modes.
            throw "Integrity manifest failed verification: $($integrity.Message) Refusing to run."
        }
        default {
            # Strike will not apply changes from an unverified/tampered/unlisted list.
            if ($Mode -eq 'Strike') {
                throw "Strike blocked: $($integrity.Message) Strike requires a list whose hash is in lists/manifest.sha256."
            }
            # Recon/Survey are read-only -- warn loudly but proceed.
            Write-Warning "Integrity: $($integrity.Message)"
            & $Context.Log "Integrity ($($integrity.Status)): $($integrity.Message)" 'Warn'
        }
    }
    # Be honest about what the gate can and cannot do: without a SIGNED catalog
    # (HardeningTomcat.cat from Sign-Module.ps1), manifest.sha256 is plain text that
    # anyone who can edit a list can also regenerate -- it detects accidental
    # corruption, not deliberate tampering.
    if ($Mode -eq 'Strike' -and -not $integrity.CatalogPresent) {
        Write-Warning ("Integrity manifest is NOT signed (no HardeningTomcat.cat): list verification " +
            "protects against accidental corruption only, not deliberate tampering. Run Sign-Module.ps1 " +
            "to produce a signed catalog for tamper resistance.")
        & $Context.Log "Strike with unsigned integrity manifest (corruption detection only)." 'Warn'
    }

    # ---- Load & validate finding list -----------------------------------------
    # $listRaw was read+hashed above from a single in-memory buffer (TOCTOU-safe); parse
    # that same buffer -- do NOT re-open $FindingList here.
    try { $list = $listRaw | ConvertFrom-Json }
    catch { throw "Finding list is not valid JSON: $($_.Exception.Message)" }
    if (-not $list.findings) { throw "Finding list contains no 'findings' array." }

    # ---- Validate findings up front (fail fast with ALL problems) --------------
    $validOps = @('=','!=','<=','>=','<','>','<=!0','contains','=|0','=or','set=','manual')
    $validSev = @('Low','Medium','High')
    $problems = New-Object System.Collections.Generic.List[string]
    $seenIds  = @{}
    $idx = 0
    foreach ($f in $list.findings) {
        $idx++
        $label = if ($f.id) { "id '$($f.id)'" } else { "finding #$idx" }
        foreach ($req in 'id','name','method','operator','recommendedValue','severity') {
            if ($null -eq $f.$req -or "$($f.$req)" -eq '') {
                # recommendedValue may legitimately be empty (e.g. user-rights = no one)
                if ($req -eq 'recommendedValue') { continue }
                $problems.Add("$label is missing required field '$req'")
            }
        }
        if ($f.operator -and $f.operator -notin $validOps) { $problems.Add("$label has invalid operator '$($f.operator)'") }
        # '=or' is Registry-only: its apply path resolves the "X or Y" prose to the first
        # value, and only the Registry handler implements that resolution. Any other
        # method would write the literal prose to the system.
        if ($f.operator -eq '=or' -and $f.method -ne 'Registry') {
            $problems.Add("$label uses operator '=or' with method '$($f.method)' -- '=or' is only supported for Registry findings")
        }
        # Reject wildcard characters in registry paths. The registry provider glob-expands
        # *, ?, and [...]; New-Item (no -LiteralPath) would otherwise let a single Strike
        # finding fan a WRITE across every matching key. Registry reads already use
        # -LiteralPath, but this closes the write path at the source.
        if ($f.method -in 'Registry','RegistryList' -and $f.args -and $f.args.path -match '[*?\[\]]') {
            $problems.Add("$label ($($f.method)) has a wildcard character (* ? [ ]) in args.path '$($f.args.path)' -- registry paths must be literal")
        }
        if ($f.severity -and $f.severity -notin $validSev) { $problems.Add("$label has invalid severity '$($f.severity)'") }
        if ($f.id) {
            if ($seenIds.ContainsKey("$($f.id)")) { $problems.Add("duplicate id '$($f.id)'") }
            else { $seenIds["$($f.id)"] = $true }
        }
    }
    if ($problems.Count -gt 0) {
        $msg = "Finding list '$FindingList' failed validation ($($problems.Count) problem(s)):`n  - " + ($problems -join "`n  - ")
        throw $msg
    }

    # ---- User-scope list guard --------------------------------------------------
    # A 'scope: user' list (e.g. CIS Intune Office) reads HKCU. In an elevated session
    # HKCU resolves to the ELEVATED identity's hive -- elevate under a different admin
    # account than the user being audited and every HKCU finding silently grades the
    # WRONG user. Warn so the operator runs user-scope lists as the target user
    # (non-elevated is fine; these reads need no admin).
    if ("$($list.scope)" -eq 'user' -and $IsAdmin) {
        Write-Warning ("This finding list is user-scope (reads HKCU), and this session is elevated: HKCU " +
            "resolves to the elevated identity's hive. If you elevated under a different account than " +
            "the user being audited, results will reflect the WRONG user. For accurate results, run " +
            "non-elevated as the target user.")
        & $Context.Log "User-scope list running elevated; HKCU hive caution issued." 'Warn'
    }

    $findings = $list.findings
    if ($Filter) { $findings = $findings | Where-Object $Filter }
    if ($ExcludeHighImpact) {
        $before = @($findings).Count
        $findings = $findings | Where-Object { -not $_.highImpact }
        $skipped = $before - @($findings).Count
        & $Context.Log "ExcludeHighImpact: skipped $skipped high-impact finding(s) (VBS/auth/remote-access lockout class)."
        if ($skipped -gt 0) {
            Write-Host "  -ExcludeHighImpact: skipping $skipped high-impact finding(s) (boot/lockout/remote-access risk)." -ForegroundColor Yellow
        }
    }
    if ($Level) {
        # L1 -> only level-1 findings; L2 -> level 1 and 2. Findings with no level
        # field are always kept (Microsoft lists have no levels to filter on).
        $maxLvl = [int]$Level
        $findings = $findings | Where-Object { (-not $_.level) -or ($_.level -le $maxLvl) }
        & $Context.Log "Level filter L$($Level): $($findings.Count) findings remain."
    }
    & $Context.Log "Finding list '$($list.listName)' v$($list.version): $($findings.Count) findings after filter."

    # ---- Elevation pre-check: warn up front if not admin ----------------------
    # Count findings whose handler requires admin so the user knows BEFORE the run
    # how much will be skipped, rather than discovering it in the results.
    if (-not $IsAdmin) {
        $adminMethods = $Handlers.Keys | Where-Object { $Handlers[$_].RequiresAdmin }
        $needAdmin = ($findings | Where-Object { $_.method -in $adminMethods }).Count
        Write-Warning ("Not running as Administrator. $needAdmin of $($findings.Count) findings " +
            "(user rights, audit policy, security policy) cannot be read and will be Skipped. " +
            "For a complete audit, re-run in an elevated PowerShell (Run as administrator).")
    }

    # ---- Prefetch pass (batch slow external calls once) -----------------------
    # Group findings by method ONCE (O(n)) instead of re-filtering the whole list
    # per method (O(methods x n)).
    $byMethod = @{}
    foreach ($f in $findings) {
        if (-not $byMethod.ContainsKey($f.method)) { $byMethod[$f.method] = New-Object System.Collections.Generic.List[object] }
        $byMethod[$f.method].Add($f)
    }
    $Cache = @{}
    foreach ($methodName in $byMethod.Keys) {
        $handler = $Handlers[$methodName]
        if (-not $handler) { continue }
        if ($handler.Prefetch) {
            try { & $handler.Prefetch $byMethod[$methodName] $Cache $Context }
            catch { & $Context.Log "Prefetch for $methodName failed: $($_.Exception.Message)" 'Warn' }
        }
    }

    # Detect dry-run ONCE, before the backup: -WhatIf sets $WhatIfPreference to $true;
    # an explicit -WhatIf:$false must run for real (checking ContainsKey('WhatIf') would
    # wrongly treat it as a dry-run). We handle the dry-run summary ourselves rather
    # than emitting PowerShell's per-finding 'What if:' chatter.
    $isDryRun = ($Mode -eq 'Strike') -and $WhatIfPreference

    # ---- Pre-Strike backup (export current state so apply is recoverable) ------
    $undoJournalPath = $null
    if ($Mode -eq 'Strike') {
        $backup = Invoke-HtPreStrikeBackup -BackupDir $BackupDir -Context $Context
        if ($backup.Complete) {
            Write-Host "Pre-Strike backup written to: $($backup.Dir)" -ForegroundColor Green
        } elseif ($SkipBackupCheck) {
            Write-Warning "Pre-Strike backup was incomplete, but -SkipBackupCheck was set. Proceeding without a full backup. Backup dir: $($backup.Dir)"
            & $Context.Log "Strike proceeding despite incomplete backup (-SkipBackupCheck)." 'Warn'
        } else {
            # The backup is the safety net for apply. If it failed, do NOT apply changes.
            throw "Strike halted: the pre-Strike backup did not complete (see log; backup dir: $($backup.Dir)). " +
                  "Applying changes without a recoverable backup is unsafe. Resolve the backup failure, " +
                  "or re-run with -SkipBackupCheck if you have another safety net (e.g. a VM snapshot)."
        }
        # Per-finding undo journal: before every apply, the pre-change observed value is
        # appended here (JSONL, one record per applied finding). Unlike the subtree
        # exports above -- which cannot cover every path Strike touches -- the journal
        # records EXACTLY what changed and what it was before, for every handler.
        if (-not $isDryRun) {
            $undoJournalPath = Join-Path $backup.Dir 'undo-journal.jsonl'
            & $Context.Log "Undo journal: $undoJournalPath"
        }
    }

    # ---- Unified finding loop (drives both Test and Apply) ---------------------
    $results = New-Object System.Collections.Generic.List[object]
    $stats = @{ Passed = 0; Low = 0; Medium = 0; High = 0; Skipped = 0; Applied = 0; ApplyFailed = 0 }
    $wouldChange = New-Object System.Collections.Generic.List[object]
    $script:HtUndoWarned = $false

    $total = $findings.Count
    $i = 0
    # Decide progress style ONCE: custom ASCII bar on a capable host, native
    # Write-Progress on the legacy Windows PowerShell 5.1 console (where redrawing
    # a line and Unicode/width handling are unreliable).
    $script:HtUseAsciiBar = ($Host.Name -ne 'ConsoleHost') -or ($PSVersionTable.PSVersion.Major -ge 6)
    foreach ($finding in $findings) {
        $i++
        # Throttled to every 5th finding (and the last) to limit redraw overhead.
        if ($i -eq $total -or ($i % 5) -eq 0) {
            Write-HtProgress -Activity "HardeningTomcat $Mode" -Current $i -Total $total -Stats $stats
        }
        # --- manual findings: no automated check exists (e.g. STIG rules that require
        # human verification, or OVAL test types with no handler). Report as Skipped
        # with the remediation text so they surface in the report rather than being
        # dropped or falsely passed. ---
        if ($finding.method -eq 'manual' -or $finding.operator -eq 'manual') {
            $detail = if ($finding.fixText) { "Manual check: $($finding.fixText)" } else { 'Manual verification required' }
            $results.Add((New-HtResult $finding 'Skipped' $detail))
            $stats.Skipped++; continue
        }
        $handler = $Handlers[$finding.method]

        # --- guards: unknown method, missing admin, missing binary -------------
        if (-not $handler) {
            $results.Add((New-HtResult $finding 'Skipped' "No handler for method '$($finding.method)'"))
            $stats.Skipped++; continue
        }
        if ($handler.RequiresAdmin -and -not $IsAdmin) {
            $results.Add((New-HtResult $finding 'Skipped' "Requires elevation; session not admin"))
            $stats.Skipped++; continue
        }
        if ($handler.RequiresBinary -and -not (Test-Path $handler.RequiresBinary)) {
            $results.Add((New-HtResult $finding 'Skipped' "Required binary missing: $($handler.RequiresBinary)"))
            $stats.Skipped++; continue
        }

        # --- observe (Test) -----------------------------------------------------
        try {
            $obs = & $handler.Test $finding $Cache $Context
        } catch {
            $results.Add((New-HtResult $finding 'Skipped' "Test error: $($_.Exception.Message)"))
            $stats.Skipped++; continue
        }

        # Normalize the observed value for comparison. Multi-string (REG_MULTI_SZ)
        # results arrive as ARRAYS; lists store the expected value ';'-separated, so a
        # naive [string] cast would space-join and make every multi-string finding
        # false-fail forever (elements like 'Server Applications' contain spaces).
        $observed = if ($obs.Found) { ConvertTo-HtObservedString $obs.Result } else { ConvertTo-HtObservedString $finding.defaultValue }
        # For the human-readable Detail string, show empty/absent values clearly.
        $observedDisp = if ([string]::IsNullOrEmpty($observed)) { '(not set)' } else { $observed }
        $obsNote = if ($obs.PSObject.Properties.Name -contains 'Note' -and $obs.Note) { " [$($obs.Note)]" } else { '' }

        # --- Survey mode just records the observed value ------------------------
        if ($Mode -eq 'Survey') {
            $results.Add((New-HtResult $finding 'Survey' "Observed=$observedDisp" -Observed $observed))
            continue
        }

        # --- compare (engine owns operator semantics) ---------------------------
        $passed = Test-HtOperator -Operator $finding.operator -Observed $observed -Recommended ([string]$finding.recommendedValue)

        if ($passed) {
            $results.Add((New-HtResult $finding 'Passed' "Observed=$observedDisp, Recommended=$($finding.recommendedValue)" -Observed $observed -Recommended "$($finding.recommendedValue)"))
            $stats.Passed++
            continue
        }

        # --- failed: record at its severity -------------------------------------
        $sev = "$($finding.severity)"
        if ($stats.ContainsKey($sev)) { $stats[$sev]++ }
        $results.Add((New-HtResult $finding $sev "Observed=$observedDisp, Recommended=$($finding.recommendedValue)$obsNote" -Observed $observed -Recommended "$($finding.recommendedValue)"))

        # --- apply (Strike only, only on failed findings) -----------------------
        if ($Mode -eq 'Strike') {
            if ($null -eq $handler.Apply) {
                & $Context.Log "ID $($finding.id): method '$($finding.method)' is read-only; cannot apply." 'Warn'
                continue
            }
            # Some handlers can READ without elevation but need admin to WRITE
            # (e.g. service start types). Skip the apply honestly instead of letting
            # it throw per-finding.
            if ($handler.RequiresAdminForApply -and -not $IsAdmin) {
                & $Context.Log "ID $($finding.id): apply requires elevation; session not admin." 'Warn'
                continue
            }
            $target = "$($finding.id) - $($finding.name)"
            if ($isDryRun) {
                # Dry-run: collect what WOULD change for a concise end-of-run summary,
                # instead of PowerShell's per-finding 'What if:' chatter (which we
                # suppress by NOT calling ShouldProcess on this path).
                $wouldChange.Add([pscustomobject]@{
                    Id = $finding.id; Name = $finding.name
                    Method = $finding.method; To = "$($finding.recommendedValue)"
                })
            }
            elseif ($PSCmdlet.ShouldProcess($target, "Apply recommendedValue '$($finding.recommendedValue)'")) {
                $ctxApply = $Context.Clone(); $ctxApply.WhatIf = $false
                # Log BEFORE applying, with the registry path / key being written, so if
                # this specific apply hangs or bricks the machine, the log's final line
                # names the exact culprit. This is the diagnostic for "which setting".
                $tgtDetail = switch ($finding.method) {
                    'Registry' { "$($finding.args.path)\$($finding.args.name) = $($finding.recommendedValue)" }
                    'service'  { "service $($finding.args.name) -> $($finding.recommendedValue)" }
                    'secedit'  { "[System Access] $($finding.args.key) = $($finding.recommendedValue) (queued)" }
                    default    { "$($finding.method) = $($finding.recommendedValue)" }
                }
                & $Context.Log "APPLYING $($finding.id) [$($finding.method)] $tgtDetail"
                # Undo journal: record the pre-change value BEFORE applying, so every
                # change Strike makes is individually reversible from the backup dir.
                if ($undoJournalPath) {
                    $undoRec = [ordered]@{
                        ts = (Get-Date -Format 'o'); id = "$($finding.id)"; method = $finding.method
                        args = $finding.args; found = [bool]$obs.Found; observed = $observed
                        recommended = "$($finding.recommendedValue)"
                    }
                    try {
                        [System.IO.File]::AppendAllText($undoJournalPath,
                            (([pscustomobject]$undoRec | ConvertTo-Json -Compress -Depth 5) + "`r`n"))
                    } catch {
                        & $Context.Log "Undo journal write failed: $($_.Exception.Message)" 'Warn'
                        if (-not $script:HtUndoWarned) {
                            $script:HtUndoWarned = $true
                            Write-Warning "Undo journal write failed ($($_.Exception.Message)). Applies continue (the pre-Strike backup still exists), but per-finding rollback data is incomplete."
                        }
                    }
                }
                try {
                    $applyResult = & $handler.Apply $finding $Cache $ctxApply
                    if ($applyResult.Changed) { $stats.Applied++ }
                    & $Context.Log "  -> done $($finding.id): $($applyResult.Message)"
                } catch {
                    # Apply failures must be VISIBLE, not just in the verbose/log stream:
                    # a run where every apply throws must not end with a green summary.
                    $stats.ApplyFailed++
                    & $Context.Log "  -> FAILED $($finding.id): $($_.Exception.Message)" 'Error'
                    if ($stats.ApplyFailed -le 3) {
                        Write-Warning "Apply failed for $($finding.id) ($($finding.name)): $($_.Exception.Message)"
                    } elseif ($stats.ApplyFailed -eq 4) {
                        Write-Warning "Further apply failures suppressed on console; the summary shows the total (full detail with -Log)."
                    }
                }
            }
        }
    }

    # ---- Batched apply flush (Strike, non-dry-run) -----------------------------
    # Some handlers (e.g. secedit) accumulate their changes during the loop and apply
    # them in ONE operation here, instead of spawning a heavy external process per
    # finding. This is gentler on the system (one secedit /configure, not dozens) and
    # avoids exhausting the Security Configuration Engine (scesrv) on repeated calls.
    if ($Mode -eq 'Strike' -and -not $isDryRun) {
        foreach ($hName in $Handlers.Keys) {
            $h = $Handlers[$hName]
            if ($h.FlushApply) {
                try {
                    $flush = & $h.FlushApply $Cache $Context
                    if ($flush -and $flush.Applied) { $stats.Applied += [int]$flush.Applied }
                    if ($flush -and $flush.Message) { & $Context.Log "FlushApply ($hName): $($flush.Message)" }
                } catch {
                    $stats.ApplyFailed++
                    & $Context.Log "FlushApply ($hName) failed: $($_.Exception.Message)" 'Error'
                    Write-Warning "Batched apply (FlushApply, $hName) failed: $($_.Exception.Message)"
                }
            }
        }
    }

    Write-HtProgress -Activity "HardeningTomcat $Mode" -Current $total -Total $total -Stats $stats -Complete   # clear the progress bar

    # ---- Scoring ---------------------------------------------------------------
    # Same model as the original: Passed=4, Low=2, Medium=1, High=0.
    $earned = ($stats.Passed * 4) + ($stats.Low * 2) + ($stats.Medium * 1)
    $graded = $stats.Passed + $stats.Low + $stats.Medium + $stats.High
    $max    = $graded * 4
    $pct    = if ($max -gt 0) { [math]::Round(($earned / $max) * 100, 1) } else { 0 }

    $summary = [pscustomobject]@{
        ListName  = $list.listName
        Mode      = $Mode
        Total     = $findings.Count
        Passed    = $stats.Passed
        Low       = $stats.Low
        Medium    = $stats.Medium
        High      = $stats.High
        Skipped   = $stats.Skipped
        Applied   = $stats.Applied
        ApplyFailed = $stats.ApplyFailed
        Score     = "$earned / $max"
        Percent   = $pct
        Duration  = (New-TimeSpan -Start $script:StartTime -End (Get-Date)).TotalSeconds
    }

    # ---- Report ----------------------------------------------------------------
    if ($Report) {
        $safeList = ($list.listName -replace '[^\w\-]', '_')
        $reportPath = if ($ReportFile) { $ReportFile } `
            else { Join-Path (Get-Location) ("hardeningtomcat_report_{0}_{1}_{2:yyyyMMdd-HHmmss}.csv" -f $env:COMPUTERNAME, $safeList, $script:StartTime) }
        $results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
        & $Context.Log "Report written: $reportPath"
    }
    if ($ReportHtml) {
        $safeListH = ($list.listName -replace '[^\w\-]', '_')
        $htmlPath = if ($ReportHtmlFile) { $ReportHtmlFile } `
            else { Join-Path (Get-Location) ("hardeningtomcat_report_{0}_{1}_{2:yyyyMMdd-HHmmss}.html" -f $env:COMPUTERNAME, $safeListH, $script:StartTime) }
        Export-HtHtmlReport -Summary $summary -Results $results -Path $htmlPath -Meta @{
            list      = $list.listName
            host      = $script:HtHostname
            mode      = $Mode
            level     = if ($Level) { "L$Level" } else { '' }
            generated = ('{0:yyyy-MM-dd HH:mm:ss}' -f $script:StartTime)
            duration  = [math]::Round($summary.Duration, 1)
            version   = "$((Import-PowerShellDataFile (Join-Path $ModuleRoot 'HardeningTomcat.psd1')).ModuleVersion)"
        }
        & $Context.Log "HTML report written: $htmlPath"
        Write-Host "HTML report: $htmlPath" -ForegroundColor Cyan
    }

    # ---- Console: failures summary -------------------------------------------
    # By default show concise counts; -ShowDetails prints every failed/skipped line.
    if ($Mode -ne 'Survey') {
        $failed  = $results | Where-Object { $_.Result -in 'Low','Medium','High' }
        $skipped = $results | Where-Object Result -eq 'Skipped'

        if (-not $ShowDetails) {
            Write-Host ""
            if ($failed)  { Write-Host ("{0} finding(s) FAILED. " -f $failed.Count) -ForegroundColor Yellow -NoNewline }
            else          { Write-Host "All graded findings passed. " -ForegroundColor Green -NoNewline }
            if ($skipped) { Write-Host ("{0} skipped (not evaluated)." -f $skipped.Count) -ForegroundColor DarkGray -NoNewline }
            Write-Host ""
            if ($Report)  { Write-Host "Full per-finding detail is in the report CSV." -ForegroundColor DarkGray }
            else          { Write-Host "Re-run with -ShowDetails (or -Report) to see per-finding detail." -ForegroundColor DarkGray }
        }
        elseif ($failed) {
            Write-Host ""
            Write-Host "--- Findings that FAILED ($($failed.Count)) ---" -ForegroundColor Yellow
            foreach ($x in ($failed | Sort-Object @{e={@{High=0;Medium=1;Low=2}[$_.Result]}}, ID)) {
                $color = switch ($x.Result) { 'High' {'Red'} 'Medium' {'DarkYellow'} 'Low' {'Yellow'} }
                Write-Host ("  [{0,-6}] {1}" -f $x.Result, $x.Name) -ForegroundColor $color
                Write-Host ("           checked: {0}" -f $x.Checked) -ForegroundColor DarkGray
                Write-Host ("           found '{0}'  expected ({1}) '{2}'" -f $x.Observed, $x.Operator, $x.Recommended) -ForegroundColor DarkGray
            }
        } else {
            Write-Host ""
            Write-Host "All graded findings passed." -ForegroundColor Green
        }
        if ($ShowDetails -and $skipped) {
            Write-Host ""
            Write-Host "--- Skipped ($($skipped.Count)) -- not evaluated ---" -ForegroundColor DarkGray
            foreach ($x in $skipped) { Write-Host ("  $($x.Name): $($x.Detail)") -ForegroundColor DarkGray }
        }
    }

    # ---- Final summary (clean, aligned) ---------------------------------------
    $passColor = if ($stats.High -gt 0) { 'Red' } elseif (($stats.Medium + $stats.Low) -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ""
    Write-Host "==== HardeningTomcat $Mode complete ====" -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  {0,-12}{1}" -f 'List:',     $summary.ListName)
    Write-Host ("  {0,-12}{1}" -f 'Host:',     $script:HtHostname)
    Write-Host ("  {0,-12}{1}" -f 'Mode:',     $summary.Mode)
    Write-Host ("  {0,-12}{1}" -f 'Total:',    $summary.Total)
    Write-Host ("  {0,-12}{1}" -f 'Passed:',   $summary.Passed) -ForegroundColor Green
    if ($summary.Low    -gt 0) { Write-Host ("  {0,-12}{1}" -f 'Low:',    $summary.Low)    -ForegroundColor Yellow }
    if ($summary.Medium -gt 0) { Write-Host ("  {0,-12}{1}" -f 'Medium:', $summary.Medium) -ForegroundColor DarkYellow }
    if ($summary.High   -gt 0) { Write-Host ("  {0,-12}{1}" -f 'High:',   $summary.High)   -ForegroundColor Red }
    if ($summary.Skipped -gt 0){ Write-Host ("  {0,-12}{1}" -f 'Skipped:',$summary.Skipped) -ForegroundColor DarkGray }
    if ($isDryRun)             { Write-Host ("  {0,-12}{1}" -f 'Would chg:', $wouldChange.Count) -ForegroundColor Cyan }
    elseif ($Mode -eq 'Strike') {
        Write-Host ("  {0,-12}{1}" -f 'Applied:',  $summary.Applied)
        if ($summary.ApplyFailed -gt 0) {
            Write-Host ("  {0,-12}{1}" -f 'Apply FAILED:', $summary.ApplyFailed) -ForegroundColor Red
        }
    }
    Write-Host ""
    Write-Host ("  {0,-12}{1}" -f 'Score:',    "$($summary.Score)  ($($summary.Percent)%)") -ForegroundColor $passColor
    Write-Host ("  {0,-12}{1:N1}s" -f 'Duration:', $summary.Duration)
    Write-Host ""

    # Dry-run detail: only when asked, list what WOULD change (otherwise just the count
    # above). Keeps -WhatIf output to a one-line count by default instead of per-finding.
    if ($isDryRun -and $wouldChange.Count -gt 0) {
        if ($ShowDetails) {
            Write-Host "  Would change ($($wouldChange.Count)):" -ForegroundColor Cyan
            foreach ($w in $wouldChange) {
                Write-Host ("    [{0}] {1} -> {2}" -f $w.Method, $w.Name, $w.To) -ForegroundColor DarkGray
            }
            Write-Host ""
        } else {
            Write-Host "  (re-run with -ShowDetails to list each change, or -Report for a CSV)" -ForegroundColor DarkGray
            Write-Host ""
        }
    }

    # Return the structured object only when asked (-PassThru), so interactive runs
    # don't dump a raw @{...} hashtable to the console after the formatted summary.
    if ($PassThru) {
        return [pscustomobject]@{ Summary = $summary; Results = $results }
    }
}

# ---- Engine helpers (not handler-specific) ------------------------------------

function Write-HtProgress {
    # Dual-mode progress. On a capable host ($script:HtUseAsciiBar) draws a custom
    # single-line ASCII bar with live pass/fail/skip counts, in color. On the legacy
    # 5.1 console it falls back to native Write-Progress (robust, host-rendered).
    param(
        [string]$Activity,
        [int]$Current,
        [int]$Total,
        [hashtable]$Stats,
        [switch]$Complete
    )
    if ($Total -le 0) { return }
    $pct = [int](($Current / $Total) * 100)

    if (-not $script:HtUseAsciiBar) {
        if ($Complete) { Write-Progress -Activity $Activity -Completed }
        else {
            $failed = $Stats.Medium + $Stats.Low + $Stats.High
            Write-Progress -Activity $Activity `
                -Status "$Current / $Total  (Passed $($Stats.Passed), Failed $failed, Skipped $($Stats.Skipped))" `
                -PercentComplete $pct
        }
        return
    }

    # Custom ASCII bar. Pure ASCII (#/.) so it renders identically on any console.
    if ($Complete) {
        # Clear the line so the summary prints cleanly underneath.
        Write-Host ("`r" + (' ' * 78) + "`r") -NoNewline
        return
    }
    $width  = 24
    $filled = [int]($width * $Current / $Total)
    $bar    = ('#' * $filled) + ('.' * ($width - $filled))
    $failed = $Stats.Medium + $Stats.Low + $Stats.High

    # Write segments in color, staying on one line via carriage return.
    Write-Host ("`r  {0} [" -f $Activity) -NoNewline
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host ("] {0,3}%  {1,4}/{2}  " -f $pct, $Current, $Total) -NoNewline
    Write-Host ("OK {0}" -f $Stats.Passed) -NoNewline -ForegroundColor Green
    Write-Host ("  X {0}" -f $failed) -NoNewline -ForegroundColor Yellow
    Write-Host ("  - {0}  " -f $Stats.Skipped) -NoNewline -ForegroundColor DarkGray
}


function New-HtResult {
    # Pure object factory: builds the per-finding result record for the report. It
    # changes no system state, so ShouldProcess does not apply despite the New- verb.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Object factory only; no state change.')]
    param(
        $Finding,
        [string]$Status,
        [string]$Detail,
        [string]$Observed = '',
        [string]$Recommended = ''
    )
    # Build a human-readable description of WHAT was checked, per method, so the report
    # shows the registry path / subcategory / key -- not just an opaque finding name.
    $checked = switch ($Finding.method) {
        'Registry'        { "$($Finding.args.path)\$($Finding.args.name)" }
        'RegistryList'    { "$($Finding.args.path)\[list] $($Finding.args.item)" }
        'auditpol'        { "Audit subcategory: $($Finding.args.subcategory)" }
        'secedit'         { "Policy: $($Finding.args.key)" }
        'accountpolicy'   { "Account policy: $($Finding.name)" }
        'service'         { "Service: $($Finding.args.name)" }
        'accesschk'       { "User right: $($Finding.args.privilege)" }
        'localaccount'    { "Local account RID: $($Finding.args.rid)" }
        'MpPreferenceAsr' { "ASR rule: $($Finding.args.ruleId)" }
        'ProcessmitigationApplication' { "Exploit protection: $($Finding.args.target)" }
        default           { $Finding.method }
    }
    [pscustomobject]@{
        ID          = $Finding.id
        Category    = $Finding.category
        Name        = $Finding.name
        Method      = $Finding.method
        Checked     = $checked
        Observed    = $Observed
        Recommended = if ($Recommended) { $Recommended } else { "$($Finding.recommendedValue)" }
        Operator    = $Finding.operator
        Severity    = $Finding.severity
        Level       = if ($Finding.level) { "L$($Finding.level)" } else { '' }
        Result      = $Status      # Passed / Low / Medium / High / Skipped / Survey
        Detail      = $Detail
        Hostname    = $script:HtHostname
    }
}

function Test-HtOperator {
    # Comparison operators supported by the engine (see schema enum for the list).
    param([string]$Operator, [string]$Observed, [string]$Recommended)
    switch ($Operator) {
        # NOTE: string comparisons are CASE-INSENSITIVE by design (PowerShell -eq
        # semantics). Registry data, secedit values, and service start types are
        # case-insensitive on Windows, so 'Enterprise' must match 'ENTERPRISE'.
        # This applies to '=', '!=', '=or', and '=|0'; pinned by a Pester test so
        # changing it is a deliberate decision, not an accident.
        '='    { return ([string]$Observed -eq $Recommended) }
        '=or'  {
            # CIS sometimes lists several acceptable values as "X or Y" (e.g. "2 or 1").
            # Either value is compliant. Split on 'or' and pass if the observed value
            # matches any of them. The Registry apply path resolves the same prose to
            # the first listed value when writing.
            $opts = $Recommended -split '\s+or\s+' | ForEach-Object { $_.Trim() }
            foreach ($o in $opts) { if ([string]$Observed -eq $o) { return $true } }
            return $false
        }
        '!='   { return ([string]$Observed -ne $Recommended) }
        # int64, not int32: registry baselines legitimately use values >= 2^31
        # (e.g. 4294967295); an [int] cast would throw and turn them into false failures.
        #
        # Empty-guard (CRITICAL): in Windows PowerShell 5.1 [int64]'' returns 0 WITHOUT
        # throwing, so the try/catch below does NOT protect against an empty observation.
        # An absent registry key is graded with an empty $Observed (engine substitutes an
        # empty defaultValue); without this guard, [int64]'' -> 0 makes '0 <= 30' etc. a
        # false PASS -- reporting an unconfigured control (e.g. LAPS PasswordAgeDays) as
        # compliant. Reject empty/whitespace observations before the numeric cast so an
        # unreadable/absent value can never masquerade as the integer 0.
        '<='   { if ([string]::IsNullOrWhiteSpace($Observed)) { return $false } try { return ([int64]$Observed -le [int64]$Recommended) } catch { return $false } }
        '>='   { if ([string]::IsNullOrWhiteSpace($Observed)) { return $false } try { return ([int64]$Observed -ge [int64]$Recommended) } catch { return $false } }
        '<'    { if ([string]::IsNullOrWhiteSpace($Observed)) { return $false } try { return ([int64]$Observed -lt [int64]$Recommended) } catch { return $false } }
        '>'    { if ([string]::IsNullOrWhiteSpace($Observed)) { return $false } try { return ([int64]$Observed -gt [int64]$Recommended) } catch { return $false } }
        '<=!0' { if ([string]::IsNullOrWhiteSpace($Observed)) { return $false } try { return ([int64]$Observed -le [int64]$Recommended -and [int64]$Observed -ne 0) } catch { return $false } }
        'contains' {
            # An empty recommended substring would match everything -- treat as non-match
            # (a security tool must not report a pass it cannot actually justify).
            if ([string]::IsNullOrEmpty($Recommended)) { return $false }
            return ($Observed.ToString().Contains($Recommended))
        }
        '=|0'  { try { return ([string]$Observed -eq $Recommended -or $Observed.Length -eq 0) } catch { return $false } }
        'set=' {
            # Set-equality for SID lists (user rights). Order-independent, comma-separated.
            # Resolves account NAMES to SIDs on both sides so "Administrators" matches
            # "S-1-5-32-544" -- secedit export may emit either form depending on the system.
            $norm = {
                param($s)
                if ([string]::IsNullOrWhiteSpace($s)) { return @() }
                $items = $s -split '[,;]' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ }
                $sids = foreach ($it in $items) {
                    if ($it -match '^S-1-') { $it }   # already a SID
                    else {
                        # Try to translate an account name to its SID; fall back to the raw name.
                        try {
                            (New-Object System.Security.Principal.NTAccount($it)
                            ).Translate([System.Security.Principal.SecurityIdentifier]).Value
                        } catch { $it }
                    }
                }
                $sids | Sort-Object -Unique
            }
            $o = @(& $norm $Observed)
            $r = @(& $norm $Recommended)
            if ($o.Count -ne $r.Count) { return $false }
            # Both empty = equal sets (e.g. "no one holds this privilege"). Compare-Object
            # throws on empty/null input, so short-circuit before calling it.
            if ($o.Count -eq 0) { return $true }
            return (-not (Compare-Object $o $r))
        }
        default { return $false }
    }
}

Export-ModuleMember -Function Invoke-HardeningTomcat
