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
        [ValidateSet('1','2')][string] $Level
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

    $Context = @{
        Mode      = $Mode
        IsAdmin   = $IsAdmin
        WhatIf    = $false      # set per-finding below for ShouldProcess dry-runs
        PSVersion = $PSVersionTable.PSVersion.Major
        Log       = {
            param($Text, $Level = 'Info')
            $stamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Write-Verbose "[$stamp][$Level] $Text"
            if ($script:LogEnabled) { Add-Content -Path $script:LogPath -Value "[$stamp][$Level] $Text" }
        }
    }

    # ---- Logging setup ---------------------------------------------------------
    $script:LogEnabled = [bool]$Log
    if ($Log) {
        $script:LogPath = if ($LogFile) { $LogFile } `
            else { Join-Path (Get-Location) ("hardeningtomcat_log_{0:yyyyMMdd-HHmmss}.txt" -f $script:StartTime) }
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

    # ---- Load handlers ---------------------------------------------------------
    # Dot-source private helpers first (shared utilities), then every handler file.
    Get-ChildItem -Path (Join-Path $ModuleRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue |
        ForEach-Object { . $_.FullName }

    $Handlers = @{}
    Get-ChildItem -Path (Join-Path $ModuleRoot 'Handlers') -Filter '*.ps1' -ErrorAction SilentlyContinue |
        ForEach-Object {
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

    # ---- Integrity check (defense against tampered lists) ----------------------
    $integrity = Test-HtListIntegrity -FindingList $FindingList -ModuleRoot $ModuleRoot
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

    # ---- Load & validate finding list -----------------------------------------
    $listRaw = Get-Content -Path $FindingList -Raw
    try { $list = $listRaw | ConvertFrom-Json }
    catch { throw "Finding list is not valid JSON: $($_.Exception.Message)" }
    if (-not $list.findings) { throw "Finding list contains no 'findings' array." }

    # ---- Validate findings up front (fail fast with ALL problems) --------------
    $validOps = @('=','!=','<=','>=','<','>','<=!0','contains','=|0','set=')
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

    $findings = $list.findings
    if ($Filter) { $findings = $findings | Where-Object $Filter }
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

    # ---- Pre-Strike backup (export current state so apply is recoverable) ------
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
    }

    # ---- Unified finding loop (drives both Test and Apply) ---------------------
    $results = New-Object System.Collections.Generic.List[object]
    $stats = @{ Passed = 0; Low = 0; Medium = 0; High = 0; Skipped = 0; Applied = 0 }

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

        $observed = if ($obs.Found) { [string]$obs.Result } else { [string]$finding.defaultValue }

        # --- Survey mode just records the observed value ------------------------
        if ($Mode -eq 'Survey') {
            $results.Add((New-HtResult $finding 'Survey' "Result=$observed" -Observed $observed))
            continue
        }

        # --- compare (engine owns operator semantics) ---------------------------
        $passed = Test-HtOperator -Operator $finding.operator -Observed $observed -Recommended ([string]$finding.recommendedValue)

        if ($passed) {
            $results.Add((New-HtResult $finding 'Passed' "Result=$observed, Recommended=$($finding.recommendedValue)" -Observed $observed -Recommended "$($finding.recommendedValue)"))
            $stats.Passed++
            continue
        }

        # --- failed: record at its severity -------------------------------------
        $sev = "$($finding.severity)"
        if ($stats.ContainsKey($sev)) { $stats[$sev]++ }
        $results.Add((New-HtResult $finding $sev "Result=$observed, Recommended=$($finding.recommendedValue)" -Observed $observed -Recommended "$($finding.recommendedValue)"))

        # --- apply (Strike only, only on failed findings) -----------------------
        if ($Mode -eq 'Strike') {
            if ($null -eq $handler.Apply) {
                & $Context.Log "ID $($finding.id): method '$($finding.method)' is read-only; cannot apply." 'Warn'
                continue
            }
            $target = "$($finding.id) - $($finding.name)"
            if ($PSCmdlet.ShouldProcess($target, "Apply recommendedValue '$($finding.recommendedValue)'")) {
                $ctxApply = $Context.Clone(); $ctxApply.WhatIf = $false
                try {
                    $applyResult = & $handler.Apply $finding $Cache $ctxApply
                    if ($applyResult.Changed) { $stats.Applied++ }
                    & $Context.Log "Applied $target : $($applyResult.Message)"
                } catch {
                    & $Context.Log "Apply failed for $target : $($_.Exception.Message)" 'Error'
                }
            } else {
                # -WhatIf path: handler reports what it WOULD do
                $ctxWhatIf = $Context.Clone(); $ctxWhatIf.WhatIf = $true
                try { $wi = & $handler.Apply $finding $Cache $ctxWhatIf; & $Context.Log $wi.Message } catch {}
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
    if ($Mode -eq 'Strike')    { Write-Host ("  {0,-12}{1}" -f 'Applied:',$summary.Applied) }
    Write-Host ""
    Write-Host ("  {0,-12}{1}" -f 'Score:',    "$($summary.Score)  ($($summary.Percent)%)") -ForegroundColor $passColor
    Write-Host ("  {0,-12}{1:N1}s" -f 'Duration:', $summary.Duration)
    Write-Host ""

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
        '='    { return ([string]$Observed -eq $Recommended) }
        '!='   { return ([string]$Observed -ne $Recommended) }
        '<='   { try { return ([int]$Observed -le [int]$Recommended) } catch { return $false } }
        '>='   { try { return ([int]$Observed -ge [int]$Recommended) } catch { return $false } }
        '<'    { try { return ([int]$Observed -lt [int]$Recommended) } catch { return $false } }
        '>'    { try { return ([int]$Observed -gt [int]$Recommended) } catch { return $false } }
        '<=!0' { try { return ([int]$Observed -le [int]$Recommended -and [int]$Observed -ne 0) } catch { return $false } }
        'contains' { return ($Observed.ToString().Contains($Recommended)) }
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
