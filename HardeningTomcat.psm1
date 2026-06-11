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
        # REQUIRED for Strike — apply mode refuses to guess.
        [string] $FindingList,

        [switch] $Log,
        [string] $LogFile,
        [switch] $Report,
        [string] $ReportFile,

        # Required guard for Strike. Without it, apply mode refuses to run.
        [switch] $Force,

        # Optional filter scriptblock over findings, e.g. { $_.severity -eq 'High' }
        [scriptblock] $Filter
    )

    $ModuleRoot = $PSScriptRoot
    $script:StartTime = Get-Date

    # ---- Session context -------------------------------------------------------
    $IsAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

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
        throw "No finding list specified. Strike mode will not auto-select a list — applying " +
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

    # ---- Load & validate finding list -----------------------------------------
    $listRaw = Get-Content -Path $FindingList -Raw
    try { $list = $listRaw | ConvertFrom-Json }
    catch { throw "Finding list is not valid JSON: $($_.Exception.Message)" }
    if (-not $list.findings) { throw "Finding list contains no 'findings' array." }

    $findings = $list.findings
    if ($Filter) { $findings = $findings | Where-Object $Filter }
    & $Context.Log "Finding list '$($list.listName)' v$($list.version): $($findings.Count) findings after filter."

    # ---- Prefetch pass (batch slow external calls once) -----------------------
    $Cache = @{}
    foreach ($methodName in ($findings.method | Sort-Object -Unique)) {
        $handler = $Handlers[$methodName]
        if (-not $handler) { continue }
        if ($handler.Prefetch) {
            $methodFindings = $findings | Where-Object { $_.method -eq $methodName }
            try { & $handler.Prefetch $methodFindings $Cache $Context }
            catch { & $Context.Log "Prefetch for $methodName failed: $($_.Exception.Message)" 'Warn' }
        }
    }

    # ---- Unified finding loop (drives both Test and Apply) ---------------------
    $results = New-Object System.Collections.Generic.List[object]
    $stats = @{ Passed = 0; Low = 0; Medium = 0; High = 0; Skipped = 0; Applied = 0 }

    foreach ($finding in $findings) {
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
            $r = New-HtResult $finding 'Survey' "Result=$observed"
            $r | Add-Member -NotePropertyName Observed -NotePropertyValue $observed
            $results.Add($r); continue
        }

        # --- compare (engine owns operator semantics) ---------------------------
        $passed = Test-HtOperator -Operator $finding.operator -Observed $observed -Recommended ([string]$finding.recommendedValue)

        if ($passed) {
            $results.Add((New-HtResult $finding 'Passed' "Result=$observed, Recommended=$($finding.recommendedValue)"))
            $stats.Passed++
            continue
        }

        # --- failed: record at its severity -------------------------------------
        $sev = "$($finding.severity)"
        if ($stats.ContainsKey($sev)) { $stats[$sev]++ }
        $results.Add((New-HtResult $finding $sev "Result=$observed, Recommended=$($finding.recommendedValue)"))

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
        $reportPath = if ($ReportFile) { $ReportFile } `
            else { Join-Path (Get-Location) ("hardeningtomcat_report_{0:yyyyMMdd-HHmmss}.csv" -f $script:StartTime) }
        $results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
        & $Context.Log "Report written: $reportPath"
    }

    # Emit to pipeline
    Write-Host ""
    Write-Host "==== HardeningTomcat $Mode complete ====" -ForegroundColor Cyan
    $summary | Format-List | Out-Host

    [pscustomobject]@{ Summary = $summary; Results = $results }
}

# ---- Engine helpers (not handler-specific) ------------------------------------

function New-HtResult {
    param($Finding, [string]$Status, [string]$Detail)
    [pscustomobject]@{
        ID       = $Finding.id
        Name     = $Finding.name
        Category = $Finding.category
        Method   = $Finding.method
        Severity = $Finding.severity
        Status   = $Status
        Detail   = $Detail
    }
}

function Test-HtOperator {
    # Replicates the original engine's 7-operator semantics exactly.
    param([string]$Operator, [string]$Observed, [string]$Recommended)
    switch ($Operator) {
        '='    { return ([string]$Observed -eq $Recommended) }
        '!='   { return ([string]$Observed -ne $Recommended) }
        '<='   { try { return ([int]$Observed -le [int]$Recommended) } catch { return $false } }
        '>='   { try { return ([int]$Observed -ge [int]$Recommended) } catch { return $false } }
        '<=!0' { try { return ([int]$Observed -le [int]$Recommended -and [int]$Observed -ne 0) } catch { return $false } }
        'contains' { return ($Observed.ToString().Contains($Recommended)) }
        '=|0'  { try { return ([string]$Observed -eq $Recommended -or $Observed.Length -eq 0) } catch { return $false } }
        default { return $false }
    }
}

Export-ModuleMember -Function Invoke-HardeningTomcat
