# Pre-Strike backup. Called once, right before the Strike apply loop runs.
#
# WHAT THIS COVERS (be honest -- these exports alone cannot restore everything):
#   - security policy (secedit INF export: account policy, user rights, audit)
#   - audit policy (auditpol /backup CSV, restorable with auditpol /restore)
#   - the two registry subtrees hardening touches most (SOFTWARE\Policies, Control\Lsa)
#   - service start types (CSV snapshot)
#   - Defender preferences incl. ASR rules (CliXml snapshot, best-effort)
# Registry findings OUTSIDE the exported subtrees are NOT covered by these dumps.
# The per-finding UNDO JOURNAL (undo-journal.jsonl, written by the engine into this
# same directory during the apply loop) is the complete record: it captures the
# pre-change observed value of EVERY finding Strike applies, for every handler.
# Windows-only (no-ops elsewhere).

function Invoke-HtPreStrikeBackup {
    param([string] $BackupDir, $Context)

    if (-not $BackupDir) {
        $BackupDir = Join-Path (Get-Location) ("hardeningtomcat_backup_{0}_{1:yyyyMMdd-HHmmss}" -f $env:COMPUTERNAME, (Get-Date))
    }
    # A backup is a safety operation, never a simulated one. Force all backup file ops
    # to run for real even when the caller's scope has $WhatIfPreference set (the engine
    # toggles ShouldProcess per-finding for Strike dry-runs, which otherwise leaks here
    # and turns the directory creation into a no-op -- then Get-Acl fails on a dir that
    # was never created).
    $WhatIfPreference = $false
    New-Item -ItemType Directory -Path $BackupDir -Force -WhatIf:$false | Out-Null
    if (-not (Test-Path $BackupDir)) {
        & $Context.Log "Backup: could not create backup directory $BackupDir" 'Warn'
        # NB: property must be named Dir -- the engine reads $backup.Dir for its messages.
        return [pscustomobject]@{ Complete = $false; Dir = $BackupDir }
    }

    # Restrict ACLs: these files contain full security policy (user rights, SIDs,
    # account policy). Lock the backup dir to SYSTEM + Administrators only, removing
    # inherited access so non-admin users can't read the dumps.
    try {
        $acl = Get-Acl $BackupDir
        $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited rules
        foreach ($id in 'NT AUTHORITY\SYSTEM','BUILTIN\Administrators') {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $BackupDir -AclObject $acl
        & $Context.Log "Backup dir ACL restricted to SYSTEM + Administrators."
    } catch {
        & $Context.Log "Backup: could not restrict ACLs on $BackupDir : $($_.Exception.Message)" 'Warn'
    }

    $ok = $true

    # 1) Security policy (account policy, user rights, audit) via secedit export.
    # External exes set $LASTEXITCODE rather than throwing, so check it AND verify the
    # output file actually exists with content -- otherwise a silent failure would let
    # the backup report success and Strike would proceed without a real safety net.
    try {
        $secPath = Join-Path $BackupDir 'secpol-backup.inf'
        & secedit.exe /export /cfg $secPath /quiet 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $secPath) -or (Get-Item $secPath).Length -eq 0) {
            $ok = $false; & $Context.Log "Backup: secedit export FAILED (exit $LASTEXITCODE or empty file)." 'Warn'
        } else {
            & $Context.Log "Backup: security policy -> $secPath"
        }
    } catch { $ok = $false; & $Context.Log "Backup: secedit export threw: $($_.Exception.Message)" 'Warn' }

    # 2) Registry hives most affected by hardening (HKLM\SOFTWARE and \SYSTEM policies)
    foreach ($hive in @(
        @{ Key = 'HKLM\SOFTWARE\Policies'; File = 'reg-software-policies.reg' }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; File = 'reg-lsa.reg' }
    )) {
        try {
            $regFile = Join-Path $BackupDir $hive.File
            & reg.exe export $hive.Key $regFile /y 2>$null | Out-Null
            # reg.exe returns non-zero if the key is absent; that's not fatal to the
            # overall backup (the key may legitimately not exist), but log it honestly.
            if ($LASTEXITCODE -ne 0) {
                & $Context.Log "Backup: reg export $($hive.Key) returned exit $LASTEXITCODE (key may not exist)." 'Warn'
            } else {
                & $Context.Log "Backup: $($hive.Key) -> $regFile"
            }
        } catch { $ok = $false; & $Context.Log "Backup: reg export $($hive.Key) threw" 'Warn' }
    }

    # 3) Audit policy snapshot
    try {
        $audPath = Join-Path $BackupDir 'auditpol-backup.csv'
        & auditpol.exe /backup /file:$audPath 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $audPath) -or (Get-Item $audPath).Length -eq 0) {
            $ok = $false; & $Context.Log "Backup: auditpol backup FAILED (exit $LASTEXITCODE or empty file)." 'Warn'
        } else {
            & $Context.Log "Backup: audit policy -> $audPath"
        }
    } catch { $ok = $false; & $Context.Log "Backup: auditpol backup threw" 'Warn' }

    # 4) Service start types. The service handler changes these during Strike and the
    # registry subtree exports above do not cover HKLM\SYSTEM\CurrentControlSet\Services.
    try {
        $svcPath = Join-Path $BackupDir 'services-starttype.csv'
        Get-Service -ErrorAction Stop | Select-Object Name, StartType, Status |
            Export-Csv -Path $svcPath -NoTypeInformation -Encoding UTF8
        & $Context.Log "Backup: service start types -> $svcPath"
    } catch { $ok = $false; & $Context.Log "Backup: service snapshot FAILED: $($_.Exception.Message)" 'Warn' }

    # 5) Defender preferences (ASR rules, the MpPreferenceAsr handler's target).
    # Best-effort: Defender may legitimately be absent/disabled on this SKU, and in that
    # case the ASR applies would no-op too -- so absence does not fail the backup.
    try {
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
            $mpPath = Join-Path $BackupDir 'defender-preferences.xml'
            Get-MpPreference -ErrorAction Stop | Export-Clixml -Path $mpPath
            & $Context.Log "Backup: Defender preferences -> $mpPath"
        } else {
            & $Context.Log "Backup: Get-MpPreference unavailable; Defender snapshot skipped." 'Warn'
        }
    } catch { & $Context.Log "Backup: Defender snapshot failed (non-fatal): $($_.Exception.Message)" 'Warn' }

    [pscustomobject]@{ Dir = $BackupDir; Complete = $ok }
}
