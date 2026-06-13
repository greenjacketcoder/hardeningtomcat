# Pre-Strike backup. Exports current system state so an apply can be rolled back.
# Called once, right before the Strike apply loop runs. Windows-only (no-ops elsewhere).

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
        return [pscustomobject]@{ Complete = $false; Path = $BackupDir }
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

    [pscustomobject]@{ Dir = $BackupDir; Complete = $ok }
}
