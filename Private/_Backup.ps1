# Pre-Strike backup. Exports current system state so an apply can be rolled back.
# Called once, right before the Strike apply loop runs. Windows-only (no-ops elsewhere).

function Invoke-HtPreStrikeBackup {
    param([string] $BackupDir, $Context)

    if (-not $BackupDir) {
        $BackupDir = Join-Path (Get-Location) ("hardeningtomcat_backup_{0}_{1:yyyyMMdd-HHmmss}" -f $env:COMPUTERNAME, (Get-Date))
    }
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

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

    # 1) Security policy (account policy, user rights, audit) via secedit export
    try {
        $secPath = Join-Path $BackupDir 'secpol-backup.inf'
        & secedit.exe /export /cfg $secPath /quiet 2>$null
        & $Context.Log "Backup: security policy -> $secPath"
    } catch { $ok = $false; & $Context.Log "Backup: secedit export failed: $($_.Exception.Message)" 'Warn' }

    # 2) Registry hives most affected by hardening (HKLM\SOFTWARE and \SYSTEM policies)
    foreach ($hive in @(
        @{ Key = 'HKLM\SOFTWARE\Policies'; File = 'reg-software-policies.reg' }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; File = 'reg-lsa.reg' }
    )) {
        try {
            $regFile = Join-Path $BackupDir $hive.File
            & reg.exe export $hive.Key $regFile /y 2>$null | Out-Null
            & $Context.Log "Backup: $($hive.Key) -> $regFile"
        } catch { $ok = $false; & $Context.Log "Backup: reg export $($hive.Key) failed" 'Warn' }
    }

    # 3) Audit policy snapshot
    try {
        $audPath = Join-Path $BackupDir 'auditpol-backup.csv'
        & auditpol.exe /backup /file:$audPath 2>$null | Out-Null
        & $Context.Log "Backup: audit policy -> $audPath"
    } catch { & $Context.Log "Backup: auditpol backup failed" 'Warn' }

    [pscustomobject]@{ Dir = $BackupDir; Complete = $ok }
}
