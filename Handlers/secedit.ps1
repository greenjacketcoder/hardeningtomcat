# Secedit handler.
# Like auditpol: the old engine ran `secedit /export` repeatedly. Here Prefetch
# exports ONCE to a temp INI, parses it, and caches. Tests are in-memory lookups.
#
# args: { "key": "PasswordComplexity" }   # the INI key under any section
# Secedit INI keys are unique enough across sections that a flat lookup works for
# the common System Access / password & lockout settings.

@{
    Name = 'secedit'
    RequiresAdmin = $true
    RequiresBinary = 'C:\Windows\System32\secedit.exe'

    Prefetch = {
        param($Findings, $Cache, $Context)
        # One export for the whole run, via the shared helper (Private/_Helpers.ps1 --
        # the same implementation backs accountpolicy and accesschk).
        $exp = Get-HtSeceditExport -Context $Context
        if ($exp.Error) { $Cache['secedit_err'] = $exp.Error }
        $Cache['secedit']    = $exp.Flat
        $Cache['secedit_ok'] = $exp.Ok
        & $Context.Log "secedit prefetch: export $(if($exp.Ok){'OK'}else{'FAILED'}), cached $($exp.Flat.Count) keys."
    }

    Test = {
        param($Finding, $Cache, $Context)
        # If the export failed, we don't know the state -- do NOT claim compliant.
        if (-not $Cache['secedit_ok']) {
            if ($Cache['secedit_err']) { throw $Cache['secedit_err'] }
            throw "secedit export unavailable; cannot evaluate $($Finding.args.key)"
        }
        $table = $Cache['secedit']
        $key = $Finding.args.key
        if ($table.ContainsKey($key)) {
            return [pscustomobject]@{ Result = $table[$key]; Found = $true }
        }
        [pscustomobject]@{ Result = $null; Found = $false }
    }

    # Apply does NOT run secedit per finding (that spawns the heavy Security
    # Configuration Engine once per setting and can exhaust scesrv). Instead it
    # ACCUMULATES validated key/value pairs; FlushApply writes them all in ONE
    # secedit /configure at the end of the run. Much gentler on the system.
    Apply = {
        param($Finding, $Cache, $Context)
        $key = $Finding.args.key
        $val = $Finding.recommendedValue
        if ($Context.WhatIf) {
            return @{ Changed = $false; Message = "WhatIf: would set [System Access] $key = $val" }
        }
        # Validate key/value -- a newline or section header could inject extra policy
        # directives into the INF. (Integrity manifest already guards list content;
        # this is defense in depth.)
        if ($key -notmatch '^[A-Za-z0-9_]+$') {
            return @{ Changed = $false; Message = "Refused: unsafe account-policy key '$key'" }
        }
        if ("$val" -match '[\r\n\[\]]') {
            return @{ Changed = $false; Message = "Refused: unsafe value for $key (contains newline/bracket)" }
        }
        if (-not $Cache.ContainsKey('secedit_pending')) { $Cache['secedit_pending'] = @{} }
        $Cache['secedit_pending'][$key] = $val
        # Not yet written -- counted when FlushApply runs. Changed=$false here so we
        # don't double-count; the flush reports the real applied total.
        @{ Changed = $false; Message = "[System Access] $key queued = $val (batched)" }
    }

    # Write ALL queued [System Access] settings in a single secedit /configure.
    FlushApply = {
        param($Cache, $Context)
        $pending = $Cache['secedit_pending']
        if (-not $pending -or $pending.Count -eq 0) { return @{ Applied = 0 } }

        $tmpInf = Join-Path ([System.IO.Path]::GetTempPath()) ("ht_applyall_{0:yyyyMMddHHmmssfff}.inf" -f (Get-Date))
        $tmpDb  = Join-Path ([System.IO.Path]::GetTempPath()) ("ht_applyall_{0:yyyyMMddHHmmssfff}.sdb" -f (Get-Date))
        $lines = foreach ($k in $pending.Keys) { "$k = $($pending[$k])" }
        $body  = $lines -join "`r`n"
        $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
$body
"@
        $applied = 0; $msg = ""
        try {
            Set-Content -Path $tmpInf -Value $inf -Encoding Unicode -WhatIf:$false
            & secedit.exe /configure /db $tmpDb /cfg $tmpInf /areas SECURITYPOLICY /quiet 2>$null
            if ($LASTEXITCODE -eq 0) {
                $applied = $pending.Count
                $msg = "applied $applied account-policy setting(s) in one pass"
            } elseif ($LASTEXITCODE -eq 2) {
                $msg = "secedit /configure could not run (insufficient system resources/scesrv). $($pending.Count) setting(s) NOT applied; free memory or reboot and re-run."
                & $Context.Log $msg 'Error'
            } else {
                $msg = "secedit /configure failed (exit $LASTEXITCODE); $($pending.Count) setting(s) not applied"
                & $Context.Log $msg 'Error'
            }
        } finally {
            Remove-Item $tmpInf,$tmpDb -Force -WhatIf:$false -ErrorAction SilentlyContinue
        }
        $Cache['secedit_pending'] = @{}
        if ($Cache.ContainsKey('secedit')) { $Cache.Remove('secedit') }
        @{ Applied = $applied; Message = $msg }
    }
}
