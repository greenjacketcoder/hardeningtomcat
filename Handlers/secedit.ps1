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
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ht_secedit_{0:yyyyMMddHHmmssfff}.inf" -f (Get-Date))
        $exportOk = $false
        try {
            & secedit.exe /export /cfg $tmp /quiet 2>$null
            if ($LASTEXITCODE -eq 0 -and (Test-Path $tmp) -and (Get-Item $tmp).Length -gt 0) { $exportOk = $true }
        } catch {
            & $Context.Log "secedit: export threw: $($_.Exception.Message)" 'Warn'
        }
        $table = @{}
        if ($exportOk) {
            foreach ($line in (Get-Content -Path $tmp -Encoding Unicode)) {
                if ($line -match '^\s*([^=\[]+?)\s*=\s*(.+?)\s*$') {
                    $table[$matches[1].Trim()] = $matches[2].Trim()
                }
            }
        } else {
            & $Context.Log "secedit: export FAILED -- policy findings will be Skipped, not passed." 'Warn'
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        $Cache['secedit']    = $table
        $Cache['secedit_ok'] = $exportOk
        & $Context.Log "secedit prefetch: export $(if($exportOk){'OK'}else{'FAILED'}), cached $($table.Count) keys."
    }

    Test = {
        param($Finding, $Cache, $Context)
        # If the export failed, we don't know the state -- do NOT claim compliant.
        if (-not $Cache['secedit_ok']) {
            throw "secedit export unavailable; cannot evaluate $($Finding.args.key)"
        }
        $table = $Cache['secedit']
        $key = $Finding.args.key
        if ($table.ContainsKey($key)) {
            return [pscustomobject]@{ Result = $table[$key]; Found = $true }
        }
        [pscustomobject]@{ Result = $null; Found = $false }
    }

    # Apply a [System Access] account-policy setting by writing a minimal INF and
    # running secedit /configure. Only account-policy keys are supported here;
    # registry-backed security options go through the Registry handler instead.
    Apply = {
        param($Finding, $Cache, $Context)
        $key = $Finding.args.key
        $val = $Finding.recommendedValue
        if ($Context.WhatIf) {
            return @{ Changed = $false; Message = "WhatIf: would set [System Access] $key = $val" }
        }
        # Validate key/value before writing them into an INF -- a newline or section
        # header in either could inject extra policy directives into the template.
        # The integrity manifest already guards list content; this is defense in depth.
        if ($key -notmatch '^[A-Za-z0-9_]+$') {
            return @{ Changed = $false; Message = "Refused: unsafe account-policy key '$key'" }
        }
        if ("$val" -match '[\r\n\[\]]') {
            return @{ Changed = $false; Message = "Refused: unsafe value for $key (contains newline/bracket)" }
        }
        $tmpInf = Join-Path ([System.IO.Path]::GetTempPath()) ("ht_apply_{0:yyyyMMddHHmmssfff}.inf" -f (Get-Date))
        $tmpDb  = Join-Path ([System.IO.Path]::GetTempPath()) ("ht_apply_{0:yyyyMMddHHmmssfff}.sdb" -f (Get-Date))
        # Minimal security template applying just this one System Access key.
        $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
$key = $val
"@
        $changed = $false; $msg = ""
        try {
            Set-Content -Path $tmpInf -Value $inf -Encoding Unicode
            & secedit.exe /configure /db $tmpDb /cfg $tmpInf /areas SECURITYPOLICY /quiet 2>$null
            if ($LASTEXITCODE -eq 0) {
                $changed = $true; $msg = "[System Access] $key set to $val"
            } else {
                $msg = "secedit /configure failed (exit $LASTEXITCODE) for $key"
                & $Context.Log $msg 'Error'
            }
        } finally {
            Remove-Item $tmpInf,$tmpDb -Force -ErrorAction SilentlyContinue
        }
        # Invalidate cached export so a re-Test reads fresh state.
        if ($Cache.ContainsKey('secedit')) { $Cache.Remove('secedit') }
        @{ Changed = $changed; Message = $msg }
    }
}
