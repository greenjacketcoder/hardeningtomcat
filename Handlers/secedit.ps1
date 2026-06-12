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
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ht_secedit_{0:yyyyMMdd-HHmmss}.inf" -f (Get-Date))
        & secedit.exe /export /cfg $tmp /quiet 2>$null
        $table = @{}
        if (Test-Path $tmp) {
            foreach ($line in (Get-Content -Path $tmp -Encoding Unicode)) {
                if ($line -match '^\s*([^=\[]+?)\s*=\s*(.+?)\s*$') {
                    $table[$matches[1].Trim()] = $matches[2].Trim()
                }
            }
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        }
        $Cache['secedit'] = $table
        & $Context.Log "secedit prefetch: cached $($table.Count) policy keys in one export."
    }

    Test = {
        param($Finding, $Cache, $Context)
        $table = $Cache['secedit']
        $key = $Finding.args.key
        if ($table -and $table.ContainsKey($key)) {
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
        Set-Content -Path $tmpInf -Value $inf -Encoding Unicode
        & secedit.exe /configure /db $tmpDb /cfg $tmpInf /areas SECURITYPOLICY /quiet 2>$null
        Remove-Item $tmpInf,$tmpDb -Force -ErrorAction SilentlyContinue
        # Invalidate cached export so a re-Test reads fresh state.
        if ($Cache.ContainsKey('secedit')) { $Cache.Remove('secedit') }
        @{ Changed = $true; Message = "[System Access] $key set to $val" }
    }
}
