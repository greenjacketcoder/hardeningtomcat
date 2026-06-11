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

    # Applying secedit settings means writing an INF and running /configure.
    # That's a heavier, riskier operation; for the beta we mark it non-trivial
    # and require it to be implemented deliberately. Left as $null = read-only
    # until you've validated the Recon path, exactly the staged approach we agreed.
    Apply = $null
}
