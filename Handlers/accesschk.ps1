# accesschk handler — user-rights assignments (the [Privilege Rights] section).
# args: { "privilege": "SeShutdownPrivilege" }
# recommendedValue: comma-separated SID list, e.g. "S-1-5-32-544,S-1-5-19"
# operator: 'set=' (order-independent set equality)
#
# Reads user rights via `secedit /export` ONCE in Prefetch (batched), then each Test
# is an in-memory lookup — same pattern as the secedit handler. No accesschk.exe needed.

@{
    Name = 'accesschk'
    RequiresAdmin = $true
    RequiresBinary = 'C:\Windows\System32\secedit.exe'

    Prefetch = {
        param($Findings, $Cache, $Context)
        # Reuse a secedit export if one was already cached by the secedit handler.
        if ($Cache['secedit_inf_path'] -and (Test-Path $Cache['secedit_inf_path'])) {
            $infPath = $Cache['secedit_inf_path']
        } else {
            $infPath = Join-Path ([System.IO.Path]::GetTempPath()) ("ht_userrights_{0:yyyyMMdd-HHmmss}.inf" -f (Get-Date))
            & secedit.exe /export /areas USER_RIGHTS /cfg $infPath /quiet 2>$null
        }

        $rights = @{}
        if (Test-Path $infPath) {
            $inSection = $false
            foreach ($line in (Get-Content -Path $infPath -Encoding Unicode)) {
                $t = $line.Trim()
                if ($t -match '^\[Privilege Rights\]') { $inSection = $true; continue }
                if ($t -match '^\[') { $inSection = $false; continue }
                if ($inSection -and $t -match '^(Se\w+)\s*=\s*(.*)$') {
                    # Value is a comma-separated list of *SIDs (or account names). Store raw.
                    $rights[$matches[1]] = $matches[2].Trim()
                }
            }
        }
        $Cache['userrights'] = $rights
        & $Context.Log "accesschk prefetch: cached $($rights.Count) user-rights assignments."
    }

    Test = {
        param($Finding, $Cache, $Context)
        $table = $Cache['userrights']
        $priv = $Finding.args.privilege
        if ($table -and $table.ContainsKey($priv)) {
            return [pscustomobject]@{ Result = $table[$priv]; Found = $true }
        }
        # Privilege absent from export = no accounts hold it = empty set.
        [pscustomobject]@{ Result = ''; Found = $true }
    }

    # Applying user rights means writing an INF with the [Privilege Rights] section and
    # running secedit /configure. Higher-risk; gated to read-only in beta like secedit.
    # Build deliberately after the audit path is validated on a VM.
    Apply = $null
}
