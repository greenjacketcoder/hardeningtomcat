# accesschk handler -- user-rights assignments (the [Privilege Rights] section).
# args: { "privilege": "SeShutdownPrivilege" }
# recommendedValue: comma-separated SID list, e.g. "S-1-5-32-544,S-1-5-19"
# operator: 'set=' (order-independent set equality)
#
# Reads user rights via `secedit /export` ONCE in Prefetch (batched), then each Test
# is an in-memory lookup -- same pattern as the secedit handler. No accesschk.exe needed.

@{
    Name = 'accesschk'
    RequiresAdmin = $true
    RequiresBinary = 'C:\Windows\System32\secedit.exe'

    Prefetch = {
        param($Findings, $Cache, $Context)
        $infPath = Join-Path ([System.IO.Path]::GetTempPath()) ("ht_userrights_{0:yyyyMMddHHmmssfff}.inf" -f (Get-Date))
        $exportOk = $false
        try {
            & secedit.exe /export /areas USER_RIGHTS /cfg $infPath /quiet 2>$null
            # secedit returns 0 on success; also require the file to actually exist & be non-empty.
            if ($LASTEXITCODE -eq 0 -and (Test-Path $infPath) -and (Get-Item $infPath).Length -gt 0) {
                $exportOk = $true
            }
        } catch {
            & $Context.Log "accesschk: secedit export threw: $($_.Exception.Message)" 'Warn'
        }

        $rights = @{}
        if ($exportOk) {
            $inSection = $false
            foreach ($line in (Get-Content -Path $infPath -Encoding Unicode)) {
                $t = $line.Trim()
                if ($t -match '^\[Privilege Rights\]') { $inSection = $true; continue }
                if ($t -match '^\[') { $inSection = $false; continue }
                if ($inSection -and $t -match '^(Se\w+)\s*=\s*(.*)$') {
                    $rights[$matches[1]] = $matches[2].Trim()
                }
            }
        } else {
            & $Context.Log "accesschk: USER_RIGHTS export FAILED -- user-rights findings will be Skipped, not passed." 'Warn'
        }

        # Always clean up the security-policy dump (contains sensitive SID assignments).
        Remove-Item $infPath -Force -ErrorAction SilentlyContinue

        $Cache['userrights']    = $rights
        $Cache['userrights_ok'] = $exportOk
        & $Context.Log "accesschk prefetch: export $(if($exportOk){'OK'}else{'FAILED'}), cached $($rights.Count) assignments."
    }

    Test = {
        param($Finding, $Cache, $Context)
        # If the export failed, we genuinely don't know the state -- do NOT claim compliant.
        if (-not $Cache['userrights_ok']) {
            throw "user-rights export unavailable; cannot evaluate $($Finding.args.privilege)"
        }
        $table = $Cache['userrights']
        $priv = $Finding.args.privilege
        if ($table.ContainsKey($priv)) {
            return [pscustomobject]@{ Result = $table[$priv]; Found = $true }
        }
        # Export succeeded AND privilege is absent = genuinely no accounts hold it (empty set).
        [pscustomobject]@{ Result = ''; Found = $true }
    }

    # Applying user rights means writing an INF with the [Privilege Rights] section and
    # running secedit /configure. Higher-risk; gated to read-only in beta like secedit.
    # Build deliberately after the audit path is validated on a VM.
    Apply = $null
}
