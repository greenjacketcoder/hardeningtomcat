# Auditpol handler.
# THE KEY ARCHITECTURAL WIN: the old engine ran auditpol.exe once PER finding
# (hundreds of process spawns). Here Prefetch runs `auditpol /get /category:*` ONCE,
# parses all subcategories into the cache, and every Test is then an in-memory lookup.
#
# args: { "subcategory": "Credential Validation" }
# recommendedValue: "Success and Failure" | "Success" | "Failure" | "No Auditing"

@{
    Name = 'auditpol'
    RequiresAdmin = $true
    RequiresBinary = 'C:\Windows\System32\auditpol.exe'

    Prefetch = {
        param($Findings, $Cache, $Context)
        # One spawn for the whole run.
        $exportOk = $false
        $parsed = @{}
        try {
            $raw = & auditpol.exe /get /category:* /r 2>$null   # /r = CSV output
            if ($LASTEXITCODE -eq 0 -and $raw) {
                $csv = $raw | ConvertFrom-Csv
                foreach ($row in $csv) {
                    $sub = $row.Subcategory
                    $set = $row.'Inclusion Setting'
                    # Key by BOTH name and GUID so findings can reference either form.
                    # Microsoft baselines use names; CIS lists use the subcategory GUID.
                    if ($sub) { $parsed[$sub.Trim()] = $set }
                    $guid = $row.'Subcategory GUID'
                    if ($guid) { $parsed[$guid.Trim().ToLower()] = $set }
                }
                if ($parsed.Count -gt 0) { $exportOk = $true }
            }
        } catch {
            & $Context.Log "auditpol: query threw: $($_.Exception.Message)" 'Warn'
        }
        if (-not $exportOk) {
            & $Context.Log "auditpol: query FAILED -- audit findings will be Skipped, not passed." 'Warn'
        }
        $Cache['auditpol']    = $parsed
        $Cache['auditpol_ok'] = $exportOk
        & $Context.Log "auditpol prefetch: query $(if($exportOk){'OK'}else{'FAILED'}), cached $($parsed.Count) subcategories."
    }

    Test = {
        param($Finding, $Cache, $Context)
        if (-not $Cache['auditpol_ok']) {
            throw "auditpol query unavailable; cannot evaluate $($Finding.args.subcategory)"
        }
        $table = $Cache['auditpol']
        $sub = $Finding.args.subcategory
        # Try exact (name) match first, then lowercased (GUID) match.
        if ($table.ContainsKey($sub)) {
            return [pscustomobject]@{ Result = $table[$sub]; Found = $true }
        }
        $subLower = "$sub".ToLower()
        if ($table.ContainsKey($subLower)) {
            return [pscustomobject]@{ Result = $table[$subLower]; Found = $true }
        }
        [pscustomobject]@{ Result = $null; Found = $false }
    }

    Apply = {
        param($Finding, $Cache, $Context)
        $sub = $Finding.args.subcategory
        $val = $Finding.recommendedValue
        # Map the human setting to auditpol flags
        $success = if ($val -match 'Success') { 'enable' } else { 'disable' }
        $failure = if ($val -match 'Failure') { 'enable' } else { 'disable' }
        if ($Context.WhatIf) {
            return @{ Changed = $false; Message = "WhatIf: would set audit '$sub' to $val" }
        }
        & auditpol.exe /set /subcategory:"$sub" /success:$success /failure:$failure | Out-Null
        @{ Changed = $true; Message = "Audit '$sub' set to $val" }
    }
}
