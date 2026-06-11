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
        $raw = & auditpol.exe /get /category:* /r 2>$null   # /r = CSV output
        $parsed = @{}
        if ($raw) {
            $csv = $raw | ConvertFrom-Csv
            foreach ($row in $csv) {
                # Column name is 'Subcategory' and 'Inclusion Setting' in auditpol /r output
                $sub = $row.Subcategory
                $set = $row.'Inclusion Setting'
                if ($sub) { $parsed[$sub.Trim()] = $set }
            }
        }
        $Cache['auditpol'] = $parsed
        & $Context.Log "auditpol prefetch: cached $($parsed.Count) subcategories in one call."
    }

    Test = {
        param($Finding, $Cache, $Context)
        $table = $Cache['auditpol']
        $sub = $Finding.args.subcategory
        if ($table -and $table.ContainsKey($sub)) {
            return [pscustomobject]@{ Result = $table[$sub]; Found = $true }
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
