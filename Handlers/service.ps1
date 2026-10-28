# Service handler - checks/sets a Windows service start type.
# args: { "name": "ServiceName" }
# recommendedValue: one of Boot|System|Automatic|Manual|Disabled (matches Get-Service StartType)

@{
    Name = 'service'

    Prefetch = {
        param($Findings, $Cache, $Context)
        # ONE Get-Service for the run. On Windows PowerShell 5.1 `Get-Service -Name X`
        # enumerates every installed service and filters, so ~40 CIS service findings
        # meant ~40 full enumerations. A name->StartType table makes each Test a lookup.
        # SilentlyContinue, not Stop: on 5.1 a single service the session cannot query
        # emits a non-terminating error; that must not discard the whole table.
        $table = @{}
        try {
            foreach ($s in (Get-Service -ErrorAction SilentlyContinue)) { $table[$s.Name] = [string]$s.StartType }
        } catch {
            & $Context.Log "service prefetch: Get-Service enumeration threw ($($_.Exception.Message))." 'Warn'
        }
        if ($table.Count -gt 0) { $Cache['services'] = $table }
        else { & $Context.Log "service prefetch: no services enumerated; falling back to per-finding Get-Service reads." 'Warn' }
        & $Context.Log "service prefetch: cached $($table.Count) services."
    }

    Test = {
        param($Finding, $Cache, $Context)
        $name = "$($Finding.args.name)"
        if ($Cache.ContainsKey('services')) {
            $table = $Cache['services']
            if ($table.ContainsKey($name)) { return [pscustomobject]@{ Result = $table[$name]; Found = $true } }
            return [pscustomobject]@{ Result = $null; Found = $false }
        }
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { return [pscustomobject]@{ Result = $null; Found = $false } }
        # StartType property exists on PS5.1+; normalize to string
        [pscustomobject]@{ Result = [string]$svc.StartType; Found = $true }
    }

    Apply = {
        param($Finding, $Cache, $Context)
        $name = $Finding.args.name
        $val  = $Finding.recommendedValue
        if ($Context.WhatIf) {
            return @{ Changed = $false; Message = "WhatIf: would set service '$name' StartType=$val" }
        }
        # A service that isn't installed is already effectively disabled -- treat as a
        # benign no-op (Changed=$false), not an error. CIS lists target services that
        # don't exist on every SKU (e.g. Browser/bowser, irmon), so this is expected.
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) {
            return @{ Changed = $false; Message = "Service '$name' not installed; nothing to disable (compliant)" }
        }
        Set-Service -Name $name -StartupType $val -ErrorAction Stop -WhatIf:$false
        if ($Cache.ContainsKey('services')) { $Cache['services'][$name] = "$val" }   # keep the prefetch table current
        @{ Changed = $true; Message = "Service '$name' StartType set to $val" }
    }

    # Reading a StartType needs no elevation -- gating the Test on admin would
    # needlessly Skip ~40 findings in a non-admin Recon. Only the APPLY needs admin.
    RequiresAdmin = $false
    RequiresAdminForApply = $true
}
