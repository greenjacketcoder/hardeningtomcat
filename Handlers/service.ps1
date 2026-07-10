# Service handler - checks/sets a Windows service start type.
# args: { "name": "ServiceName" }
# recommendedValue: one of Boot|System|Automatic|Manual|Disabled (matches Get-Service StartType)

@{
    Name = 'service'

    Test = {
        param($Finding, $Cache, $Context)
        $svc = Get-Service -Name $Finding.args.name -ErrorAction SilentlyContinue
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
        @{ Changed = $true; Message = "Service '$name' StartType set to $val" }
    }

    # Reading a StartType needs no elevation -- gating the Test on admin would
    # needlessly Skip ~40 findings in a non-admin Recon. Only the APPLY needs admin.
    RequiresAdmin = $false
    RequiresAdminForApply = $true
}
