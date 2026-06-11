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
        Set-Service -Name $name -StartupType $val -ErrorAction Stop
        @{ Changed = $true; Message = "Service '$name' StartType set to $val" }
    }

    RequiresAdmin = $true
}
